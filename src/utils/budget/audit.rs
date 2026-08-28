//! Append-only audit trail for budget enforcement decisions.
//!
//! Every call to [`super::gate`] appends one JSON line to
//! `<data_dir>/budget/audit.jsonl`, regardless of whether the decision was
//! `Allow`, `Warn`, `Block`, or `OverrideAllowed`. The log is append-only
//! (never rewritten in place) and file permissions are restricted to the
//! owner on Unix, since override reasons and contract/function identifiers
//! can be operationally sensitive.
//!
//! `starforge budget audit` reads this file back for humans; nothing else in
//! the codebase should need to parse it, so the schema here is intentionally
//! flat rather than mirroring `EnforcementReport` field-for-field.

use super::enforce::{Decision, EnforcementReport};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const AUDIT_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema_version: u8,
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub network: String,
    pub contract: Option<String>,
    pub function: Option<String>,
    pub decision: Decision,
    pub violation_metrics: Vec<String>,
    pub warning_metrics: Vec<String>,
    /// Redacted via `commands::ai::impact::redactor::redact_text` by every
    /// CLI command handler that populates `GateRequest::override_reason` (or
    /// calls `enforce::apply_override` directly, as `commands::budget::check`
    /// does), *before* the string reaches [`super::gate::gate`] or this
    /// struct. This module and `gate()` intentionally do not redact
    /// themselves so `src/utils` has no dependency on `src/commands` — see
    /// each integrated command's `redacted_override_reason` local.
    pub override_reason: Option<String>,
}

impl AuditRecord {
    pub fn from_report(report: &EnforcementReport) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            timestamp: Utc::now(),
            command: report.command.clone(),
            network: report.network.clone(),
            contract: report.contract.clone(),
            function: report.function.clone(),
            decision: report.decision,
            violation_metrics: report
                .violations()
                .iter()
                .map(|c| c.metric.as_str().to_string())
                .collect(),
            warning_metrics: report
                .warnings()
                .iter()
                .map(|c| c.metric.as_str().to_string())
                .collect(),
            override_reason: report.override_reason.clone(),
        }
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn append_record_at(path: &Path, record: &AuditRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let is_new = !path.exists();
    let line = serde_json::to_string(record).context("Failed to serialize audit record")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open audit log {}", path.display()))?;
    writeln!(file, "{}", line)
        .with_context(|| format!("Failed to append to audit log {}", path.display()))?;

    if is_new {
        restrict_permissions(path)?;
    }
    Ok(())
}

pub fn append_record(record: &AuditRecord) -> Result<PathBuf> {
    let path = default_audit_log_path()?;
    append_record_at(&path, record)?;
    Ok(path)
}

pub fn default_audit_log_path() -> Result<PathBuf> {
    Ok(crate::utils::config::get_data_dir()?
        .join("budget")
        .join("audit.jsonl"))
}

/// Reads every record from `path` in append order. Malformed lines (e.g. a
/// half-written line from a crash mid-append) are skipped rather than
/// failing the whole read, since the audit log is meant to survive partial
/// writes without becoming unreadable.
pub fn read_records_at(path: &Path) -> Result<Vec<AuditRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read audit log {}", path.display()))?;
    Ok(contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

pub fn read_records() -> Result<Vec<AuditRecord>> {
    read_records_at(&default_audit_log_path()?)
}

/// Filters (already-loaded) records by decision kind and/or command name,
/// most-recent-first, capped at `limit` (0 means unlimited).
pub fn filter_records(
    records: Vec<AuditRecord>,
    decision: Option<Decision>,
    command: Option<&str>,
    limit: usize,
) -> Vec<AuditRecord> {
    let mut filtered: Vec<AuditRecord> = records
        .into_iter()
        .filter(|r| decision.is_none_or(|d| d == r.decision))
        .filter(|r| command.is_none_or(|c| r.command == c))
        .collect();
    filtered.reverse();
    if limit > 0 && filtered.len() > limit {
        filtered.truncate(limit);
    }
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::budget::enforce::{EnforcementReport, ENFORCEMENT_REPORT_SCHEMA_VERSION};
    use crate::utils::budget::metrics::BudgetMetrics;
    use tempfile::tempdir;

    fn sample_report(decision: Decision) -> EnforcementReport {
        EnforcementReport {
            schema_version: ENFORCEMENT_REPORT_SCHEMA_VERSION,
            command: "invoke".to_string(),
            network: "testnet".to_string(),
            contract: Some("CABC".to_string()),
            function: Some("transfer".to_string()),
            metrics: BudgetMetrics::default(),
            warning_threshold_percent: 80.0,
            policy_layers: vec!["global".to_string()],
            checks: Vec::new(),
            decision,
            override_reason: None,
        }
    }

    #[test]
    fn append_and_read_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let record = AuditRecord::from_report(&sample_report(Decision::Allow));
        append_record_at(&path, &record).unwrap();

        let records = read_records_at(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].command, "invoke");
    }

    #[test]
    fn multiple_appends_accumulate_in_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        for decision in [Decision::Allow, Decision::Warn, Decision::Block] {
            append_record_at(&path, &AuditRecord::from_report(&sample_report(decision))).unwrap();
        }
        let records = read_records_at(&path).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].decision, Decision::Block);
    }

    #[test]
    fn read_missing_log_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.jsonl");
        assert!(read_records_at(&path).unwrap().is_empty());
    }

    #[test]
    fn malformed_line_is_skipped_not_fatal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_record_at(
            &path,
            &AuditRecord::from_report(&sample_report(Decision::Allow)),
        )
        .unwrap();
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(file, "{{ not valid json").unwrap();
        }
        append_record_at(
            &path,
            &AuditRecord::from_report(&sample_report(Decision::Warn)),
        )
        .unwrap();

        let records = read_records_at(&path).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_record_at(
            &path,
            &AuditRecord::from_report(&sample_report(Decision::Allow)),
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn filter_records_by_decision_and_command_most_recent_first() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_record_at(
            &path,
            &AuditRecord::from_report(&sample_report(Decision::Allow)),
        )
        .unwrap();
        append_record_at(
            &path,
            &AuditRecord::from_report(&sample_report(Decision::Block)),
        )
        .unwrap();
        let mut second_block = sample_report(Decision::Block);
        second_block.command = "deploy".to_string();
        append_record_at(&path, &AuditRecord::from_report(&second_block)).unwrap();

        let records = read_records_at(&path).unwrap();
        let filtered = filter_records(records, Some(Decision::Block), Some("invoke"), 0);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].command, "invoke");
    }

    #[test]
    fn filter_records_respects_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        for _ in 0..5 {
            append_record_at(
                &path,
                &AuditRecord::from_report(&sample_report(Decision::Allow)),
            )
            .unwrap();
        }
        let records = read_records_at(&path).unwrap();
        let filtered = filter_records(records, None, None, 2);
        assert_eq!(filtered.len(), 2);
    }
}
