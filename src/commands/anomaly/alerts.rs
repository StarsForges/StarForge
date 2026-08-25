//! Append-only alert history: persistence, deduplication/cooldown, pruning,
//! and export.
//!
//! Storage layout mirrors `commands::cost::history` and
//! `utils::performance::baseline`: one JSON file per alert under
//! `<data_dir>/anomaly_alerts/<contract-fingerprint>/<timestamp>-<seq>.json`,
//! plus a small `dedup_index.json` in the same directory mapping each
//! [`Alert::dedup_key`] to the last time it fired, so repeat detections of
//! the *same* condition within a cooldown window are suppressed rather than
//! flooding history and paging the same incident twice.

use super::model::Alert;
use crate::utils::config;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const ALERT_SCHEMA_VERSION: u8 = 1;

/// Default cooldown before a repeat of the exact same alert condition
/// (same contract/network/kind/metric) is persisted again.
pub const DEFAULT_DEDUP_COOLDOWN_SECS: i64 = 900; // 15 minutes

fn sanitize(part: &str) -> String {
    let s: String = part
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "default".to_string()
    } else {
        s
    }
}

fn fingerprint(contract_id: &str, network: &str) -> String {
    let mut h = Sha256::new();
    h.update(contract_id.as_bytes());
    h.update(b"|");
    h.update(network.as_bytes());
    hex::encode(&h.finalize()[..4])
}

fn alert_dir(base: &Path, contract_id: &str, network: &str) -> PathBuf {
    let name = format!(
        "{}-{}-{}",
        sanitize(contract_id),
        sanitize(network),
        fingerprint(contract_id, network)
    );
    base.join("anomaly_alerts").join(name)
}

fn dedup_index_path(dir: &Path) -> PathBuf {
    dir.join("dedup_index.json")
}

type DedupIndex = BTreeMap<String, DateTime<Utc>>;

fn load_dedup_index(dir: &Path) -> DedupIndex {
    let path = dedup_index_path(dir);
    fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_dedup_index(dir: &Path, index: &DedupIndex) -> Result<()> {
    let json = serde_json::to_string_pretty(index).context("Failed to serialize dedup index")?;
    fs::write(dedup_index_path(dir), json).context("Failed to write dedup index")?;
    Ok(())
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

/// Outcome of attempting to persist a single alert.
#[derive(Debug, Clone, PartialEq)]
pub enum SaveOutcome {
    /// Persisted as a new alert file.
    Saved(PathBuf),
    /// Suppressed: an alert with the same dedup key fired within the
    /// cooldown window, so no new file was written.
    Deduplicated { last_fired: DateTime<Utc> },
}

fn unique_path(dir: &Path, ts: DateTime<Utc>) -> PathBuf {
    for seq in 0..1000u32 {
        let candidate = dir.join(format!(
            "{}-{:03}.json",
            ts.format("%Y%m%dT%H%M%S%3fZ"),
            seq
        ));
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!(
        "{}-pid{}.json",
        ts.format("%Y%m%dT%H%M%S%3fZ"),
        std::process::id()
    ))
}

fn save_one_in(base: &Path, alert: &Alert, cooldown_secs: i64) -> Result<SaveOutcome> {
    let dir = alert_dir(base, &alert.contract_id, &alert.network);
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create alert directory {}", dir.display()))?;

    let mut index = load_dedup_index(&dir);
    if let Some(last_fired) = index.get(&alert.dedup_key) {
        let elapsed = alert.timestamp.signed_duration_since(*last_fired);
        if elapsed < ChronoDuration::seconds(cooldown_secs) && elapsed >= ChronoDuration::zero() {
            return Ok(SaveOutcome::Deduplicated {
                last_fired: *last_fired,
            });
        }
    }

    let mut versioned = alert.clone();
    versioned.schema_version = ALERT_SCHEMA_VERSION;
    let path = unique_path(&dir, alert.timestamp);
    let json = serde_json::to_string_pretty(&versioned).context("Failed to serialize alert")?;
    fs::write(&path, &json).with_context(|| format!("Failed to write alert {}", path.display()))?;
    restrict_permissions(&path)?;

    index.insert(alert.dedup_key.clone(), alert.timestamp);
    save_dedup_index(&dir, &index)?;

    Ok(SaveOutcome::Saved(path))
}

/// Persists every alert in `alerts`, applying dedup/cooldown to each
/// independently, and returns the outcome for each in order.
pub fn save_all(alerts: &[Alert], cooldown_secs: i64) -> Result<Vec<SaveOutcome>> {
    let base = config::get_data_dir()?;
    alerts
        .iter()
        .map(|a| save_one_in(&base, a, cooldown_secs))
        .collect()
}

fn list_paths_in(base: &Path, contract_id: &str, network: &str) -> Result<Vec<PathBuf>> {
    let dir = alert_dir(base, contract_id, network);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("Failed to read alert directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("dedup_index.json"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn load_alert(path: &Path) -> Result<Alert> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read alert {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "Failed to parse alert {} (schema mismatch?)",
            path.display()
        )
    })
}

/// Loads every alert for `(contract_id, network)`, oldest first.
pub fn load_all(contract_id: &str, network: &str) -> Result<Vec<Alert>> {
    let base = config::get_data_dir()?;
    list_paths_in(&base, contract_id, network)?
        .iter()
        .map(|p| load_alert(p))
        .collect()
}

/// Loads alerts for `(contract_id, network)` timestamped within the last
/// `hours`, oldest first.
pub fn load_recent(contract_id: &str, network: &str, hours: i64) -> Result<Vec<Alert>> {
    let cutoff = Utc::now() - ChronoDuration::hours(hours.max(0));
    Ok(load_all(contract_id, network)?
        .into_iter()
        .filter(|a| a.timestamp >= cutoff)
        .collect())
}

/// Removes alert files beyond `keep_latest` most-recent entries and/or older
/// than `older_than_days`. Returns the number of files removed. The dedup
/// index is left intact — pruning history doesn't reopen a cooldown window
/// for conditions that already fired recently.
pub fn prune(
    contract_id: &str,
    network: &str,
    keep_latest: Option<usize>,
    older_than_days: Option<i64>,
) -> Result<usize> {
    prune_in(
        &config::get_data_dir()?,
        contract_id,
        network,
        keep_latest,
        older_than_days,
    )
}

fn prune_in(
    base: &Path,
    contract_id: &str,
    network: &str,
    keep_latest: Option<usize>,
    older_than_days: Option<i64>,
) -> Result<usize> {
    let mut paths = list_paths_in(base, contract_id, network)?;
    let mut to_remove: Vec<PathBuf> = Vec::new();

    if let Some(days) = older_than_days {
        let cutoff = Utc::now() - ChronoDuration::days(days.max(0));
        let mut kept = Vec::new();
        for path in paths {
            let is_old = load_alert(&path)
                .map(|a| a.timestamp < cutoff)
                .unwrap_or(false);
            if is_old {
                to_remove.push(path);
            } else {
                kept.push(path);
            }
        }
        paths = kept;
    }

    if let Some(keep) = keep_latest {
        if paths.len() > keep {
            let excess = paths.len() - keep;
            to_remove.extend(paths.into_iter().take(excess));
        }
    }

    let removed = to_remove.len();
    for path in to_remove {
        let _ = fs::remove_file(path);
    }
    Ok(removed)
}

/// Exports alert history as JSON or CSV.
pub fn export(contract_id: &str, network: &str, format: &str) -> Result<String> {
    format_export(&load_all(contract_id, network)?, format)
}

/// Pure formatting step behind [`export`], split out so it can be tested
/// without touching the real StarForge data directory.
pub fn format_export(alerts: &[Alert], format: &str) -> Result<String> {
    match format {
        "json" => serde_json::to_string_pretty(alerts).context("Failed to serialize alert export"),
        "csv" => {
            let mut out = String::from(
                "timestamp,contract_id,network,kind,severity,metric,observed_value,\
                 expected_mean,deviation_score,used_fallback_threshold,message\n",
            );
            for a in alerts {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},\"{}\"\n",
                    a.timestamp.to_rfc3339(),
                    a.contract_id,
                    a.network,
                    a.kind.as_str(),
                    a.severity,
                    a.metric,
                    a.observed_value,
                    a.expected_mean
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "".to_string()),
                    a.deviation_score
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "".to_string()),
                    a.used_fallback_threshold,
                    a.message.replace('"', "'"),
                ));
            }
            Ok(out)
        }
        other => anyhow::bail!(
            "Unsupported export format '{}'. Use 'json' or 'csv'.",
            other
        ),
    }
}

/// Lists every `(contract_id, network)` pair with recorded alert history.
pub fn list_scopes() -> Result<Vec<(String, String)>> {
    #[derive(Deserialize)]
    struct ScopeProbe {
        contract_id: String,
        network: String,
    }
    let base = config::get_data_dir()?.join("anomaly_alerts");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut scopes = Vec::new();
    for entry in fs::read_dir(&base)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        // Read the scope from the first alert file we find rather than
        // parsing the sanitized directory name, since sanitization is lossy.
        if let Some(first_file) = fs::read_dir(entry.path())?
            .filter_map(|e| e.ok())
            .find(|e| {
                e.path().extension().and_then(|x| x.to_str()) == Some("json")
                    && e.file_name().to_string_lossy() != "dedup_index.json"
            })
        {
            if let Ok(raw) = fs::read_to_string(first_file.path()) {
                if let Ok(probe) = serde_json::from_str::<ScopeProbe>(&raw) {
                    scopes.push((probe.contract_id, probe.network));
                }
            }
        }
    }
    scopes.sort();
    scopes.dedup();
    Ok(scopes)
}

#[derive(Debug, Serialize)]
pub struct AlertStats {
    pub total: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_kind: BTreeMap<String, usize>,
}

pub fn summarize(alerts: &[Alert]) -> AlertStats {
    let mut by_severity = BTreeMap::new();
    let mut by_kind = BTreeMap::new();
    for a in alerts {
        *by_severity.entry(a.severity.to_string()).or_insert(0) += 1;
        *by_kind.entry(a.kind.as_str().to_string()).or_insert(0) += 1;
    }
    AlertStats {
        total: alerts.len(),
        by_severity,
        by_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::anomaly::model::{AnomalyKind, Severity};
    use tempfile::tempdir;

    fn sample_alert(contract: &str, network: &str, kind: AnomalyKind, metric: &str) -> Alert {
        Alert {
            schema_version: ALERT_SCHEMA_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            contract_id: contract.to_string(),
            network: network.to_string(),
            kind,
            severity: Severity::Medium,
            metric: metric.to_string(),
            observed_value: 100.0,
            expected_mean: Some(10.0),
            deviation_score: Some(5.0),
            message: "test alert".to_string(),
            used_fallback_threshold: false,
            dedup_key: Alert::dedup_key_for(contract, network, kind, metric),
        }
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = tempdir().unwrap();
        let alert = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        let outcome = save_one_in(dir.path(), &alert, DEFAULT_DEDUP_COOLDOWN_SECS).unwrap();
        assert!(matches!(outcome, SaveOutcome::Saved(_)));

        let loaded = list_paths_in(dir.path(), "CFOO", "testnet").unwrap();
        assert_eq!(loaded.len(), 1);
        let parsed = load_alert(&loaded[0]).unwrap();
        assert_eq!(parsed.contract_id, "CFOO");
    }

    #[test]
    fn duplicate_alert_within_cooldown_is_suppressed() {
        let dir = tempdir().unwrap();
        let alert = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        save_one_in(dir.path(), &alert, DEFAULT_DEDUP_COOLDOWN_SECS).unwrap();

        let mut repeat = alert.clone();
        repeat.timestamp = alert.timestamp + ChronoDuration::seconds(10);
        let outcome = save_one_in(dir.path(), &repeat, DEFAULT_DEDUP_COOLDOWN_SECS).unwrap();
        assert!(matches!(outcome, SaveOutcome::Deduplicated { .. }));

        let files = list_paths_in(dir.path(), "CFOO", "testnet").unwrap();
        assert_eq!(
            files.len(),
            1,
            "deduplicated alert must not create a new file"
        );
    }

    #[test]
    fn alert_after_cooldown_expires_is_saved_again() {
        let dir = tempdir().unwrap();
        let alert = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        save_one_in(dir.path(), &alert, 60).unwrap();

        let mut later = alert.clone();
        later.timestamp = alert.timestamp + ChronoDuration::seconds(120);
        let outcome = save_one_in(dir.path(), &later, 60).unwrap();
        assert!(matches!(outcome, SaveOutcome::Saved(_)));

        let files = list_paths_in(dir.path(), "CFOO", "testnet").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn different_metrics_do_not_dedup_against_each_other() {
        let dir = tempdir().unwrap();
        let a = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        let b = sample_alert("CFOO", "testnet", AnomalyKind::ErrorRateShift, "error_rate");
        save_one_in(dir.path(), &a, DEFAULT_DEDUP_COOLDOWN_SECS).unwrap();
        let outcome = save_one_in(dir.path(), &b, DEFAULT_DEDUP_COOLDOWN_SECS).unwrap();
        assert!(matches!(outcome, SaveOutcome::Saved(_)));
    }

    #[test]
    fn prune_keeps_only_latest_n() {
        let dir = tempdir().unwrap();
        for i in 0..5u32 {
            let mut a = sample_alert(
                "CFOO",
                "testnet",
                AnomalyKind::VolumeSpike,
                &format!("m{}", i),
            );
            a.dedup_key = format!("unique-{}", i); // avoid cooldown suppression across saves
            save_one_in(dir.path(), &a, 0).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            list_paths_in(dir.path(), "CFOO", "testnet").unwrap().len(),
            5
        );

        let removed = prune_in(dir.path(), "CFOO", "testnet", Some(2), None).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(
            list_paths_in(dir.path(), "CFOO", "testnet").unwrap().len(),
            2
        );
    }

    #[test]
    fn prune_removes_entries_older_than_cutoff() {
        let dir = tempdir().unwrap();
        let mut old = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "old");
        old.timestamp = Utc::now() - ChronoDuration::days(30);
        old.dedup_key = "old-unique".to_string();
        save_one_in(dir.path(), &old, 0).unwrap();

        let mut recent = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "recent");
        recent.dedup_key = "recent-unique".to_string();
        save_one_in(dir.path(), &recent, 0).unwrap();

        let removed = prune_in(dir.path(), "CFOO", "testnet", None, Some(7)).unwrap();
        assert_eq!(removed, 1);
        let remaining = list_paths_in(dir.path(), "CFOO", "testnet")
            .unwrap()
            .iter()
            .map(|p| load_alert(p).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].metric, "recent");
    }

    #[test]
    fn export_json_round_trips() {
        let alert = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        let json = format_export(std::slice::from_ref(&alert), "json").unwrap();
        let parsed: Vec<Alert> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, alert.id);
    }

    #[test]
    fn export_csv_has_header_and_row_per_alert() {
        let alerts = vec![
            sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count"),
            sample_alert("CFOO", "testnet", AnomalyKind::ErrorRateShift, "error_rate"),
        ];
        let csv = format_export(&alerts, "csv").unwrap();
        assert!(csv.starts_with("timestamp,contract_id,network"));
        assert_eq!(csv.lines().count(), 3);
    }

    #[test]
    fn export_rejects_unsupported_format() {
        let alert = sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        assert!(format_export(&[alert], "xml").is_err());
    }

    #[test]
    fn summarize_counts_by_severity_and_kind() {
        let alerts = vec![
            sample_alert("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count"),
            sample_alert("CFOO", "testnet", AnomalyKind::ErrorRateShift, "error_rate"),
        ];
        let stats = summarize(&alerts);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.by_kind.get("volume_spike"), Some(&1));
    }
}
