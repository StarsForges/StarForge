//! Append-only evidence log: a durable record of the documents,
//! attestations, and reviews backing a compliance control, stored as
//! newline-delimited JSON (mirrors [`crate::utils::ai_telemetry`]'s event
//! log shape).

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::path::PathBuf;

pub const EVIDENCE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub schema_version: u8,
    pub id: String,
    pub control_id: String,
    pub description: String,
    pub file_reference: Option<String>,
    pub reviewer: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

impl EvidenceRecord {
    pub fn new(
        control_id: impl Into<String>,
        description: impl Into<String>,
        file_reference: Option<String>,
        reviewer: Option<String>,
    ) -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            control_id: control_id.into(),
            description: description.into(),
            file_reference,
            reviewer,
            recorded_at: Utc::now(),
        }
    }
}

fn evidence_log_path() -> PathBuf {
    super::compliance_dir().join("evidence.jsonl")
}

/// Appends a single evidence record to the log, creating the compliance
/// directory if needed.
pub fn record(entry: &EvidenceRecord) -> Result<()> {
    let dir = super::compliance_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    }

    let path = evidence_log_path();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Failed to open evidence log at {}", path.display()))?;

    let line = serde_json::to_string(entry).context("Failed to serialize evidence record")?;
    writeln!(file, "{line}").with_context(|| format!("Failed to append to {}", path.display()))?;
    Ok(())
}

/// Loads every evidence record on file, oldest first. Missing file means no
/// evidence has been recorded yet, which is not an error.
pub fn load_all() -> Result<Vec<EvidenceRecord>> {
    let path = evidence_log_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file =
        fs::File::open(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines() {
        let line =
            line.with_context(|| format!("Failed to read a line from {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: EvidenceRecord = serde_json::from_str(&line)
            .with_context(|| format!("Failed to parse evidence record: {line}"))?;
        records.push(record);
    }
    Ok(records)
}

/// True if any evidence was recorded for `control_id` within the last
/// `within_days` days, relative to `now`.
pub fn has_recent_evidence(
    records: &[EvidenceRecord],
    control_id: &str,
    within_days: i64,
    now: DateTime<Utc>,
) -> bool {
    let cutoff = now - Duration::days(within_days);
    records
        .iter()
        .any(|r| r.control_id == control_id && r.recorded_at >= cutoff)
}

pub fn all_for_control<'a>(
    records: &'a [EvidenceRecord],
    control_id: &str,
) -> Vec<&'a EvidenceRecord> {
    records
        .iter()
        .filter(|r| r.control_id == control_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Isolates `HOME` for the lifetime of the guard so evidence-log tests
    /// never race each other or the real `~/.starforge` directory. Mirrors
    /// the `TestConfigGuard` pattern in `src/utils/horizon.rs`.
    struct TestHomeGuard {
        _env_lock: MutexGuard<'static, ()>,
        _temp_dir: TempDir,
        original_home: Option<String>,
    }

    impl TestHomeGuard {
        fn new() -> Self {
            let env_lock = TEST_ENV_LOCK.lock().expect("test env lock");
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let original_home = std::env::var("HOME").ok();
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
            }
            Self {
                _env_lock: env_lock,
                _temp_dir: temp_dir,
                original_home,
            }
        }
    }

    impl Drop for TestHomeGuard {
        fn drop(&mut self) {
            match &self.original_home {
                Some(home) => unsafe { std::env::set_var("HOME", home) },
                None => unsafe { std::env::remove_var("HOME") },
            }
        }
    }

    fn record_at(control_id: &str, when: DateTime<Utc>) -> EvidenceRecord {
        EvidenceRecord {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            control_id: control_id.to_string(),
            description: "test evidence".into(),
            file_reference: None,
            reviewer: Some("alice".into()),
            recorded_at: when,
        }
    }

    #[test]
    fn has_recent_evidence_true_within_window() {
        let now = Utc::now();
        let records = vec![record_at("AT-2", now - ChronoDuration::days(10))];
        assert!(has_recent_evidence(&records, "AT-2", 90, now));
    }

    #[test]
    fn has_recent_evidence_false_outside_window() {
        let now = Utc::now();
        let records = vec![record_at("AT-2", now - ChronoDuration::days(200))];
        assert!(!has_recent_evidence(&records, "AT-2", 90, now));
    }

    #[test]
    fn has_recent_evidence_false_for_different_control() {
        let now = Utc::now();
        let records = vec![record_at("AC-1", now)];
        assert!(!has_recent_evidence(&records, "AT-2", 90, now));
    }

    #[test]
    fn all_for_control_filters_correctly() {
        let now = Utc::now();
        let records = vec![
            record_at("AC-1", now),
            record_at("AT-2", now),
            record_at("AC-1", now),
        ];
        assert_eq!(all_for_control(&records, "AC-1").len(), 2);
    }

    #[test]
    fn record_and_load_round_trip() {
        let _guard = TestHomeGuard::new();

        let entry = EvidenceRecord::new(
            "AC-1",
            "Manual code review completed",
            None,
            Some("bob".into()),
        );
        record(&entry).unwrap();

        let loaded = load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].control_id, "AC-1");
        assert_eq!(loaded[0].description, "Manual code review completed");
    }

    #[test]
    fn load_all_returns_empty_when_no_log_exists() {
        let _guard = TestHomeGuard::new();
        assert!(load_all().unwrap().is_empty());
    }
}
