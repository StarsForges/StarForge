//! Versioned persistence for cost estimates, enabling trend export and
//! regression-threshold checks across runs.
//!
//! Snapshots are stored as one pretty-printed JSON file per estimate under
//! `<data_dir>/cost_history/<label>/<timestamp>.json`, mirroring the
//! versioned-report convention used by `utils::upgrade_analyzer` rather than
//! the append-only jsonl log convention used by `utils::telemetry` — each
//! estimate is a standalone, independently loadable artifact rather than a
//! log line. File names are RFC3339-ish sortable timestamps so directory
//! listing order is chronological without parsing file contents.

use crate::commands::cost::model::CostEstimate;
use crate::utils::config;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const HISTORY_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySnapshot {
    pub schema_version: u8,
    pub label: String,
    pub timestamp: DateTime<Utc>,
    pub estimate: CostEstimate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionCheckResult {
    pub label: String,
    pub threshold_percent: f64,
    pub candidate_timestamp: DateTime<Utc>,
    pub candidate_fee_stroops: u64,
    pub baseline_timestamp: Option<DateTime<Utc>>,
    pub baseline_fee_stroops: Option<u64>,
    pub delta_stroops: i64,
    pub delta_percent: f64,
    pub regressed: bool,
}

/// Replaces any character outside `[A-Za-z0-9_-]` with `_` so a label is
/// always safe to use as a single path segment (no traversal, no separators).
fn sanitize_label(label: &str) -> String {
    let sanitized: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "default".to_string()
    } else {
        sanitized
    }
}

fn history_dir(base: &Path, label: &str) -> PathBuf {
    base.join("cost_history").join(sanitize_label(label))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn snapshot_filename(timestamp: DateTime<Utc>) -> String {
    format!("{}.json", timestamp.format("%Y%m%dT%H%M%S%3fZ"))
}

fn save_snapshot_in(base: &Path, label: &str, estimate: &CostEstimate) -> Result<PathBuf> {
    let dir = history_dir(base, label);
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create cost history directory {}", dir.display()))?;

    let timestamp = Utc::now();
    let mut estimate = estimate.clone();
    estimate.label = Some(label.to_string());
    let snapshot = HistorySnapshot {
        schema_version: HISTORY_SCHEMA_VERSION,
        label: label.to_string(),
        timestamp,
        estimate,
    };

    let path = dir.join(snapshot_filename(timestamp));
    let json = serde_json::to_string_pretty(&snapshot).context("Failed to serialize snapshot")?;
    fs::write(&path, json)
        .with_context(|| format!("Failed to write snapshot to {}", path.display()))?;
    restrict_permissions(&path)?;
    Ok(path)
}

fn list_snapshot_paths_in(base: &Path, label: &str) -> Result<Vec<PathBuf>> {
    let dir = history_dir(base, label);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("Failed to read cost history directory {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn load_snapshot_from(path: &Path) -> Result<HistorySnapshot> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read snapshot {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| {
        format!(
            "Failed to parse snapshot {} (schema mismatch?)",
            path.display()
        )
    })
}

fn load_all_snapshots_in(base: &Path, label: &str) -> Result<Vec<HistorySnapshot>> {
    list_snapshot_paths_in(base, label)?
        .iter()
        .map(|p| load_snapshot_from(p))
        .collect()
}

fn check_regression_in(
    base: &Path,
    label: &str,
    threshold_percent: f64,
) -> Result<RegressionCheckResult> {
    let snapshots = load_all_snapshots_in(base, label)?;
    let candidate = snapshots
        .last()
        .with_context(|| format!("No cost history found for label '{}'", label))?;

    let baseline = if snapshots.len() >= 2 {
        snapshots.get(snapshots.len() - 2)
    } else {
        None
    };

    let candidate_fee = candidate.estimate.total_fee_stroops;
    let (baseline_timestamp, baseline_fee, delta_stroops, delta_percent) = match baseline {
        Some(b) => {
            let delta = candidate_fee as i64 - b.estimate.total_fee_stroops as i64;
            let pct = if b.estimate.total_fee_stroops == 0 {
                0.0
            } else {
                (delta as f64 / b.estimate.total_fee_stroops as f64) * 100.0
            };
            (
                Some(b.timestamp),
                Some(b.estimate.total_fee_stroops),
                delta,
                pct,
            )
        }
        None => (None, None, 0, 0.0),
    };

    let regressed = baseline.is_some() && delta_percent > threshold_percent;

    Ok(RegressionCheckResult {
        label: label.to_string(),
        threshold_percent,
        candidate_timestamp: candidate.timestamp,
        candidate_fee_stroops: candidate_fee,
        baseline_timestamp,
        baseline_fee_stroops: baseline_fee,
        delta_stroops,
        delta_percent,
        regressed,
    })
}

fn export_history_in(base: &Path, label: &str, format: &str) -> Result<String> {
    let snapshots = load_all_snapshots_in(base, label)?;
    match format {
        "json" => {
            serde_json::to_string_pretty(&snapshots).context("Failed to serialize history export")
        }
        "csv" => {
            let mut out = String::from(
                "timestamp,operation,network,batch_size,total_fee_stroops,total_fee_xlm\n",
            );
            for s in &snapshots {
                out.push_str(&format!(
                    "{},{},{},{},{},{:.7}\n",
                    s.timestamp.to_rfc3339(),
                    s.estimate.operation.as_str(),
                    s.estimate.network,
                    s.estimate.batch_size,
                    s.estimate.total_fee_stroops,
                    s.estimate.total_fee_xlm,
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

// ── Public API (defaults to the real starforge data directory) ──────────────

pub fn save_snapshot(label: &str, estimate: &CostEstimate) -> Result<PathBuf> {
    save_snapshot_in(&config::get_data_dir()?, label, estimate)
}

pub fn load_all_snapshots(label: &str) -> Result<Vec<HistorySnapshot>> {
    load_all_snapshots_in(&config::get_data_dir()?, label)
}

pub fn load_latest(label: &str) -> Result<Option<HistorySnapshot>> {
    Ok(load_all_snapshots(label)?.into_iter().next_back())
}

pub fn check_regression(label: &str, threshold_percent: f64) -> Result<RegressionCheckResult> {
    check_regression_in(&config::get_data_dir()?, label, threshold_percent)
}

pub fn export_history(label: &str, format: &str) -> Result<String> {
    export_history_in(&config::get_data_dir()?, label, format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cost::model::{estimate_cost, OperationKind, ResourceUsage};
    use tempfile::tempdir;

    fn sample_estimate(cpu: u64) -> CostEstimate {
        let usage = ResourceUsage {
            cpu_insns: cpu,
            ..Default::default()
        };
        estimate_cost(&usage, OperationKind::Invoke, "testnet", 1, None)
    }

    #[test]
    fn sanitize_label_strips_unsafe_characters() {
        assert_eq!(sanitize_label("my/contract:v1"), "my_contract_v1");
        assert_eq!(sanitize_label(""), "default");
        assert_eq!(sanitize_label("../../etc"), "______etc");
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = tempdir().unwrap();
        let est = sample_estimate(10_000);
        let path = save_snapshot_in(dir.path(), "my-contract", &est).unwrap();
        assert!(path.exists());

        let loaded = load_snapshot_from(&path).unwrap();
        assert_eq!(loaded.schema_version, HISTORY_SCHEMA_VERSION);
        assert_eq!(loaded.estimate.total_fee_stroops, est.total_fee_stroops);
    }

    #[cfg(unix)]
    #[test]
    fn saved_snapshot_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let est = sample_estimate(1_000);
        let path = save_snapshot_in(dir.path(), "perm-check", &est).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn list_is_empty_when_no_history_exists() {
        let dir = tempdir().unwrap();
        let snapshots = load_all_snapshots_in(dir.path(), "never-seen").unwrap();
        assert!(snapshots.is_empty());
    }

    #[test]
    fn regression_check_flags_increase_beyond_threshold() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "regress-me", &sample_estimate(10_000)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        save_snapshot_in(dir.path(), "regress-me", &sample_estimate(100_000)).unwrap();

        let result = check_regression_in(dir.path(), "regress-me", 5.0).unwrap();
        assert!(result.regressed);
        assert!(result.delta_percent > 5.0);
        assert!(result.baseline_fee_stroops.is_some());
    }

    #[test]
    fn regression_check_passes_within_threshold() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "stable", &sample_estimate(10_000)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        save_snapshot_in(dir.path(), "stable", &sample_estimate(10_050)).unwrap();

        let result = check_regression_in(dir.path(), "stable", 50.0).unwrap();
        assert!(!result.regressed);
    }

    #[test]
    fn regression_check_without_baseline_never_regresses() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "first-run", &sample_estimate(10_000)).unwrap();
        let result = check_regression_in(dir.path(), "first-run", 5.0).unwrap();
        assert!(!result.regressed);
        assert!(result.baseline_fee_stroops.is_none());
    }

    #[test]
    fn regression_check_errors_on_unknown_label() {
        let dir = tempdir().unwrap();
        assert!(check_regression_in(dir.path(), "nonexistent", 5.0).is_err());
    }

    #[test]
    fn export_json_round_trips_snapshots() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "export-me", &sample_estimate(5_000)).unwrap();
        let json = export_history_in(dir.path(), "export-me", "json").unwrap();
        let parsed: Vec<HistorySnapshot> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn export_csv_includes_header_and_row() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "export-csv", &sample_estimate(5_000)).unwrap();
        let csv = export_history_in(dir.path(), "export-csv", "csv").unwrap();
        assert!(csv.starts_with("timestamp,operation,network"));
        assert_eq!(csv.lines().count(), 2);
    }

    #[test]
    fn export_rejects_unsupported_format() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "export-bad", &sample_estimate(5_000)).unwrap();
        assert!(export_history_in(dir.path(), "export-bad", "xml").is_err());
    }

    #[test]
    fn snapshots_are_returned_in_chronological_order() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "ordered", &sample_estimate(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        save_snapshot_in(dir.path(), "ordered", &sample_estimate(2)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        save_snapshot_in(dir.path(), "ordered", &sample_estimate(3)).unwrap();

        let snapshots = load_all_snapshots_in(dir.path(), "ordered").unwrap();
        let cpu_order: Vec<u64> = snapshots
            .iter()
            .map(|s| s.estimate.resource_usage.cpu_insns)
            .collect();
        assert_eq!(cpu_order, vec![1, 2, 3]);
    }
}
