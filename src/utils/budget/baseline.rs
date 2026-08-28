//! Versioned baseline capture and regression comparison for budget metrics.
//!
//! Mirrors the persistence shape of `commands::cost::history` (one
//! pretty-printed JSON snapshot per capture, under a label-derived
//! directory, sortable filenames, restrictive permissions) but stores
//! [`BudgetMetrics`] rather than a cost estimate, since baselines here are
//! about resource/fee regressions across CI runs, not fee-narrative history.

use super::metrics::{BudgetMetrics, MetricKind};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const BASELINE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub schema_version: u8,
    pub label: String,
    pub timestamp: DateTime<Utc>,
    pub metrics: BudgetMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub metric: MetricKind,
    pub baseline: u64,
    pub candidate: u64,
    pub delta: i64,
    pub delta_percent: f64,
    pub regressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub label: String,
    pub threshold_percent: f64,
    pub baseline_timestamp: DateTime<Utc>,
    pub candidate_timestamp: DateTime<Utc>,
    pub deltas: Vec<MetricDelta>,
    pub regressed: bool,
}

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

fn label_fingerprint(label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hex::encode(&hasher.finalize()[..4])
}

fn baseline_dir(base: &Path, label: &str) -> PathBuf {
    base.join("budget").join("baselines").join(format!(
        "{}-{}",
        sanitize_label(label),
        label_fingerprint(label)
    ))
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

fn snapshot_filename(timestamp: DateTime<Utc>, seq: u32) -> String {
    format!("{}-{:03}.json", timestamp.format("%Y%m%dT%H%M%S%3fZ"), seq)
}

fn unique_snapshot_path(dir: &Path, timestamp: DateTime<Utc>) -> PathBuf {
    for seq in 0..1000u32 {
        let candidate = dir.join(snapshot_filename(timestamp, seq));
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!(
        "{}-pid{}.json",
        timestamp.format("%Y%m%dT%H%M%S%3fZ"),
        std::process::id()
    ))
}

fn save_snapshot_in(base: &Path, label: &str, metrics: BudgetMetrics) -> Result<PathBuf> {
    let dir = baseline_dir(base, label);
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create baseline directory {}", dir.display()))?;

    let timestamp = Utc::now();
    let snapshot = BaselineSnapshot {
        schema_version: BASELINE_SCHEMA_VERSION,
        label: label.to_string(),
        timestamp,
        metrics,
    };
    let path = unique_snapshot_path(&dir, timestamp);
    let json = serde_json::to_string_pretty(&snapshot).context("Failed to serialize baseline")?;
    fs::write(&path, json)
        .with_context(|| format!("Failed to write baseline to {}", path.display()))?;
    restrict_permissions(&path)?;
    Ok(path)
}

fn list_snapshot_paths_in(base: &Path, label: &str) -> Result<Vec<PathBuf>> {
    let dir = baseline_dir(base, label);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("Failed to read baseline directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn load_all_snapshots_in(base: &Path, label: &str) -> Result<Vec<BaselineSnapshot>> {
    list_snapshot_paths_in(base, label)?
        .iter()
        .map(|p| {
            let contents = fs::read_to_string(p)
                .with_context(|| format!("Failed to read baseline {}", p.display()))?;
            serde_json::from_str(&contents)
                .with_context(|| format!("Failed to parse baseline {}", p.display()))
        })
        .collect()
}

fn diff_in(base: &Path, label: &str, threshold_percent: f64) -> Result<DiffResult> {
    let snapshots = load_all_snapshots_in(base, label)?;
    if snapshots.len() < 2 {
        anyhow::bail!(
            "Need at least 2 baseline captures for label '{}' to diff; found {}. \
             Run `starforge budget baseline` twice (once per run you want to compare).",
            label,
            snapshots.len()
        );
    }
    let candidate = &snapshots[snapshots.len() - 1];
    let baseline = &snapshots[snapshots.len() - 2];

    let mut deltas = Vec::new();
    let mut regressed = false;
    for kind in MetricKind::ALL {
        let base_val = baseline.metrics.value_of(kind);
        let cand_val = candidate.metrics.value_of(kind);
        let delta = cand_val as i64 - base_val as i64;
        let delta_percent = if base_val == 0 {
            if cand_val == 0 {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            (delta as f64 / base_val as f64) * 100.0
        };
        let metric_regressed = delta_percent > threshold_percent;
        regressed = regressed || metric_regressed;
        deltas.push(MetricDelta {
            metric: kind,
            baseline: base_val,
            candidate: cand_val,
            delta,
            delta_percent,
            regressed: metric_regressed,
        });
    }

    Ok(DiffResult {
        label: label.to_string(),
        threshold_percent,
        baseline_timestamp: baseline.timestamp,
        candidate_timestamp: candidate.timestamp,
        deltas,
        regressed,
    })
}

pub fn save_snapshot(label: &str, metrics: BudgetMetrics) -> Result<PathBuf> {
    save_snapshot_in(&crate::utils::config::get_data_dir()?, label, metrics)
}

pub fn load_all_snapshots(label: &str) -> Result<Vec<BaselineSnapshot>> {
    load_all_snapshots_in(&crate::utils::config::get_data_dir()?, label)
}

pub fn load_latest(label: &str) -> Result<Option<BaselineSnapshot>> {
    Ok(load_all_snapshots(label)?.into_iter().next_back())
}

pub fn diff(label: &str, threshold_percent: f64) -> Result<DiffResult> {
    diff_in(
        &crate::utils::config::get_data_dir()?,
        label,
        threshold_percent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn metrics(cpu: u64) -> BudgetMetrics {
        BudgetMetrics::from_parts(0, 0, cpu, 0, 0, 0, 0, 0, 0, 0)
    }

    #[test]
    fn sanitize_label_strips_unsafe_chars() {
        assert_eq!(sanitize_label("svc/v1:beta"), "svc_v1_beta");
        assert_eq!(sanitize_label(""), "default");
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = save_snapshot_in(dir.path(), "checkout", metrics(1_000)).unwrap();
        assert!(path.exists());
        let all = load_all_snapshots_in(dir.path(), "checkout").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].metrics.cpu_insns, 1_000);
    }

    #[cfg(unix)]
    #[test]
    fn baseline_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = save_snapshot_in(dir.path(), "perm", metrics(1)).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn diff_requires_two_snapshots() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "solo", metrics(100)).unwrap();
        assert!(diff_in(dir.path(), "solo", 10.0).is_err());
    }

    #[test]
    fn diff_flags_regression_beyond_threshold() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "regress", metrics(1_000)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        save_snapshot_in(dir.path(), "regress", metrics(2_000)).unwrap();

        let result = diff_in(dir.path(), "regress", 10.0).unwrap();
        assert!(result.regressed);
        let cpu_delta = result
            .deltas
            .iter()
            .find(|d| d.metric == MetricKind::CpuInsns)
            .unwrap();
        assert!(cpu_delta.regressed);
        assert_eq!(cpu_delta.delta, 1_000);
    }

    #[test]
    fn diff_within_threshold_does_not_regress() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "stable", metrics(1_000)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        save_snapshot_in(dir.path(), "stable", metrics(1_010)).unwrap();

        let result = diff_in(dir.path(), "stable", 50.0).unwrap();
        assert!(!result.regressed);
    }

    #[test]
    fn diff_uses_two_most_recent_snapshots_when_more_than_two_exist() {
        let dir = tempdir().unwrap();
        for cpu in [1_000, 1_001, 5_000] {
            save_snapshot_in(dir.path(), "trend", metrics(cpu)).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let result = diff_in(dir.path(), "trend", 10.0).unwrap();
        let cpu_delta = result
            .deltas
            .iter()
            .find(|d| d.metric == MetricKind::CpuInsns)
            .unwrap();
        assert_eq!(cpu_delta.baseline, 1_001);
        assert_eq!(cpu_delta.candidate, 5_000);
    }

    #[test]
    fn labels_are_isolated_from_each_other() {
        let dir = tempdir().unwrap();
        save_snapshot_in(dir.path(), "a", metrics(1)).unwrap();
        save_snapshot_in(dir.path(), "b", metrics(2)).unwrap();
        assert_eq!(load_all_snapshots_in(dir.path(), "a").unwrap().len(), 1);
        assert_eq!(load_all_snapshots_in(dir.path(), "b").unwrap().len(), 1);
    }
}
