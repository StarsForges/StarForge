//! Versioned baseline persistence for contract performance profiles.
//!
//! Baselines are stored as one JSON file per snapshot under
//! `<data_dir>/perf_baselines/<sanitized-label>-<fingerprint>/<timestamp>-<seq>.json`,
//! following the same convention as [`crate::commands::cost::history`].
//! Each snapshot is a standalone, independently loadable artifact that can be
//! diffed against a future run to detect regressions or improvements.

use crate::utils::config;
use crate::utils::performance::metrics::ProfileMetrics;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const BASELINE_SCHEMA_VERSION: u8 = 1;

/// A versioned snapshot pairing a [`ProfileMetrics`] with its capture timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub schema_version: u8,
    pub label: String,
    pub timestamp: DateTime<Utc>,
    pub metrics: ProfileMetrics,
    /// Human-readable description attached at save time.
    pub description: Option<String>,
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn sanitize_label(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() { "default".to_string() } else { s }
}

fn label_fingerprint(label: &str) -> String {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    hex::encode(&h.finalize()[..4])
}

fn baseline_dir(base: &Path, label: &str) -> PathBuf {
    let dir = format!("{}-{}", sanitize_label(label), label_fingerprint(label));
    base.join("perf_baselines").join(dir)
}

fn snapshot_filename(ts: DateTime<Utc>, seq: u32) -> String {
    format!("{}-{:03}.json", ts.format("%Y%m%dT%H%M%S%3fZ"), seq)
}

fn unique_path(dir: &Path, ts: DateTime<Utc>) -> PathBuf {
    for seq in 0..1000u32 {
        let candidate = dir.join(snapshot_filename(ts, seq));
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

// ── Core persistence operations ───────────────────────────────────────────────

fn save_in(
    base: &Path,
    label: &str,
    metrics: &ProfileMetrics,
    description: Option<&str>,
) -> Result<PathBuf> {
    let dir = baseline_dir(base, label);
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create baseline directory {}", dir.display()))?;

    let ts = Utc::now();
    let snapshot = BaselineSnapshot {
        schema_version: BASELINE_SCHEMA_VERSION,
        label: label.to_string(),
        timestamp: ts,
        metrics: metrics.clone(),
        description: description.map(str::to_string),
    };
    let path = unique_path(&dir, ts);
    let json =
        serde_json::to_string_pretty(&snapshot).context("Failed to serialize baseline snapshot")?;
    fs::write(&path, &json)
        .with_context(|| format!("Failed to write baseline to {}", path.display()))?;
    restrict_permissions(&path)?;
    Ok(path)
}

fn list_paths_in(base: &Path, label: &str) -> Result<Vec<PathBuf>> {
    let dir = baseline_dir(base, label);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("Failed to read baseline directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn load_snapshot(path: &Path) -> Result<BaselineSnapshot> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read baseline {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse baseline {} (schema mismatch?)", path.display()))
}

fn load_all_in(base: &Path, label: &str) -> Result<Vec<BaselineSnapshot>> {
    list_paths_in(base, label)?
        .iter()
        .map(|p| load_snapshot(p))
        .collect()
}

/// Exports all snapshots for a label as JSON or CSV.
fn export_in(base: &Path, label: &str, format: &str) -> Result<String> {
    let snapshots = load_all_in(base, label)?;
    match format {
        "json" => serde_json::to_string_pretty(&snapshots)
            .context("Failed to serialize baseline export"),
        "csv" => {
            let mut out = String::from(
                "timestamp,label,contract_label,network,cpu_insns,mem_bytes,fee_stroops,\
                 read_keys,write_keys,event_count\n",
            );
            for s in &snapshots {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\n",
                    s.timestamp.to_rfc3339(),
                    s.label,
                    s.metrics.contract_label,
                    s.metrics.network,
                    s.metrics.cpu_insns,
                    s.metrics.mem_bytes,
                    s.metrics.sim_fee_stroops,
                    s.metrics.storage.read_only_keys,
                    s.metrics.storage.read_write_keys,
                    s.metrics.events.event_count,
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

// ── Public API ────────────────────────────────────────────────────────────────

/// Save a baseline snapshot to the default StarForge data directory.
pub fn save_baseline(
    label: &str,
    metrics: &ProfileMetrics,
    description: Option<&str>,
) -> Result<PathBuf> {
    save_in(&config::get_data_dir()?, label, metrics, description)
}

/// Load all snapshots for `label`, oldest first.
pub fn load_baselines(label: &str) -> Result<Vec<BaselineSnapshot>> {
    load_all_in(&config::get_data_dir()?, label)
}

/// Load the most recent snapshot for `label`, if one exists.
pub fn load_latest_baseline(label: &str) -> Result<Option<BaselineSnapshot>> {
    Ok(load_baselines(label)?.into_iter().next_back())
}

/// Load all snapshots from a specific file path (useful for `--baseline-file` comparisons).
pub fn load_baseline_from_file(path: &Path) -> Result<BaselineSnapshot> {
    load_snapshot(path)
}

/// Export baseline history as JSON or CSV.
pub fn export_baselines(label: &str, format: &str) -> Result<String> {
    export_in(&config::get_data_dir()?, label, format)
}

/// List all known labels (directories) under the baselines store.
pub fn list_labels() -> Result<Vec<String>> {
    let base = config::get_data_dir()?.join("perf_baselines");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut labels: Vec<String> = fs::read_dir(&base)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .split('-')
                .next()
                .map(str::to_string)
        })
        .collect();
    labels.sort();
    labels.dedup();
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::performance::metrics::ProfileMetrics;
    use tempfile::tempdir;

    fn sample_metrics(cpu: u64) -> ProfileMetrics {
        ProfileMetrics {
            cpu_insns: cpu,
            mem_bytes: 1024,
            contract_label: "my-contract".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn sanitize_removes_unsafe_chars() {
        assert_eq!(sanitize_label("my/contract:v1"), "my_contract_v1");
        assert_eq!(sanitize_label(""), "default");
        assert_eq!(sanitize_label("../../etc"), "______etc");
    }

    #[test]
    fn colliding_labels_map_to_different_dirs() {
        let a = baseline_dir(Path::new("/tmp"), "svc:v1");
        let b = baseline_dir(Path::new("/tmp"), "svc/v1");
        assert_ne!(a, b);
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = tempdir().unwrap();
        let m = sample_metrics(100_000);
        let path = save_in(dir.path(), "mycontract", &m, Some("initial")).unwrap();
        assert!(path.exists());
        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded.schema_version, BASELINE_SCHEMA_VERSION);
        assert_eq!(loaded.metrics.cpu_insns, 100_000);
        assert_eq!(loaded.description, Some("initial".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn saved_baseline_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = save_in(dir.path(), "perm-test", &sample_metrics(1_000), None).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn multiple_saves_do_not_overwrite() {
        let dir = tempdir().unwrap();
        for cpu in 1..=5u64 {
            save_in(dir.path(), "rapid", &sample_metrics(cpu), None).unwrap();
        }
        let all = load_all_in(dir.path(), "rapid").unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn load_all_returns_empty_for_unknown_label() {
        let dir = tempdir().unwrap();
        let all = load_all_in(dir.path(), "never-existed").unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn snapshots_returned_in_chronological_order() {
        let dir = tempdir().unwrap();
        for cpu in [1u64, 2, 3] {
            save_in(dir.path(), "ordered", &sample_metrics(cpu), None).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let all = load_all_in(dir.path(), "ordered").unwrap();
        let cpus: Vec<u64> = all.iter().map(|s| s.metrics.cpu_insns).collect();
        assert_eq!(cpus, vec![1, 2, 3]);
    }

    #[test]
    fn export_json_round_trips() {
        let dir = tempdir().unwrap();
        save_in(dir.path(), "export-me", &sample_metrics(5_000), None).unwrap();
        let json = export_in(dir.path(), "export-me", "json").unwrap();
        let parsed: Vec<BaselineSnapshot> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].metrics.cpu_insns, 5_000);
    }

    #[test]
    fn export_csv_header_and_row() {
        let dir = tempdir().unwrap();
        save_in(dir.path(), "export-csv", &sample_metrics(5_000), None).unwrap();
        let csv = export_in(dir.path(), "export-csv", "csv").unwrap();
        assert!(csv.starts_with("timestamp,label,contract_label"));
        assert_eq!(csv.lines().count(), 2);
    }

    #[test]
    fn export_rejects_unsupported_format() {
        let dir = tempdir().unwrap();
        save_in(dir.path(), "export-bad", &sample_metrics(1), None).unwrap();
        assert!(export_in(dir.path(), "export-bad", "xml").is_err());
    }
}
