//! Persistence for anomaly baselines.
//!
//! Unlike `performance::baseline` (one immutable snapshot file per run), an
//! anomaly baseline is a single *evolving* record per `(contract, network)`:
//! each observed window folds into the same running statistics rather than
//! creating a new file, since z-score detection needs one coherent mean/
//! stddev per metric, not a history of independent snapshots. Alert history
//! (which *is* an append-only log) lives separately in [`super::alerts`].

use super::migrations::{self, CURRENT_BASELINE_VERSION};
use super::model::Baseline;
use crate::utils::config;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

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

fn baseline_path(base: &Path, contract_id: &str, network: &str) -> PathBuf {
    let name = format!(
        "{}-{}-{}.json",
        sanitize(contract_id),
        sanitize(network),
        fingerprint(contract_id, network)
    );
    base.join("anomaly_baselines").join(name)
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

fn load_in(base: &Path, contract_id: &str, network: &str) -> Result<Option<Baseline>> {
    let path = baseline_path(base, contract_id, network);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read anomaly baseline {}", path.display()))?;
    let baseline = migrations::load_baseline_json(&raw)
        .with_context(|| format!("Failed to load anomaly baseline {}", path.display()))?;
    Ok(Some(baseline))
}

fn save_in(base: &Path, baseline: &Baseline) -> Result<PathBuf> {
    let dir = base.join("anomaly_baselines");
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create baseline directory {}", dir.display()))?;
    let path = baseline_path(base, &baseline.contract_id, &baseline.network);
    let mut versioned = baseline.clone();
    versioned.schema_version = CURRENT_BASELINE_VERSION;
    let json =
        serde_json::to_string_pretty(&versioned).context("Failed to serialize anomaly baseline")?;
    fs::write(&path, &json)
        .with_context(|| format!("Failed to write anomaly baseline {}", path.display()))?;
    restrict_permissions(&path)?;
    Ok(path)
}

fn delete_in(base: &Path, contract_id: &str, network: &str) -> Result<bool> {
    let path = baseline_path(base, contract_id, network);
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove anomaly baseline {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn list_in(base: &Path) -> Result<Vec<Baseline>> {
    let dir = base.join("anomaly_baselines");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("Failed to read baseline directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        if let Ok(baseline) = migrations::load_baseline_json(&raw) {
            out.push(baseline);
        }
    }
    out.sort_by(|a, b| {
        (a.contract_id.as_str(), a.network.as_str())
            .cmp(&(b.contract_id.as_str(), b.network.as_str()))
    });
    Ok(out)
}

// ── Public API ───────────────────────────────────────────────────────────────

pub fn load(contract_id: &str, network: &str) -> Result<Option<Baseline>> {
    load_in(&config::get_data_dir()?, contract_id, network)
}

/// Loads the existing baseline for `(contract_id, network)`, or creates a
/// fresh one if none exists yet.
pub fn load_or_create(contract_id: &str, network: &str) -> Result<Baseline> {
    Ok(load(contract_id, network)?.unwrap_or_else(|| Baseline::new(contract_id, network)))
}

pub fn save(baseline: &Baseline) -> Result<PathBuf> {
    save_in(&config::get_data_dir()?, baseline)
}

pub fn reset(contract_id: &str, network: &str) -> Result<bool> {
    delete_in(&config::get_data_dir()?, contract_id, network)
}

pub fn list_all() -> Result<Vec<Baseline>> {
    list_in(&config::get_data_dir()?)
}

#[cfg(test)]
mod tests {
    use super::super::model::WindowMetrics;
    use super::*;
    use tempfile::tempdir;

    fn sample_window(event_count: u64) -> WindowMetrics {
        WindowMetrics {
            event_count,
            success_count: event_count,
            ..Default::default()
        }
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = tempdir().unwrap();
        let mut baseline = Baseline::new("CFOO", "testnet");
        baseline.observe(&sample_window(10));
        save_in(dir.path(), &baseline).unwrap();

        let loaded = load_in(dir.path(), "CFOO", "testnet").unwrap().unwrap();
        assert_eq!(loaded.sample_count, 1);
        assert_eq!(loaded.contract_id, "CFOO");
    }

    #[test]
    fn load_missing_baseline_returns_none() {
        let dir = tempdir().unwrap();
        assert!(load_in(dir.path(), "CNOPE", "testnet").unwrap().is_none());
    }

    #[test]
    fn different_networks_do_not_collide() {
        let dir = tempdir().unwrap();
        let mut testnet = Baseline::new("CFOO", "testnet");
        testnet.observe(&sample_window(5));
        let mut mainnet = Baseline::new("CFOO", "mainnet");
        mainnet.observe(&sample_window(500));
        save_in(dir.path(), &testnet).unwrap();
        save_in(dir.path(), &mainnet).unwrap();

        let loaded_testnet = load_in(dir.path(), "CFOO", "testnet").unwrap().unwrap();
        let loaded_mainnet = load_in(dir.path(), "CFOO", "mainnet").unwrap().unwrap();
        assert_ne!(
            loaded_testnet.metric("event_count").unwrap().mean,
            loaded_mainnet.metric("event_count").unwrap().mean
        );
    }

    #[test]
    fn reset_removes_baseline() {
        let dir = tempdir().unwrap();
        let baseline = Baseline::new("CFOO", "testnet");
        save_in(dir.path(), &baseline).unwrap();
        assert!(delete_in(dir.path(), "CFOO", "testnet").unwrap());
        assert!(load_in(dir.path(), "CFOO", "testnet").unwrap().is_none());
        assert!(!delete_in(dir.path(), "CFOO", "testnet").unwrap());
    }

    #[test]
    fn list_all_returns_every_saved_baseline() {
        let dir = tempdir().unwrap();
        save_in(dir.path(), &Baseline::new("CFOO", "testnet")).unwrap();
        save_in(dir.path(), &Baseline::new("CBAR", "testnet")).unwrap();
        let all = list_in(dir.path()).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn saved_baseline_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = save_in(dir.path(), &Baseline::new("CFOO", "testnet")).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
