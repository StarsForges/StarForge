//! Restore dry-run simulation for the AI disaster-recovery subsystem.
//! Validates every artifact in a backup archive without writing any files.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;

use super::crypto;
use super::model::{Artifact, ArtifactValidation, SimulationResult};

/// Simulate a full restore from `archive` without writing any files.
/// Returns a [`SimulationResult`] with all validation failures collected.
pub fn simulate(archive: &Path, passphrase: Option<&str>) -> Result<SimulationResult> {
    let archive_str = archive.to_string_lossy().to_string();

    // Read raw bytes.
    let raw_bytes = std::fs::read(archive)
        .with_context(|| format!("Failed to read archive {}", archive.display()))?;

    // Decrypt if key_params.json sidecar exists.
    let mut kp_path = archive.as_os_str().to_owned();
    kp_path.push(".key_params.json");
    let kp_path = std::path::PathBuf::from(kp_path);

    let payload_bytes = if kp_path.exists() {
        let kp_bytes = std::fs::read(&kp_path)
            .with_context(|| format!("Failed to read key_params.json for {}", archive.display()))?;
        let kp: serde_json::Value = serde_json::from_slice(&kp_bytes)
            .context("Failed to parse key_params.json")?;
        let salt_b64 = kp
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("key_params.json missing 'salt' field"))?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64)
            .context("Failed to base64-decode salt")?;
        let pass = passphrase.unwrap_or("");
        crypto::decrypt(&raw_bytes, pass, &salt)
            .context("Failed to decrypt archive; wrong passphrase or corrupted data")?
    } else {
        raw_bytes
    };

    // Deserialize as Vec<Artifact> (JSON format written by backup.rs).
    let artifacts: Vec<Artifact> = serde_json::from_slice(&payload_bytes)
        .context("Failed to deserialize artifacts from archive")?;

    let artifact_count = artifacts.len();
    let mut validation_results: Vec<ArtifactValidation> = Vec::new();

    for artifact in &artifacts {
        let mut issues: Vec<String> = Vec::new();

        // (a) Check path is not empty.
        if artifact.path.is_empty() {
            issues.push("artifact path is empty".to_string());
        }

        // (b) Check that no clear-text Stellar secret key appears in the path.
        if contains_stellar_key(&artifact.path) {
            issues.push("artifact path contains a clear-text Stellar secret key".to_string());
        }

        // (c) Validate id is non-empty.
        if artifact.id.is_empty() {
            issues.push("artifact id is empty".to_string());
        }

        let passed = issues.is_empty();
        validation_results.push(ArtifactValidation {
            artifact_id: artifact.id.clone(),
            passed,
            issues,
        });
    }

    let simulation_passed = validation_results.iter().all(|v| v.passed);
    let total_bytes: u64 = artifacts.iter().map(|a| a.size_bytes).sum();
    let simulated_restore_duration_ms = std::cmp::max(1, total_bytes / 10_240);

    Ok(SimulationResult {
        archive_path: archive_str,
        artifact_count,
        validation_results,
        simulation_passed,
        simulated_restore_duration_ms,
    })
}

/// Returns true if the string contains a 56-char S-prefixed Stellar secret key.
fn contains_stellar_key(s: &str) -> bool {
    for token in s.split(|c: char| c.is_whitespace() || c == '/' || c == '\\') {
        if token.len() == 56
            && token.starts_with('S')
            && token.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ai::recovery::backup::run_backup;
    use crate::commands::ai::recovery::model::{
        ArtifactKind, ArtifactStatus, BackupPolicy, EncryptionMode, IntegrityAlgorithm,
    };
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_artifact(path: &str) -> crate::commands::ai::recovery::model::Artifact {
        crate::commands::ai::recovery::model::Artifact {
            id: uuid::Uuid::new_v4().to_string(),
            kind: ArtifactKind::WasmBinary,
            path: path.to_string(),
            status: ArtifactStatus::Present,
            sha256: Some("abc".to_string()),
            expected_sha256: None,
            size_bytes: 1024,
            last_modified: Utc::now(),
        }
    }

    fn plain_policy() -> BackupPolicy {
        BackupPolicy {
            schema_version: 1,
            cadence_hours: 24,
            retention_count: 7,
            encryption: EncryptionMode::None,
            integrity: IntegrityAlgorithm::Sha256,
        }
    }

    #[test]
    fn simulate_valid_archive_passes() {
        let dir = TempDir::new().unwrap();
        let store = dir.path().join("backups");
        let artifacts = vec![make_artifact("/project/contract.wasm")];
        let result = run_backup(&artifacts, &plain_policy(), &store, "", false).unwrap();
        let archive = std::path::PathBuf::from(&result.archive_path);
        let sim = simulate(&archive, None).unwrap();
        assert!(sim.simulation_passed);
        assert_eq!(sim.artifact_count, 1);
        assert!(sim.validation_results.iter().all(|v| v.passed));
    }

    #[test]
    fn simulate_empty_artifact_id_fails() {
        let dir = TempDir::new().unwrap();
        let store = dir.path().join("backups");
        let mut artifact = make_artifact("/project/contract.wasm");
        artifact.id = String::new(); // corrupt the id
        let artifacts = vec![artifact];
        let result = run_backup(&artifacts, &plain_policy(), &store, "", false).unwrap();
        let archive = std::path::PathBuf::from(&result.archive_path);
        let sim = simulate(&archive, None).unwrap();
        assert!(!sim.simulation_passed);
        assert!(sim.validation_results.iter().any(|v| !v.passed));
    }

    #[test]
    fn simulate_reports_all_failures_not_just_first() {
        let dir = TempDir::new().unwrap();
        let store = dir.path().join("backups");
        let mut a1 = make_artifact("/project/a.wasm");
        a1.id = String::new();
        let mut a2 = make_artifact("/project/b.wasm");
        a2.id = String::new();
        let result = run_backup(&[a1, a2], &plain_policy(), &store, "", false).unwrap();
        let archive = std::path::PathBuf::from(&result.archive_path);
        let sim = simulate(&archive, None).unwrap();
        assert!(!sim.simulation_passed);
        let failed = sim.validation_results.iter().filter(|v| !v.passed).count();
        assert_eq!(failed, 2, "both failures should be reported");
    }

    #[test]
    fn simulate_writes_no_files() {
        let dir = TempDir::new().unwrap();
        let store = dir.path().join("backups");
        let artifacts = vec![make_artifact("/project/contract.wasm")];
        let result = run_backup(&artifacts, &plain_policy(), &store, "", false).unwrap();
        let archive = std::path::PathBuf::from(&result.archive_path);

        let before: Vec<_> = std::fs::read_dir(&store)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

        simulate(&archive, None).unwrap();

        let after: Vec<_> = std::fs::read_dir(&store)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

        assert_eq!(before.len(), after.len(), "simulate must not write any files");
    }
}
