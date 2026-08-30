//! Integration tests for the ai-disaster-recovery subsystem.
//! All tests use tempfile::TempDir — no writes to ~/.starforge/, no network calls.

use starforge::commands::ai::recovery::{
    backup::run_backup,
    model::{Artifact, ArtifactKind, ArtifactStatus, BackupPolicy, EncryptionMode, IntegrityAlgorithm, VerifyStatus},
    verify::{verify_all, verify_one},
    restore_sim::simulate,
};
use chrono::Utc;
use tempfile::TempDir;

fn make_artifact(path: &str) -> Artifact {
    Artifact {
        id: uuid::Uuid::new_v4().to_string(),
        kind: ArtifactKind::WasmBinary,
        path: path.to_string(),
        status: ArtifactStatus::Present,
        sha256: Some("abc123".to_string()),
        expected_sha256: None,
        size_bytes: 512,
        last_modified: Utc::now(),
    }
}

fn plain_policy(retention: u32) -> BackupPolicy {
    BackupPolicy {
        schema_version: 1,
        cadence_hours: 24,
        retention_count: retention,
        encryption: EncryptionMode::None,
        integrity: IntegrityAlgorithm::Sha256,
    }
}

// ── backup_verify_roundtrip ───────────────────────────────────────────────────

#[test]
fn backup_verify_roundtrip() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let result = run_backup(&artifacts, &plain_policy(7), &store, "", false).unwrap();
    let archive = std::path::PathBuf::from(&result.archive_path);
    let vr = verify_one(&archive, None).unwrap();
    assert_eq!(vr.status, VerifyStatus::Ok, "backup should verify OK");
}

// ── corrupted_archive_detection ───────────────────────────────────────────────

#[test]
fn corrupted_archive_detection() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let result = run_backup(&artifacts, &plain_policy(7), &store, "", false).unwrap();
    let archive = std::path::PathBuf::from(&result.archive_path);

    // Corrupt by flipping bytes.
    let mut bytes = std::fs::read(&archive).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&archive, &bytes).unwrap();

    let vr = verify_one(&archive, None).unwrap();
    assert_eq!(vr.status, VerifyStatus::Corrupted);
    assert!(vr.expected_digest.is_some());
    assert!(vr.actual_digest.is_some());
}

// ── missing_sidecar ───────────────────────────────────────────────────────────

#[test]
fn missing_sidecar() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let result = run_backup(&artifacts, &plain_policy(7), &store, "", false).unwrap();
    let archive = std::path::PathBuf::from(&result.archive_path);

    // Delete the .sha256 sidecar.
    let mut sidecar = archive.as_os_str().to_owned();
    sidecar.push(".sha256");
    std::fs::remove_file(std::path::PathBuf::from(sidecar)).unwrap();

    let vr = verify_one(&archive, None).unwrap();
    assert_eq!(vr.status, VerifyStatus::Unverifiable);
}

// ── restore_dry_run_pass ──────────────────────────────────────────────────────

#[test]
fn restore_dry_run_pass() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let result = run_backup(&artifacts, &plain_policy(7), &store, "", false).unwrap();
    let archive = std::path::PathBuf::from(&result.archive_path);
    let sim = simulate(&archive, None).unwrap();
    assert!(sim.simulation_passed, "restore dry-run should pass for valid archive");
    assert_eq!(sim.artifact_count, 1);
}

// ── restore_dry_run_fail ──────────────────────────────────────────────────────

#[test]
fn restore_dry_run_fail_reports_all_failures() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");

    // Two artifacts with empty IDs — both should fail validation.
    let mut a1 = make_artifact("/project/a.wasm");
    a1.id = String::new();
    let mut a2 = make_artifact("/project/b.wasm");
    a2.id = String::new();

    let result = run_backup(&[a1, a2], &plain_policy(7), &store, "", false).unwrap();
    let archive = std::path::PathBuf::from(&result.archive_path);
    let sim = simulate(&archive, None).unwrap();

    assert!(!sim.simulation_passed);
    let failed = sim.validation_results.iter().filter(|v| !v.passed).count();
    assert_eq!(failed, 2, "all failures must be reported, not just the first");
}

// ── retention_enforcement_integration ────────────────────────────────────────

#[test]
fn retention_enforcement_integration() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let policy = plain_policy(2);

    // Run 3 backups; only 2 should remain.
    for _ in 0..3 {
        run_backup(&artifacts, &policy, &store, "", false).unwrap();
    }

    let entries: Vec<_> = std::fs::read_dir(&store)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(".tar.gz")).unwrap_or(false))
        .collect();

    assert!(entries.len() <= 2, "expected at most 2 archives, got {}", entries.len());
}

// ── no_archive_overwrite_integration ─────────────────────────────────────────

#[test]
fn no_archive_overwrite_integration() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    std::fs::create_dir_all(&store).unwrap();
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let archive_bytes = serde_json::to_vec(&artifacts).unwrap();

    // Write two archives with the same base name via never_overwrite.
    let base = "backup-2024-01-01T00-00-00.tar.gz";
    let path1 = starforge::commands::ai::recovery::persistence::never_overwrite(&store, base);
    starforge::commands::ai::recovery::persistence::atomic_write(&path1, &archive_bytes).unwrap();
    let path2 = starforge::commands::ai::recovery::persistence::never_overwrite(&store, base);
    starforge::commands::ai::recovery::persistence::atomic_write(&path2, &archive_bytes).unwrap();

    assert_ne!(path1, path2, "second path must differ from first");

    let archives: Vec<_> = std::fs::read_dir(&store)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(".tar.gz") || n.ends_with(".tar.gz.1")).unwrap_or(false))
        .collect();

    assert_eq!(archives.len(), 2, "two distinct archive files should exist, not one overwritten");
}

// ── verify_all_integration ────────────────────────────────────────────────────

#[test]
fn verify_all_all_ok() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("backups");
    std::fs::create_dir_all(&store).unwrap();
    let artifacts = vec![make_artifact("/project/contract.wasm")];
    let archive_bytes = serde_json::to_vec(&artifacts).unwrap();

    // Write 3 archives with distinct timestamped names + sha256 sidecars.
    for i in 1u8..=3 {
        let name = format!("backup-2024-01-01T00-00-0{}.tar.gz", i);
        let path = store.join(&name);
        std::fs::write(&path, &archive_bytes).unwrap();
        let digest = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&archive_bytes);
            format!("{:x}", h.finalize())
        };
        let mut sp = path.as_os_str().to_owned();
        sp.push(".sha256");
        std::fs::write(std::path::PathBuf::from(sp), &digest).unwrap();
    }

    let results = verify_all(&store, None).unwrap();
    assert_eq!(results.len(), 3, "verify_all should return one result per archive");
    for r in &results {
        assert_eq!(r.status, VerifyStatus::Ok);
    }
}
