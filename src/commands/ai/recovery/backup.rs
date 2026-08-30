//! Backup execution for the AI disaster-recovery subsystem.
//!
//! ## Dry-run
//! When `dry_run` is `true`, `run_backup` prints each artifact path that
//! would be archived and the expected archive path to stdout, then returns
//! immediately with a zeroed [`BackupResult`].  No files are written.
//!
//! ## Normal run
//! 1. Serialize `artifacts` as JSON (one JSON document per archive entry) to
//!    produce an in-memory payload.
//! 2. If `policy.encryption == Aes256Gcm`, encrypt via [`super::crypto`] and
//!    write a `key_params.json` sidecar containing the base64-encoded Argon2
//!    salt.
//! 3. Use [`super::persistence::never_overwrite`] to pick a collision-free
//!    filename of the form `backup-YYYY-MM-DDTHH-MM-SS.tar.gz`.
//! 4. Write the archive to `<store>/<name>.tmp`, then rename atomically via
//!    [`super::persistence::atomic_write`].
//! 5. Compute SHA-256 of the final archive bytes and write a `<archive>.sha256`
//!    sidecar.
//! 6. On any I/O error, delete the `.tmp` file before propagating.
//! 7. Call [`enforce_retention`] to prune old archives.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::crypto;
use super::model::{Artifact, BackupPolicy, BackupResult, EncryptionMode};
use super::persistence::{atomic_write, never_overwrite};

// ── Public API ────────────────────────────────────────────────────────────────

/// Run a backup of `artifacts` according to `policy`.
///
/// `store` is the directory where archive files are written.
/// `passphrase` is used for AES-256-GCM encryption when
/// `policy.encryption == Aes256Gcm`; it is ignored when encryption is
/// `None`.
///
/// When `dry_run` is `true` no files are written; the function prints each
/// artifact path and the expected archive path to stdout and returns a zeroed
/// [`BackupResult`].
pub fn run_backup(
    artifacts: &[Artifact],
    policy: &BackupPolicy,
    store: &Path,
    passphrase: &str,
    dry_run: bool,
) -> Result<BackupResult> {
    let now = Utc::now();
    let timestamp_str = now.format("%Y-%m-%dT%H-%M-%S").to_string();
    let archive_base = format!("backup-{}.tar.gz", timestamp_str);
    let expected_archive_path = store.join(&archive_base);

    if dry_run {
        println!("DRY RUN — the following artifacts would be backed up:");
        for artifact in artifacts {
            println!("  {}", artifact.path);
        }
        println!(
            "Expected archive path: {}",
            expected_archive_path.display()
        );
        return Ok(BackupResult {
            archive_path: expected_archive_path.to_string_lossy().to_string(),
            artifact_count: 0,
            size_bytes: 0,
            integrity_digest: "dry-run".to_string(),
            timestamp: now,
        });
    }

    // Ensure the store directory exists.
    std::fs::create_dir_all(store)
        .with_context(|| format!("Failed to create backup store directory {}", store.display()))?;

    // Serialize artifacts to JSON bytes (used as the archive payload).
    let archive_bytes = serde_json::to_vec(artifacts)
        .context("Failed to serialize artifacts to JSON")?;

    // Encrypt if requested.
    let (final_bytes, maybe_salt) = if policy.encryption == EncryptionMode::Aes256Gcm {
        let (encrypted, salt) = crypto::encrypt(&archive_bytes, passphrase)
            .context("Failed to encrypt backup archive")?;
        (encrypted, Some(salt))
    } else {
        (archive_bytes, None)
    };

    // Resolve a collision-free filename.
    let archive_path = never_overwrite(store, &archive_base);

    // Write the archive atomically via a .tmp file.
    if let Err(e) = atomic_write(&archive_path, &final_bytes) {
        // Clean up any .tmp that may have been left by atomic_write.
        let tmp = tmp_path(&archive_path);
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| {
            format!(
                "Failed to write backup archive to {}",
                archive_path.display()
            )
        });
    }

    // Write key_params.json sidecar (Argon2 salt in base64) if encrypted.
    if let Some(salt) = maybe_salt {
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);
        let key_params = serde_json::json!({ "salt": salt_b64 });
        let key_params_bytes =
            serde_json::to_vec(&key_params).context("Failed to serialize key_params.json")?;
        let key_params_path = sidecar_path(&archive_path, "key_params.json");
        if let Err(e) = atomic_write(&key_params_path, &key_params_bytes) {
            // Roll back the archive on sidecar write failure.
            let _ = std::fs::remove_file(&archive_path);
            return Err(e).with_context(|| {
                format!(
                    "Failed to write key_params.json sidecar for {}",
                    archive_path.display()
                )
            });
        }
    }

    // Compute SHA-256 of the archive bytes and write the .sha256 sidecar.
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(&final_bytes);
        format!("{:x}", hasher.finalize())
    };
    let sha256_path = sha256_sidecar_path(&archive_path);
    if let Err(e) = atomic_write(&sha256_path, digest.as_bytes()) {
        // Roll back the archive on sidecar write failure.
        let _ = std::fs::remove_file(&archive_path);
        return Err(e).with_context(|| {
            format!(
                "Failed to write .sha256 sidecar for {}",
                archive_path.display()
            )
        });
    }

    let size_bytes = final_bytes.len() as u64;
    let artifact_count = artifacts.len();

    // Enforce retention policy.
    enforce_retention(store, policy.retention_count as usize)
        .context("Failed to enforce backup retention policy")?;

    Ok(BackupResult {
        archive_path: archive_path.to_string_lossy().to_string(),
        artifact_count,
        size_bytes,
        integrity_digest: digest,
        timestamp: now,
    })
}

/// Delete the oldest `*.tar.gz` archives in `store` until at most `retain`
/// archives remain.
///
/// Archives are sorted by filename (which uses ISO-8601 UTC timestamps with
/// dashes, so lexicographic order == chronological order).  The oldest
/// (smallest filename) are deleted first.
pub fn enforce_retention(store: &Path, retain: usize) -> Result<()> {
    let mut archives = list_archives(store)?;

    // Sort lexicographically — ISO-timestamp filenames sort by time.
    archives.sort();

    // Delete from the front (oldest) until we are within the limit.
    while archives.len() > retain {
        let oldest = archives.remove(0);
        std::fs::remove_file(&oldest).with_context(|| {
            format!(
                "Failed to delete old backup archive {}",
                oldest.display()
            )
        })?;
        // Best-effort removal of the accompanying sidecars.
        let _ = std::fs::remove_file(sha256_sidecar_path(&oldest));
        let _ = std::fs::remove_file(sidecar_path(&oldest, "key_params.json"));
    }

    Ok(())
}

// ── Private helpers ────────────────────────────────────────────────────────────

/// Return the `.sha256` sidecar path for `archive`.
fn sha256_sidecar_path(archive: &Path) -> PathBuf {
    let mut p = archive.as_os_str().to_owned();
    p.push(".sha256");
    PathBuf::from(p)
}

/// Return a named sidecar next to `archive` (e.g. `key_params.json`).
///
/// The sidecar sits in the same directory as the archive and is named
/// `<archive_filename>.<sidecar_name>`.  Example:
/// `backup-2024-01-01T00-00-00.tar.gz.key_params.json`
fn sidecar_path(archive: &Path, sidecar_name: &str) -> PathBuf {
    let mut p = archive.as_os_str().to_owned();
    p.push(".");
    p.push(sidecar_name);
    PathBuf::from(p)
}

/// Return the `.tmp` path that `atomic_write` uses for `path`.
fn tmp_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".tmp");
    PathBuf::from(p)
}

/// List all `*.tar.gz` paths in `store`.
fn list_archives(store: &Path) -> Result<Vec<PathBuf>> {
    if !store.exists() {
        return Ok(vec![]);
    }

    let entries = std::fs::read_dir(store)
        .with_context(|| format!("Failed to read backup store directory {}", store.display()))?;

    let mut archives = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "Failed to read directory entry in {}",
                store.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("gz")
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.ends_with(".tar.gz"))
                .unwrap_or(false)
        {
            archives.push(path);
        }
    }

    Ok(archives)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ai::recovery::model::{
        ArtifactKind, ArtifactStatus, BackupPolicy, EncryptionMode,
    };
    use chrono::Utc;
    use tempfile::TempDir;

    /// Build a minimal [`Artifact`] for use in tests.
    fn make_artifact(path: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4().to_string(),
            kind: ArtifactKind::WasmBinary,
            path: path.to_string(),
            status: ArtifactStatus::Present,
            sha256: Some("abc123".to_string()),
            expected_sha256: Some("abc123".to_string()),
            size_bytes: 42,
            last_modified: Utc::now(),
        }
    }

    /// Build a [`BackupPolicy`] with the given encryption mode and retention.
    fn make_policy(encryption: EncryptionMode, retention_count: u32) -> BackupPolicy {
        BackupPolicy {
            schema_version: 1,
            cadence_hours: 24,
            retention_count,
            encryption,
            integrity: crate::commands::ai::recovery::model::IntegrityAlgorithm::Sha256,
        }
    }

    // ── dry_run ───────────────────────────────────────────────────────────────

    /// dry_run must produce no files in the store directory.
    #[test]
    fn dry_run_produces_no_files() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("backups");
        std::fs::create_dir_all(&store).unwrap();

        let artifacts = vec![make_artifact("/project/contract.wasm")];
        let policy = make_policy(EncryptionMode::None, 7);

        let result = run_backup(&artifacts, &policy, &store, "", true)
            .expect("dry_run should succeed");

        // No files should have been written.
        let file_count = std::fs::read_dir(&store)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .count();
        assert_eq!(file_count, 0, "dry_run must not write any files");

        // Result is zeroed.
        assert_eq!(result.artifact_count, 0);
        assert_eq!(result.size_bytes, 0);
        assert_eq!(result.integrity_digest, "dry-run");
    }

    // ── successful backup ─────────────────────────────────────────────────────

    /// A successful unencrypted backup writes the archive and a .sha256 sidecar.
    #[test]
    fn successful_backup_writes_archive_and_sha256_sidecar() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("backups");

        let artifacts = vec![
            make_artifact("/project/a.wasm"),
            make_artifact("/project/b.wasm"),
        ];
        let policy = make_policy(EncryptionMode::None, 7);

        let result = run_backup(&artifacts, &policy, &store, "", false)
            .expect("backup should succeed");

        // Archive should exist.
        let archive = PathBuf::from(&result.archive_path);
        assert!(archive.exists(), "archive file should exist");

        // .sha256 sidecar should exist.
        let sha256_file = sha256_sidecar_path(&archive);
        assert!(sha256_file.exists(), ".sha256 sidecar should exist");

        // Digest in result should match the sidecar content.
        let sidecar_content = std::fs::read_to_string(&sha256_file).unwrap();
        assert_eq!(sidecar_content, result.integrity_digest);

        // Artifact count should be correct.
        assert_eq!(result.artifact_count, 2);
        assert!(result.size_bytes > 0);

        // No .tmp should remain.
        let tmp = tmp_path(&archive);
        assert!(!tmp.exists(), "no .tmp should remain after successful backup");
    }

    /// A successful encrypted backup writes the archive, .sha256, and
    /// key_params.json sidecars.
    #[test]
    fn encrypted_backup_writes_key_params_sidecar() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("backups");

        let artifacts = vec![make_artifact("/project/contract.wasm")];
        let policy = make_policy(EncryptionMode::Aes256Gcm, 7);

        let result = run_backup(&artifacts, &policy, &store, "secret-pass", false)
            .expect("encrypted backup should succeed");

        let archive = PathBuf::from(&result.archive_path);
        let key_params = sidecar_path(&archive, "key_params.json");
        assert!(
            key_params.exists(),
            "key_params.json sidecar should exist for encrypted backup"
        );

        // Parse and check it has a "salt" field.
        let kp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&key_params).unwrap()).unwrap();
        assert!(kp.get("salt").is_some(), "key_params.json must contain 'salt'");
    }

    // ── retention enforcement ─────────────────────────────────────────────────

    /// With N+1 archives and retain=N, exactly N archives remain after
    /// enforce_retention.
    #[test]
    fn enforce_retention_leaves_exactly_n_files() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("backups");
        std::fs::create_dir_all(&store).unwrap();
        let policy = make_policy(EncryptionMode::None, 3);
        let _artifacts = vec![make_artifact("/project/contract.wasm")];

        // Write 4 backups (N+1 where N=3). Inject a small sleep-like delay via
        // unique file names using an index suffix to guarantee ordering.
        for i in 0..4u32 {
            // Use a uniquely-named archive to avoid filename collisions.
            let name = format!("backup-2024-01-0{}T00-00-00.tar.gz", i + 1);
            let path = store.join(&name);
            std::fs::write(&path, format!("archive-content-{}", i)).unwrap();
            // Write a sha256 sidecar for each so enforce_retention can clean it up.
            std::fs::write(sha256_sidecar_path(&path), "digest").unwrap();
        }

        enforce_retention(&store, policy.retention_count as usize)
            .expect("enforce_retention should succeed");

        let archives = list_archives(&store).unwrap();
        assert_eq!(
            archives.len(),
            3,
            "enforce_retention should leave exactly N=3 archives"
        );

        // The remaining archives should be the most recent (higher suffix).
        let mut names: Vec<String> = archives
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        names.sort();
        // The oldest archive (day 01) should have been deleted; the remaining
        // three should be days 02, 03, 04.
        assert!(
            !names.iter().any(|n| n.contains("-01T")),
            "oldest archive (day 01) should have been deleted, remaining: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.contains("-02T")),
            "day-02 archive should remain: {:?}",
            names
        );
    }

    /// run_backup with N+1 calls respects retention_count=N.
    #[test]
    fn run_backup_respects_retention_count() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("backups");

        let artifacts = vec![make_artifact("/project/contract.wasm")];
        let policy = make_policy(EncryptionMode::None, 2);

        // Run 3 backups — retention_count=2 so only 2 should remain.
        for _ in 0..3 {
            run_backup(&artifacts, &policy, &store, "", false)
                .expect("backup should succeed");
        }

        let archives = list_archives(&store).unwrap();
        assert!(
            archives.len() <= 2,
            "expected at most 2 archives after retention, got {}",
            archives.len()
        );
    }

    // ── error / cleanup ───────────────────────────────────────────────────────

    /// On a write failure (read-only store directory on Unix), no .tmp file
    /// should remain.
    #[cfg(unix)]
    #[test]
    fn no_tmp_remains_after_failed_write() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("backups");
        std::fs::create_dir_all(&store).unwrap();

        // Make the store directory read-only so writes will fail.
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500))
            .expect("chmod ro");

        let artifacts = vec![make_artifact("/project/contract.wasm")];
        let policy = make_policy(EncryptionMode::None, 7);

        let result = run_backup(&artifacts, &policy, &store, "", false);

        // Restore permissions so TempDir can clean up.
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))
            .expect("chmod rw");

        assert!(result.is_err(), "write to read-only dir should fail");

        // No .tmp should remain anywhere in the store.
        let tmp_count = std::fs::read_dir(&store)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(tmp_count, 0, "no .tmp files should remain after a failed write");
    }

    // ── list_archives ─────────────────────────────────────────────────────────

    /// list_archives returns an empty vec for a non-existent store.
    #[test]
    fn list_archives_returns_empty_for_nonexistent_dir() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("nonexistent");
        let archives = list_archives(&store).expect("should not error");
        assert!(archives.is_empty());
    }

    /// list_archives ignores non-archive files.
    #[test]
    fn list_archives_ignores_non_tar_gz_files() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path();

        std::fs::write(store.join("backup-2024-01-01T00-00-00.tar.gz"), b"").unwrap();
        std::fs::write(store.join("backup-2024-01-01T00-00-00.tar.gz.sha256"), b"").unwrap();
        std::fs::write(store.join("other.json"), b"").unwrap();

        let archives = list_archives(store).expect("should not error");
        assert_eq!(archives.len(), 1, "only .tar.gz files should be listed");
    }
}
