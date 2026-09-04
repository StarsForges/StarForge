//! Backup integrity verifier for the AI disaster-recovery subsystem.
//!
//! ## How verification works
//!
//! For each `*.tar.gz` archive in the backup store, `verify_one`:
//!
//! 1. Reads the `<archive>.sha256` sidecar.  If absent → `Unverifiable`.
//! 2. Reads `<archive>.key_params.json` to obtain the Argon2 salt.  If
//!    present and a passphrase is supplied, decrypts the archive bytes via
//!    [`super::crypto::decrypt`].  Decryption failure → `Corrupted`.
//! 3. Recomputes SHA-256 of the raw (post-encryption) archive bytes and
//!    compares against the stored sidecar digest.  Match → `Ok`, mismatch →
//!    `Corrupted { expected, actual }`.
//!
//! The SHA-256 digest is computed over the raw on-disk bytes (i.e. still
//! encrypted when encryption was used), matching what [`super::backup`]
//! writes after the encrypt step.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::crypto;
use super::model::{VerifyResult, VerifyStatus};

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify a single backup archive.
///
/// `passphrase` is used to attempt decryption when a `key_params.json`
/// sidecar is present.  Pass `None` (or `Some("")`) for unencrypted archives.
///
/// # Returns
/// * `VerifyStatus::Ok` — digest matches the sidecar.
/// * `VerifyStatus::Corrupted` — digest mismatch **or** decryption failure.
/// * `VerifyStatus::Unverifiable` — `.sha256` sidecar is absent.
pub fn verify_one(archive: &Path, passphrase: Option<&str>) -> Result<VerifyResult> {
    let archive_path_str = archive.to_string_lossy().to_string();

    // ── Step 1: read the .sha256 sidecar ────────────────────────────────────
    let sha256_path = sha256_sidecar_path(archive);
    if !sha256_path.exists() {
        return Ok(VerifyResult {
            archive_path: archive_path_str,
            status: VerifyStatus::Unverifiable,
            expected_digest: None,
            actual_digest: None,
        });
    }

    let expected_digest = std::fs::read_to_string(&sha256_path)
        .with_context(|| format!("Failed to read .sha256 sidecar {}", sha256_path.display()))?
        .trim()
        .to_string();

    // ── Step 2: read raw archive bytes ───────────────────────────────────────
    let raw_bytes = std::fs::read(archive)
        .with_context(|| format!("Failed to read archive {}", archive.display()))?;

    // ── Step 3: check for encryption sidecar ────────────────────────────────
    //
    // The key_params.json sidecar is present iff the archive was encrypted.
    // When it is present we attempt decryption to confirm the passphrase
    // produces valid plaintext — a failed decrypt is treated as corruption
    // (requirement 4.7).  The digest is always compared against the raw
    // (still-encrypted) bytes, mirroring what backup.rs writes.
    let key_params_path = key_params_sidecar_path(archive);
    if key_params_path.exists() {
        if let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) {
            // Parse the salt from key_params.json.
            let kp_bytes = std::fs::read(&key_params_path).with_context(|| {
                format!(
                    "Failed to read key_params.json sidecar {}",
                    key_params_path.display()
                )
            })?;
            let kp: serde_json::Value = serde_json::from_slice(&kp_bytes).with_context(|| {
                format!(
                    "key_params.json is not valid JSON: {}",
                    key_params_path.display()
                )
            })?;

            let salt_b64 = kp.get("salt").and_then(|v| v.as_str()).with_context(|| {
                format!(
                    "key_params.json missing 'salt' field: {}",
                    key_params_path.display()
                )
            })?;

            let salt = base64::engine::general_purpose::STANDARD
                .decode(salt_b64)
                .with_context(|| {
                    format!(
                        "Failed to base64-decode salt from {}",
                        key_params_path.display()
                    )
                })?;

            // Attempt decryption — failure means wrong passphrase or corruption.
            if crypto::decrypt(&raw_bytes, passphrase, &salt).is_err() {
                let actual_digest = compute_sha256(&raw_bytes);
                return Ok(VerifyResult {
                    archive_path: archive_path_str,
                    status: VerifyStatus::Corrupted,
                    expected_digest: Some(expected_digest),
                    actual_digest: Some(actual_digest),
                });
            }
        }
        // If no passphrase was supplied for an encrypted archive we fall
        // through to the digest check — the SHA-256 is over raw bytes so
        // it still works without decrypting.
    }

    // ── Step 4: recompute SHA-256 and compare ────────────────────────────────
    let actual_digest = compute_sha256(&raw_bytes);

    if actual_digest == expected_digest {
        Ok(VerifyResult {
            archive_path: archive_path_str,
            status: VerifyStatus::Ok,
            expected_digest: Some(expected_digest),
            actual_digest: Some(actual_digest),
        })
    } else {
        Ok(VerifyResult {
            archive_path: archive_path_str,
            status: VerifyStatus::Corrupted,
            expected_digest: Some(expected_digest),
            actual_digest: Some(actual_digest),
        })
    }
}

/// Verify all `*.tar.gz` archives found in `store`.
///
/// Archives are processed in lexicographic (chronological) filename order.
/// Each archive is verified independently via [`verify_one`].
pub fn verify_all(store: &Path, passphrase: Option<&str>) -> Result<Vec<VerifyResult>> {
    let mut archives = list_archives(store)?;
    archives.sort();

    let mut results = Vec::with_capacity(archives.len());
    for archive in archives {
        let result = verify_one(&archive, passphrase)
            .with_context(|| format!("Failed to verify archive {}", archive.display()))?;
        results.push(result);
    }
    Ok(results)
}

// ── Private helpers ────────────────────────────────────────────────────────────

/// Return the path of the `.sha256` sidecar for `archive`.
fn sha256_sidecar_path(archive: &Path) -> PathBuf {
    let mut p = archive.as_os_str().to_owned();
    p.push(".sha256");
    PathBuf::from(p)
}

/// Return the path of the `key_params.json` sidecar for `archive`.
fn key_params_sidecar_path(archive: &Path) -> PathBuf {
    let mut p = archive.as_os_str().to_owned();
    p.push(".key_params.json");
    PathBuf::from(p)
}

/// Compute the lowercase hex SHA-256 digest of `bytes`.
fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// List all `*.tar.gz` paths in `store`.  Returns an empty vec when the
/// directory does not exist.
fn list_archives(store: &Path) -> Result<Vec<PathBuf>> {
    if !store.exists() {
        return Ok(vec![]);
    }
    let entries = std::fs::read_dir(store)
        .with_context(|| format!("Failed to read backup store directory {}", store.display()))?;

    let mut archives = Vec::new();
    for entry in entries {
        let entry = entry
            .with_context(|| format!("Failed to read directory entry in {}", store.display()))?;
        let path = entry.path();
        if path
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
    use tempfile::TempDir;

    /// Write a fake archive with a correct .sha256 sidecar.
    fn write_valid_archive(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let archive = dir.join(name);
        std::fs::write(&archive, contents).unwrap();
        let digest = compute_sha256(contents);
        std::fs::write(sha256_sidecar_path(&archive), digest.as_bytes()).unwrap();
        archive
    }

    // ── verify_one: ok path ───────────────────────────────────────────────────

    /// Task 9.1 — valid archive with matching digest returns Ok.
    /// Validates: Requirements 4.1, 4.3
    #[test]
    fn verify_one_valid_archive_returns_ok() {
        let dir = TempDir::new().unwrap();
        let archive = write_valid_archive(dir.path(), "backup.tar.gz", b"archive contents");

        let result = verify_one(&archive, None).unwrap();

        assert_eq!(result.status, VerifyStatus::Ok);
        assert!(result.expected_digest.is_some());
        assert_eq!(result.expected_digest, result.actual_digest);
    }

    // ── verify_one: corrupted (byte-flip) ────────────────────────────────────

    /// Task 9.1 — archive with a flipped byte returns Corrupted with both
    /// digests populated.
    /// Validates: Requirements 4.3
    #[test]
    fn verify_one_byte_flipped_archive_returns_corrupted_with_both_digests() {
        let dir = TempDir::new().unwrap();
        let archive = write_valid_archive(dir.path(), "backup.tar.gz", b"good content");

        // Flip the first byte of the archive.
        let mut bad = std::fs::read(&archive).unwrap();
        bad[0] ^= 0xFF;
        std::fs::write(&archive, &bad).unwrap();

        let result = verify_one(&archive, None).unwrap();

        assert_eq!(result.status, VerifyStatus::Corrupted);
        assert!(
            result.expected_digest.is_some(),
            "expected_digest should be set"
        );
        assert!(
            result.actual_digest.is_some(),
            "actual_digest should be set"
        );
        assert_ne!(
            result.expected_digest, result.actual_digest,
            "digests should differ for corrupted archive"
        );
    }

    // ── verify_one: missing sidecar ───────────────────────────────────────────

    /// Task 9.1 — missing .sha256 sidecar returns Unverifiable.
    /// Validates: Requirement 4.4
    #[test]
    fn verify_one_missing_sidecar_returns_unverifiable() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("backup.tar.gz");
        std::fs::write(&archive, b"archive data").unwrap();
        // Deliberately no .sha256 sidecar.

        let result = verify_one(&archive, None).unwrap();

        assert_eq!(result.status, VerifyStatus::Unverifiable);
        assert!(result.expected_digest.is_none());
        assert!(result.actual_digest.is_none());
    }

    // ── verify_one: wrong passphrase (decryption failure) ────────────────────

    /// Task 9.1 — decryption failure (wrong passphrase) returns Corrupted.
    /// Validates: Requirement 4.7
    #[test]
    fn verify_one_wrong_passphrase_returns_corrupted() {
        use crate::commands::ai::recovery::crypto;
        use base64::Engine as _;

        let dir = TempDir::new().unwrap();
        let plaintext = b"sensitive backup payload";
        let correct_pass = "correct-passphrase";

        // Encrypt the payload.
        let (ciphertext, salt) = crypto::encrypt(plaintext, correct_pass).unwrap();

        // Write archive and sidecars manually.
        let archive = dir.path().join("backup.tar.gz");
        std::fs::write(&archive, &ciphertext).unwrap();

        // .sha256 sidecar is over the raw (encrypted) bytes.
        let digest = compute_sha256(&ciphertext);
        std::fs::write(sha256_sidecar_path(&archive), digest.as_bytes()).unwrap();

        // key_params.json with the salt.
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);
        let kp = serde_json::json!({ "salt": salt_b64 });
        std::fs::write(
            key_params_sidecar_path(&archive),
            serde_json::to_vec(&kp).unwrap(),
        )
        .unwrap();

        // Verify with the WRONG passphrase.
        let result = verify_one(&archive, Some("wrong-passphrase")).unwrap();

        assert_eq!(result.status, VerifyStatus::Corrupted);
        assert!(result.expected_digest.is_some());
        assert!(result.actual_digest.is_some());
    }

    // ── verify_one: correct passphrase ───────────────────────────────────────

    /// Encrypted archive with correct passphrase returns Ok.
    /// Validates: Requirements 4.1, 4.7
    #[test]
    fn verify_one_correct_passphrase_returns_ok() {
        use crate::commands::ai::recovery::crypto;
        use base64::Engine as _;

        let dir = TempDir::new().unwrap();
        let plaintext = b"sensitive backup payload";
        let passphrase = "correct-passphrase";

        let (ciphertext, salt) = crypto::encrypt(plaintext, passphrase).unwrap();

        let archive = dir.path().join("backup.tar.gz");
        std::fs::write(&archive, &ciphertext).unwrap();

        let digest = compute_sha256(&ciphertext);
        std::fs::write(sha256_sidecar_path(&archive), digest.as_bytes()).unwrap();

        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);
        let kp = serde_json::json!({ "salt": salt_b64 });
        std::fs::write(
            key_params_sidecar_path(&archive),
            serde_json::to_vec(&kp).unwrap(),
        )
        .unwrap();

        let result = verify_one(&archive, Some(passphrase)).unwrap();
        assert_eq!(result.status, VerifyStatus::Ok);
    }

    // ── verify_all ────────────────────────────────────────────────────────────

    /// verify_all returns one result per archive in the store.
    #[test]
    fn verify_all_returns_one_result_per_archive() {
        let dir = TempDir::new().unwrap();
        write_valid_archive(dir.path(), "backup-2024-01-01T00-00-01.tar.gz", b"data1");
        write_valid_archive(dir.path(), "backup-2024-01-01T00-00-02.tar.gz", b"data2");
        write_valid_archive(dir.path(), "backup-2024-01-01T00-00-03.tar.gz", b"data3");

        let results = verify_all(dir.path(), None).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.status == VerifyStatus::Ok));
    }

    /// verify_all on an empty store returns an empty vec.
    #[test]
    fn verify_all_empty_store_returns_empty_vec() {
        let dir = TempDir::new().unwrap();
        let results = verify_all(dir.path(), None).unwrap();
        assert!(results.is_empty());
    }

    /// verify_all on a non-existent store returns an empty vec (not an error).
    #[test]
    fn verify_all_nonexistent_store_returns_empty_vec() {
        let dir = TempDir::new().unwrap();
        let store = dir.path().join("does_not_exist");
        let results = verify_all(&store, None).unwrap();
        assert!(results.is_empty());
    }

    /// verify_all correctly mixes Ok and Corrupted results.
    #[test]
    fn verify_all_mixed_ok_and_corrupted() {
        let dir = TempDir::new().unwrap();

        // One good archive.
        write_valid_archive(dir.path(), "backup-a.tar.gz", b"good");

        // One corrupted archive — write a bad digest to the sidecar.
        let bad_archive = dir.path().join("backup-b.tar.gz");
        std::fs::write(&bad_archive, b"bad content").unwrap();
        std::fs::write(
            sha256_sidecar_path(&bad_archive),
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let results = verify_all(dir.path(), None).unwrap();
        assert_eq!(results.len(), 2);

        let ok_count = results
            .iter()
            .filter(|r| r.status == VerifyStatus::Ok)
            .count();
        let corrupted_count = results
            .iter()
            .filter(|r| r.status == VerifyStatus::Corrupted)
            .count();
        assert_eq!(ok_count, 1);
        assert_eq!(corrupted_count, 1);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// compute_sha256 is deterministic.
    #[test]
    fn compute_sha256_is_deterministic() {
        let d1 = compute_sha256(b"hello");
        let d2 = compute_sha256(b"hello");
        assert_eq!(d1, d2);
    }

    /// compute_sha256 differs for different inputs.
    #[test]
    fn compute_sha256_differs_for_different_inputs() {
        let d1 = compute_sha256(b"hello");
        let d2 = compute_sha256(b"world");
        assert_ne!(d1, d2);
    }

    /// list_archives ignores non-.tar.gz files.
    #[test]
    fn list_archives_ignores_non_archive_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("backup.tar.gz"), b"").unwrap();
        std::fs::write(dir.path().join("backup.tar.gz.sha256"), b"").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"").unwrap();

        let archives = list_archives(dir.path()).unwrap();
        assert_eq!(archives.len(), 1);
    }
}
