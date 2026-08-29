//! Local, offline verification of a staged/published release directory.
//!
//! `verify_release` never makes a network call — every check reads only
//! from `dir` (and, optionally, a local `Cargo.lock` for the
//! dependency-completeness check). Every check runs and is recorded even
//! after an earlier one fails, so a single invocation reports the full
//! picture instead of stopping at the first problem.

use super::checksum::sha256_file;
use super::manifest::ReleaseManifest;
use super::naming;
use super::provenance::ProvenanceStatement;
use super::sbom::{self, Sbom};
use super::signing;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

pub const MANIFEST_SIG_FILE: &str = "release-manifest.json.sig";
pub const SBOM_FILE: &str = "sbom.json";
pub const SBOM_SIG_FILE: &str = "sbom.json.sig";
pub const PROVENANCE_FILE: &str = "provenance.json";
pub const PROVENANCE_SIG_FILE: &str = "provenance.json.sig";
pub const PUBLIC_KEY_FILE: &str = "release.pub";

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub ok: bool,
    pub checks: Vec<CheckResult>,
}

impl VerificationReport {
    fn new() -> Self {
        Self {
            ok: true,
            checks: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, result: Result<String>) {
        match result {
            Ok(detail) => self.checks.push(CheckResult {
                name: name.to_string(),
                passed: true,
                detail,
            }),
            Err(e) => {
                self.ok = false;
                self.checks.push(CheckResult {
                    name: name.to_string(),
                    passed: false,
                    // `{:#}` renders the full anyhow context chain (e.g.
                    // "failed to migrate ...: no migration path ..."), not
                    // just the outermost wrapper — the underlying reason is
                    // exactly what a maintainer needs to see here.
                    detail: format!("{:#}", e),
                });
            }
        }
    }
}

pub struct VerifyOptions<'a> {
    pub dir: &'a Path,
    /// Base64 Ed25519 public key. When `None`, `release.pub` inside `dir`
    /// is used, matching how `release attest` writes it.
    pub pubkey_b64: Option<&'a str>,
    /// Optional path to a `Cargo.lock` to cross-check the SBOM's dependency
    /// list against. Skipped when `None` — verification of a distributed
    /// tarball doesn't require the source tree to be present.
    pub check_lock: Option<&'a Path>,
}

fn read_public_key(opts: &VerifyOptions<'_>) -> Result<String> {
    if let Some(key) = opts.pubkey_b64 {
        return Ok(key.to_string());
    }
    let path = opts.dir.join(PUBLIC_KEY_FILE);
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .with_context(|| format!("no --pubkey given and {} not found", path.display()))
}

fn read_sig(dir: &Path, file_name: &str) -> Result<String> {
    std::fs::read_to_string(dir.join(file_name))
        .map(|s| s.trim().to_string())
        .with_context(|| format!("failed to read signature file {}", file_name))
}

/// Runs every verification check against `dir` and returns a full report.
/// Returns `Err` only for a setup problem outside the checks themselves
/// (currently unreachable, kept `Result` for forward compatibility with
/// checks that need to short-circuit before any per-item check can run).
pub fn verify_release(opts: &VerifyOptions<'_>) -> Result<VerificationReport> {
    let mut report = VerificationReport::new();

    let manifest_path = opts.dir.join(super::manifest::MANIFEST_FILE_NAME);
    let manifest = match ReleaseManifest::load(&manifest_path) {
        Ok(m) => {
            report.record(
                "manifest-schema",
                Ok(format!("schema_version {}", m.schema_version)),
            );
            Some(m)
        }
        Err(e) => {
            report.record("manifest-schema", Err(e));
            None
        }
    };

    if let Some(manifest) = &manifest {
        report.record(
            "manifest-internal-consistency",
            manifest.validate().map(|_| {
                format!(
                    "{} artifact(s) internally consistent",
                    manifest.artifacts.len()
                )
            }),
        );
    }

    let pubkey = match read_public_key(opts) {
        Ok(k) => {
            report.record("public-key-present", Ok("resolved".to_string()));
            Some(k)
        }
        Err(e) => {
            report.record("public-key-present", Err(e));
            None
        }
    };

    if let (Some(manifest), Some(pubkey)) = (&manifest, &pubkey) {
        let manifest_bytes = std::fs::read(&manifest_path).ok();
        let sig_check = (|| -> Result<String> {
            let bytes = manifest_bytes.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "could not re-read {} for signature check",
                    manifest_path.display()
                )
            })?;
            let sig = read_sig(opts.dir, MANIFEST_SIG_FILE)?;
            signing::verify(pubkey, bytes, &sig)?;
            Ok("signature valid".to_string())
        })();
        report.record("manifest-signature", sig_check);

        // Per-artifact checksum + naming checks. Each artifact is its own
        // check so a report can point at exactly which target failed.
        for artifact in &manifest.artifacts {
            let check_name = format!("artifact[{}]-checksum", artifact.target);
            let result = (|| -> Result<String> {
                let path = opts.dir.join(&artifact.file_name);
                if !path.exists() {
                    anyhow::bail!(
                        "artifact file {} is missing from {}",
                        artifact.file_name,
                        opts.dir.display()
                    );
                }
                let actual = sha256_file(&path)?;
                if actual != artifact.sha256 {
                    anyhow::bail!(
                        "checksum mismatch for {}: manifest says {}, file hashes to {} (artifact may be tampered)",
                        artifact.file_name,
                        artifact.sha256,
                        actual
                    );
                }
                Ok(format!("sha256 {} matches manifest", &actual[..12]))
            })();
            report.record(&check_name, result);

            let naming_check =
                naming::validate_file_name(&artifact.file_name, &manifest.name, &manifest.version)
                    .map(|_| "file name matches naming convention".to_string());
            report.record(
                &format!("artifact[{}]-naming", artifact.target),
                naming_check,
            );
        }
    }

    let sbom_path = opts.dir.join(SBOM_FILE);
    let sbom: Option<Sbom> = match std::fs::read_to_string(&sbom_path) {
        Ok(contents) => match serde_json::from_str::<Sbom>(&contents) {
            Ok(s) => {
                report.record(
                    "sbom-parses",
                    Ok(format!("{} component(s)", s.components.len())),
                );
                Some(s)
            }
            Err(e) => {
                report.record("sbom-parses", Err(anyhow::anyhow!("{}", e)));
                None
            }
        },
        Err(e) => {
            report.record("sbom-parses", Err(anyhow::anyhow!("{}", e)));
            None
        }
    };

    if let (Some(_sbom), Some(pubkey)) = (&sbom, &pubkey) {
        let sig_check = (|| -> Result<String> {
            let bytes = std::fs::read(&sbom_path)?;
            let sig = read_sig(opts.dir, SBOM_SIG_FILE)?;
            signing::verify(pubkey, &bytes, &sig)?;
            Ok("signature valid".to_string())
        })();
        report.record("sbom-signature", sig_check);
    }

    if let (Some(sbom), Some(lock_path)) = (&sbom, opts.check_lock) {
        let app_name = manifest
            .as_ref()
            .map(|m| m.name.clone())
            .unwrap_or_default();
        let result =
            sbom::find_missing_dependencies(sbom, lock_path, &app_name).and_then(|missing| {
                if missing.is_empty() {
                    Ok("all Cargo.lock dependencies are represented".to_string())
                } else {
                    Err(anyhow::anyhow!("missing: {}", missing.join(", ")))
                }
            });
        report.record("sbom-dependency-completeness", result);
    }

    let provenance_path = opts.dir.join(PROVENANCE_FILE);
    let provenance: Option<ProvenanceStatement> = match std::fs::read_to_string(&provenance_path) {
        Ok(contents) => match serde_json::from_str::<ProvenanceStatement>(&contents) {
            Ok(p) => {
                report.record(
                    "provenance-parses",
                    Ok(format!("{} subject(s)", p.subject.len())),
                );
                Some(p)
            }
            Err(e) => {
                report.record("provenance-parses", Err(anyhow::anyhow!("{}", e)));
                None
            }
        },
        Err(e) => {
            report.record("provenance-parses", Err(anyhow::anyhow!("{}", e)));
            None
        }
    };

    if let Some(pubkey) = &pubkey {
        if provenance.is_some() {
            let sig_check = (|| -> Result<String> {
                let bytes = std::fs::read(&provenance_path)?;
                let sig = read_sig(opts.dir, PROVENANCE_SIG_FILE)?;
                signing::verify(pubkey, &bytes, &sig)?;
                Ok("signature valid".to_string())
            })();
            report.record("provenance-signature", sig_check);
        }
    }

    if let (Some(manifest), Some(provenance)) = (&manifest, &provenance) {
        let result = (|| -> Result<String> {
            for artifact in &manifest.artifacts {
                let matched = provenance.subject.iter().any(|s| {
                    s.name == artifact.file_name && s.digest.get("sha256") == Some(&artifact.sha256)
                });
                if !matched {
                    anyhow::bail!(
                        "provenance statement has no subject matching manifest artifact {} ({})",
                        artifact.file_name,
                        artifact.sha256
                    );
                }
            }
            Ok("every manifest artifact has a matching provenance subject".to_string())
        })();
        report.record("provenance-subjects-match-manifest", result);
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::release::archive::{build_deterministic_archive, ArchiveEntry};
    use crate::utils::release::manifest::{ArtifactRecord, ReleaseManifest};
    use crate::utils::release::provenance::{build_provenance, BuildProvenanceArgs};
    use crate::utils::release::sbom::generate_sbom;
    use crate::utils::release::signing::ReleaseKeyPair;
    use tempfile::tempdir;

    struct SignedRelease {
        dir: tempfile::TempDir,
        pubkey: String,
    }

    fn build_signed_release() -> SignedRelease {
        let repo = tempdir().unwrap();
        std::fs::write(
            repo.path().join("Cargo.toml"),
            "[package]\nname = \"starforge\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            repo.path().join("Cargo.lock"),
            "[[package]]\nname = \"starforge\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"dep-one\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let out = tempdir().unwrap();
        let bin_path = repo.path().join("starforge-bin");
        std::fs::write(&bin_path, b"pretend binary").unwrap();
        let archive = build_deterministic_archive(
            &[ArchiveEntry {
                archive_path: "starforge".to_string(),
                source_path: bin_path,
            }],
            &out.path()
                .join("starforge-1.0.0-x86_64-unknown-linux-gnu.zip"),
            Some(1_700_000_000),
        )
        .unwrap();

        let manifest = ReleaseManifest::new(
            "starforge".to_string(),
            "1.0.0".to_string(),
            Some("commit123".to_string()),
            "1.89.0".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            Some(1_700_000_000),
            vec![ArtifactRecord {
                target: "x86_64-unknown-linux-gnu".to_string(),
                file_name: "starforge-1.0.0-x86_64-unknown-linux-gnu.zip".to_string(),
                archive_format: "zip".to_string(),
                size_bytes: archive.size_bytes,
                sha256: archive.sha256.clone(),
            }],
        );
        let manifest_path = out.path().join(super::super::manifest::MANIFEST_FILE_NAME);
        manifest.save(&manifest_path).unwrap();

        let sbom = generate_sbom(
            repo.path(),
            "starforge",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
        let sbom_path = out.path().join(SBOM_FILE);
        let sbom_bytes = serde_json::to_vec_pretty(&sbom).unwrap();
        std::fs::write(&sbom_path, &sbom_bytes).unwrap();

        let key = ReleaseKeyPair::generate();
        let pubkey = key.public_key_base64();

        let provenance = build_provenance(BuildProvenanceArgs {
            manifest: &manifest,
            sbom_sha256: Some(&sha256_file(&sbom_path).unwrap()),
            source_commit: manifest.git_commit.as_deref(),
            builder_id: "starforge-cli/1.0.0",
            build_started_on: "2026-01-01T00:00:00Z",
            build_finished_on: "2026-01-01T00:05:00Z",
        });
        let provenance_path = out.path().join(PROVENANCE_FILE);
        let provenance_bytes = serde_json::to_vec_pretty(&provenance).unwrap();
        std::fs::write(&provenance_path, &provenance_bytes).unwrap();

        std::fs::write(
            out.path().join(MANIFEST_SIG_FILE),
            key.sign(&std::fs::read(&manifest_path).unwrap()),
        )
        .unwrap();
        std::fs::write(out.path().join(SBOM_SIG_FILE), key.sign(&sbom_bytes)).unwrap();
        std::fs::write(
            out.path().join(PROVENANCE_SIG_FILE),
            key.sign(&provenance_bytes),
        )
        .unwrap();
        std::fs::write(out.path().join(PUBLIC_KEY_FILE), &pubkey).unwrap();

        SignedRelease { dir: out, pubkey }
    }

    #[test]
    fn verify_release_passes_every_check_on_a_well_formed_release() {
        let release = build_signed_release();
        let report = verify_release(&VerifyOptions {
            dir: release.dir.path(),
            pubkey_b64: None,
            check_lock: None,
        })
        .unwrap();

        assert!(
            report.ok,
            "expected all checks to pass: {:#?}",
            report.checks
        );
        assert!(report.checks.len() >= 8);
    }

    #[test]
    fn verify_release_detects_tampered_artifact() {
        let release = build_signed_release();
        let artifact_path = release
            .dir
            .path()
            .join("starforge-1.0.0-x86_64-unknown-linux-gnu.zip");
        let mut bytes = std::fs::read(&artifact_path).unwrap();
        bytes[0] ^= 0xFF;
        std::fs::write(&artifact_path, bytes).unwrap();

        let report = verify_release(&VerifyOptions {
            dir: release.dir.path(),
            pubkey_b64: None,
            check_lock: None,
        })
        .unwrap();

        assert!(!report.ok);
        let checksum_check = report
            .checks
            .iter()
            .find(|c| c.name.contains("checksum"))
            .unwrap();
        assert!(!checksum_check.passed);
        assert!(checksum_check.detail.contains("mismatch"));
    }

    #[test]
    fn verify_release_detects_signature_failure_with_wrong_key() {
        let release = build_signed_release();
        let wrong_key = ReleaseKeyPair::generate();

        let report = verify_release(&VerifyOptions {
            dir: release.dir.path(),
            pubkey_b64: Some(&wrong_key.public_key_base64()),
            check_lock: None,
        })
        .unwrap();

        assert!(!report.ok);
        let sig_check = report
            .checks
            .iter()
            .find(|c| c.name == "manifest-signature")
            .unwrap();
        assert!(!sig_check.passed);
    }

    #[test]
    fn verify_release_reports_missing_manifest_clearly() {
        let dir = tempdir().unwrap();
        let report = verify_release(&VerifyOptions {
            dir: dir.path(),
            pubkey_b64: None,
            check_lock: None,
        })
        .unwrap();

        assert!(!report.ok);
        let manifest_check = report
            .checks
            .iter()
            .find(|c| c.name == "manifest-schema")
            .unwrap();
        assert!(!manifest_check.passed);
    }

    #[test]
    fn verify_release_detects_version_drift() {
        let release = build_signed_release();
        let manifest_path = release
            .dir
            .path()
            .join(super::super::manifest::MANIFEST_FILE_NAME);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(999);
        std::fs::write(&manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        let report = verify_release(&VerifyOptions {
            dir: release.dir.path(),
            pubkey_b64: Some(&release.pubkey),
            check_lock: None,
        })
        .unwrap();

        assert!(!report.ok);
        let manifest_check = report
            .checks
            .iter()
            .find(|c| c.name == "manifest-schema")
            .unwrap();
        assert!(!manifest_check.passed);
        assert!(manifest_check.detail.contains("newer than"));
    }

    #[test]
    fn verify_release_check_lock_detects_missing_dependency_in_sbom() {
        let release = build_signed_release();
        // Rewrite the SBOM to drop `dep-one`, simulating a stale SBOM that
        // wasn't regenerated after Cargo.lock changed.
        let sbom_path = release.dir.path().join(SBOM_FILE);
        let mut sbom: Sbom =
            serde_json::from_str(&std::fs::read_to_string(&sbom_path).unwrap()).unwrap();
        sbom.components.clear();
        let sbom_bytes = serde_json::to_vec_pretty(&sbom).unwrap();
        std::fs::write(&sbom_path, &sbom_bytes).unwrap();

        let lock_path = release.dir.path().join("Cargo.lock");
        std::fs::write(
            &lock_path,
            "[[package]]\nname = \"starforge\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"dep-one\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let report = verify_release(&VerifyOptions {
            dir: release.dir.path(),
            pubkey_b64: Some(&release.pubkey),
            check_lock: Some(&lock_path),
        })
        .unwrap();

        let dep_check = report
            .checks
            .iter()
            .find(|c| c.name == "sbom-dependency-completeness")
            .unwrap();
        assert!(!dep_check.passed);
        assert!(dep_check.detail.contains("dep-one"));
    }
}
