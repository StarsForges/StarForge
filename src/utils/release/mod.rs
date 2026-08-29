//! Reproducible release orchestration: building normalized per-target
//! archives, generating a versioned release manifest and SBOM, signing
//! attestations, and verifying a staged or published release offline.
//!
//! See `docs/release-provenance.md` for the full command reference,
//! threat model, and recovery guidance. Module layout:
//!
//! - [`targets`] / [`naming`] — supported targets, pinned toolchain lookup,
//!   artifact file-naming rules.
//! - [`builder`] — locates or builds the per-target binary.
//! - [`archive`] — deterministic zip archive creation.
//! - [`checksum`] — SHA-256 hashing and `SHA256SUMS` sidecar files.
//! - [`staging`] — rollback-safe publication staging.
//! - [`manifest`] / [`migrations`] — the versioned release manifest schema.
//! - [`sbom`] — CycloneDX software bill of materials.
//! - [`signing`] — Ed25519 release-key signing and verification.
//! - [`provenance`] — SLSA-shaped provenance statements.
//! - [`verify`] — offline verification of a staged/published release.

pub mod archive;
pub mod builder;
pub mod checksum;
pub mod manifest;
pub mod migrations;
pub mod naming;
pub mod provenance;
pub mod sbom;
pub mod signing;
pub mod staging;
pub mod targets;
pub mod verify;

use anyhow::{Context, Result};
use archive::{build_deterministic_archive, ArchiveEntry};
use manifest::ArtifactRecord;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use targets::binary_file_name;

/// The name given to the per-target artifact records staging writes so a
/// later `release manifest` invocation doesn't have to re-hash every
/// archive to recover them.
pub const STAGED_ARTIFACTS_FILE: &str = ".staged-artifacts.json";

/// Best-effort `git rev-parse HEAD` against `repo_root`. Returns `None`
/// (never an error) when `git` isn't installed or `repo_root` isn't a git
/// checkout — a source archive extracted without `.git` should still be
/// releasable, just without a recorded commit.
pub fn git_commit(repo_root: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    if commit.is_empty() {
        None
    } else {
        Some(commit.to_string())
    }
}

/// Reads the `[package].version` field of `Cargo.toml` at `repo_root`.
pub fn read_package_version(repo_root: &Path) -> Result<String> {
    let path = repo_root.join("Cargo.toml");
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {} as TOML", path.display()))?;
    value
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("{} is missing [package].version", path.display()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StagedArtifacts {
    version: String,
    artifacts: Vec<ArtifactRecord>,
    source_date_epoch: Option<i64>,
}

pub struct PrepareOptions<'a> {
    pub repo_root: &'a Path,
    pub app_name: &'a str,
    pub version: &'a str,
    pub targets: &'a [String],
    pub skip_build: bool,
    pub staging_root: &'a Path,
    pub source_date_epoch: Option<i64>,
    pub force: bool,
}

#[derive(Debug)]
pub struct PrepareOutcome {
    pub staged_dir: PathBuf,
    pub artifacts: Vec<ArtifactRecord>,
}

/// Builds (or locates) the binary for every requested target, packages it
/// into a deterministic archive, and stages the result. On any failure the
/// staging session is rolled back automatically ([`staging::StagingSession`]
/// removes its temp directory on drop) so a failed `prepare` never leaves a
/// directory `release manifest` could mistake for a complete release.
pub fn prepare_release(opts: &PrepareOptions<'_>) -> Result<PrepareOutcome> {
    if opts.targets.is_empty() {
        anyhow::bail!(
            "at least one target is required (use '{}' for the host build)",
            targets::NATIVE_PSEUDO_TARGET
        );
    }
    for target in opts.targets {
        if !targets::is_supported(target) {
            anyhow::bail!(
                "unsupported target '{}'. Supported: {}, {}",
                target,
                targets::NATIVE_PSEUDO_TARGET,
                targets::SUPPORTED_TARGETS.join(", ")
            );
        }
    }

    let session = staging::StagingSession::begin(opts.staging_root, opts.version)?;
    let mut artifacts = Vec::new();

    for target in opts.targets {
        let binary_path =
            builder::locate_or_build_binary(opts.repo_root, target, opts.app_name, opts.skip_build)
                .with_context(|| format!("failed to obtain binary for target '{}'", target))?;

        let archive_binary_name = binary_file_name(opts.app_name, target);
        let file_name = naming::expected_file_name(opts.app_name, opts.version, target, "zip");
        let archive_path = session.path().join(&file_name);

        let normalized = build_deterministic_archive(
            &[ArchiveEntry {
                archive_path: archive_binary_name,
                source_path: binary_path,
            }],
            &archive_path,
            opts.source_date_epoch,
        )
        .with_context(|| format!("failed to build archive for target '{}'", target))?;

        artifacts.push(ArtifactRecord {
            target: target.clone(),
            file_name,
            archive_format: "zip".to_string(),
            size_bytes: normalized.size_bytes,
            sha256: normalized.sha256,
        });
    }

    let checksum_entries: Vec<(String, String)> = artifacts
        .iter()
        .map(|a| (a.file_name.clone(), a.sha256.clone()))
        .collect();
    checksum::write_checksums_file(&checksum_entries, &session.path().join("SHA256SUMS"))?;

    let staged = StagedArtifacts {
        version: opts.version.to_string(),
        artifacts: artifacts.clone(),
        source_date_epoch: opts.source_date_epoch,
    };
    let staged_json = serde_json::to_vec_pretty(&staged)?;
    std::fs::write(session.path().join(STAGED_ARTIFACTS_FILE), staged_json)
        .context("failed to write staged artifact index")?;

    let staged_dir = session.commit(opts.force)?;

    Ok(PrepareOutcome {
        staged_dir,
        artifacts,
    })
}

/// Reads back the artifact index a prior `prepare_release` call staged, for
/// use by the `release manifest` command.
pub fn load_staged_artifacts(
    staged_dir: &Path,
) -> Result<(String, Vec<ArtifactRecord>, Option<i64>)> {
    let path = staged_dir.join(STAGED_ARTIFACTS_FILE);
    let contents = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read {} (run `starforge release prepare` first)",
            path.display()
        )
    })?;
    let staged: StagedArtifacts = serde_json::from_str(&contents)
        .with_context(|| format!("{} is malformed", path.display()))?;
    Ok((staged.version, staged.artifacts, staged.source_date_epoch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fake_repo_with_binary(app_name: &str) -> tempfile::TempDir {
        let repo = tempdir().unwrap();
        std::fs::write(
            repo.path().join("Cargo.toml"),
            format!("[package]\nname = \"{app_name}\"\nversion = \"1.2.3\"\n"),
        )
        .unwrap();
        let release_dir = repo.path().join("target").join("release");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join(app_name), b"fake compiled binary").unwrap();
        repo
    }

    #[test]
    fn read_package_version_reads_cargo_toml() {
        let repo = fake_repo_with_binary("myapp");
        assert_eq!(read_package_version(repo.path()).unwrap(), "1.2.3");
    }

    #[test]
    fn git_commit_returns_none_outside_a_git_checkout() {
        let dir = tempdir().unwrap();
        assert!(git_commit(dir.path()).is_none());
    }

    #[test]
    fn prepare_release_stages_native_target_with_skip_build() {
        let repo = fake_repo_with_binary("myapp");
        let staging_root = tempdir().unwrap();

        let outcome = prepare_release(&PrepareOptions {
            repo_root: repo.path(),
            app_name: "myapp",
            version: "1.2.3",
            targets: &[targets::NATIVE_PSEUDO_TARGET.to_string()],
            skip_build: true,
            staging_root: staging_root.path(),
            source_date_epoch: Some(1_700_000_000),
            force: false,
        })
        .unwrap();

        assert_eq!(outcome.artifacts.len(), 1);
        assert!(outcome.staged_dir.join("myapp-1.2.3-native.zip").exists());
        assert!(outcome.staged_dir.join("SHA256SUMS").exists());
        assert!(outcome.staged_dir.join(STAGED_ARTIFACTS_FILE).exists());
    }

    #[test]
    fn prepare_release_rejects_unsupported_target() {
        let repo = fake_repo_with_binary("myapp");
        let staging_root = tempdir().unwrap();

        let err = prepare_release(&PrepareOptions {
            repo_root: repo.path(),
            app_name: "myapp",
            version: "1.2.3",
            targets: &["not-a-real-target".to_string()],
            skip_build: true,
            staging_root: staging_root.path(),
            source_date_epoch: None,
            force: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported target"));
    }

    #[test]
    fn prepare_release_rolls_back_staging_when_a_target_binary_is_missing() {
        let repo = fake_repo_with_binary("myapp");
        let staging_root = tempdir().unwrap();

        let err = prepare_release(&PrepareOptions {
            repo_root: repo.path(),
            app_name: "myapp",
            // "native" exists, but the windows target's binary was never built.
            version: "1.2.3",
            targets: &[
                targets::NATIVE_PSEUDO_TARGET.to_string(),
                "x86_64-pc-windows-msvc".to_string(),
            ],
            skip_build: true,
            staging_root: staging_root.path(),
            source_date_epoch: None,
            force: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("failed to obtain binary"));

        // No partial staging directory left behind for this version.
        assert!(!staging_root.path().join("1.2.3").exists());
        let leftovers: Vec<_> = std::fs::read_dir(staging_root.path()).unwrap().collect();
        assert!(
            leftovers.is_empty(),
            "staging root should be empty after rollback"
        );
    }

    #[test]
    fn load_staged_artifacts_roundtrips_prepare_output() {
        let repo = fake_repo_with_binary("myapp");
        let staging_root = tempdir().unwrap();

        let outcome = prepare_release(&PrepareOptions {
            repo_root: repo.path(),
            app_name: "myapp",
            version: "1.2.3",
            targets: &[targets::NATIVE_PSEUDO_TARGET.to_string()],
            skip_build: true,
            staging_root: staging_root.path(),
            source_date_epoch: Some(1_700_000_000),
            force: false,
        })
        .unwrap();

        let (version, artifacts, epoch) = load_staged_artifacts(&outcome.staged_dir).unwrap();
        assert_eq!(version, "1.2.3");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(epoch, Some(1_700_000_000));
    }
}
