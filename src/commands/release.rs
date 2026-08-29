//! `starforge release` — reproducible release orchestration, SBOM
//! generation, signing, and provenance verification for StarForge's own
//! release artifacts (issue #94).
//!
//! Publishing a release remains a maintainer-controlled, manual action:
//! nothing under this command family uploads, tags, or pushes anything —
//! every subcommand only reads and writes local files.

use crate::utils::print as p;
use crate::utils::release::{
    self, checksum, manifest::ReleaseManifest, provenance, signing::ReleaseKeyPair, targets, verify,
};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ReleaseCommands {
    /// Build (or reuse) per-target binaries and stage normalized,
    /// deterministic release archives
    Prepare(PrepareArgs),
    /// Generate the versioned release manifest from a staged directory
    Manifest(ManifestArgs),
    /// Generate a CycloneDX software bill of materials
    Sbom(SbomArgs),
    /// Sign the manifest/SBOM and write a SLSA-shaped provenance statement
    Attest(AttestArgs),
    /// Verify a staged or published release directory offline
    Verify(VerifyArgs),
}

fn default_repo_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[derive(Args)]
pub struct PrepareArgs {
    /// Release version. Defaults to the `[package].version` in Cargo.toml.
    #[arg(long)]
    pub version: Option<String>,
    /// Target triples to build for (repeatable), or `native` to reuse the
    /// host's existing `target/release` build.
    #[arg(long = "target", default_values_t = vec![targets::NATIVE_PSEUDO_TARGET.to_string()])]
    pub targets: Vec<String>,
    /// Reuse an already-built binary instead of invoking `cargo build`.
    /// Required for cross targets this machine cannot compile.
    #[arg(long, default_value = "false")]
    pub skip_build: bool,
    /// Name of the compiled binary (must match Cargo.toml's `[[bin]] name`).
    #[arg(long, default_value = "starforge")]
    pub binary_name: String,
    /// Path to the project root being released. Defaults to the current
    /// directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    /// Staging root directory. Defaults to `~/.starforge/release/staging`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Unix timestamp used to normalize archive entry timestamps. Required
    /// for the release to be recorded as reproducible; omitting it still
    /// produces a valid archive, just not one flagged reproducible.
    #[arg(long)]
    pub source_date_epoch: Option<i64>,
    /// Overwrite an existing staged release for this version.
    #[arg(long, default_value = "false")]
    pub force: bool,
}

#[derive(Args)]
pub struct ManifestArgs {
    /// Release version whose staged artifacts should be described.
    /// Defaults to the `[package].version` in Cargo.toml.
    #[arg(long)]
    pub version: Option<String>,
    /// Path to the project root being released. Defaults to the current
    /// directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    /// Staging root directory that `prepare` wrote to. Defaults to
    /// `~/.starforge/release/staging`.
    #[arg(long)]
    pub staging_root: Option<PathBuf>,
    /// Name recorded in the manifest. Must match the name `prepare` used.
    #[arg(long, default_value = "starforge")]
    pub name: String,
}

#[derive(Args)]
pub struct SbomArgs {
    /// Path to the project root to inventory. Defaults to the current
    /// directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    /// Application name (excluded from the dependency component list, and
    /// used as the SBOM's root component).
    #[arg(long, default_value = "starforge")]
    pub name: String,
    /// Application version. Defaults to `[package].version` in Cargo.toml.
    #[arg(long)]
    pub version: Option<String>,
    /// Output path for the generated SBOM JSON.
    #[arg(long)]
    pub out: PathBuf,
    /// Bundled-asset directories (relative to repo-root) to include as
    /// aggregate file components, e.g. `--include-assets templates`.
    #[arg(long = "include-assets")]
    pub include_assets: Vec<String>,
}

#[derive(Args)]
pub struct AttestArgs {
    /// Directory containing release-manifest.json and sbom.json (typically
    /// the staged release directory from `prepare`/`manifest`).
    #[arg(long)]
    pub dir: PathBuf,
    /// Path to the Ed25519 signing key (base64 seed). Falls back to the
    /// STARFORGE_RELEASE_SIGNING_KEY environment variable.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
    /// Generate a new signing key at --signing-key if one doesn't exist yet.
    /// Only use this for a maintainer's first release — back the resulting
    /// key file up somewhere durable and out of version control.
    #[arg(long, default_value = "false")]
    pub generate_key_if_missing: bool,
    /// Builder identity recorded in the provenance statement.
    #[arg(long, default_value = "starforge-cli")]
    pub builder_id: String,
    /// Git commit to record as provenance material. Auto-detected from
    /// --repo-root via `git rev-parse HEAD` when omitted.
    #[arg(long)]
    pub source_commit: Option<String>,
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Directory containing the manifest, SBOM, provenance statement, and
    /// signatures to verify.
    #[arg(long)]
    pub dir: PathBuf,
    /// Base64 Ed25519 public key. Defaults to release.pub inside --dir.
    #[arg(long)]
    pub pubkey: Option<String>,
    /// Cross-check the SBOM's dependency list against this Cargo.lock.
    #[arg(long)]
    pub check_lock: Option<PathBuf>,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
}

pub fn handle(cmd: ReleaseCommands) -> Result<()> {
    match cmd {
        ReleaseCommands::Prepare(args) => handle_prepare(args),
        ReleaseCommands::Manifest(args) => handle_manifest(args),
        ReleaseCommands::Sbom(args) => handle_sbom(args),
        ReleaseCommands::Attest(args) => handle_attest(args),
        ReleaseCommands::Verify(args) => handle_verify(args),
    }
}

fn resolve_version(repo_root: &std::path::Path, version: Option<String>) -> Result<String> {
    match version {
        Some(v) => Ok(v),
        None => release::read_package_version(repo_root),
    }
}

fn handle_prepare(args: PrepareArgs) -> Result<()> {
    let repo_root = args.repo_root.unwrap_or_else(default_repo_root);
    let version = resolve_version(&repo_root, args.version)?;
    let staging_root = match args.out {
        Some(dir) => dir,
        None => release::staging::default_staging_root()?,
    };

    p::header(&format!(
        "Preparing release {} {}",
        args.binary_name, version
    ));
    for target in &args.targets {
        p::info(&format!("target: {}", target));
    }

    let outcome = release::prepare_release(&release::PrepareOptions {
        repo_root: &repo_root,
        app_name: &args.binary_name,
        version: &version,
        targets: &args.targets,
        skip_build: args.skip_build,
        staging_root: &staging_root,
        source_date_epoch: args.source_date_epoch,
        force: args.force,
    })?;

    for artifact in &outcome.artifacts {
        p::success(&format!(
            "{} ({} bytes, sha256 {})",
            artifact.file_name,
            artifact.size_bytes,
            &artifact.sha256[..12]
        ));
    }
    p::kv("Staged at", &outcome.staged_dir.display().to_string());
    if args.source_date_epoch.is_none() {
        p::warn("No --source-date-epoch given: this release will not be marked reproducible.");
    }
    Ok(())
}

fn handle_manifest(args: ManifestArgs) -> Result<()> {
    let repo_root = args.repo_root.unwrap_or_else(default_repo_root);
    let version = resolve_version(&repo_root, args.version)?;
    let staging_root = match args.staging_root {
        Some(dir) => dir,
        None => release::staging::default_staging_root()?,
    };
    let staged_dir = staging_root.join(&version);

    let (staged_version, artifacts, source_date_epoch) =
        release::load_staged_artifacts(&staged_dir)?;
    if staged_version != version {
        anyhow::bail!(
            "staged artifact index at {} was built for version '{}', not '{}'",
            staged_dir.display(),
            staged_version,
            version
        );
    }

    let toolchain = targets::read_pinned_toolchain(&repo_root)?;
    let git_commit = release::git_commit(&repo_root);
    let generated_at = chrono::Utc::now().to_rfc3339();

    let manifest = ReleaseManifest::new(
        args.name,
        version,
        git_commit,
        toolchain,
        generated_at,
        source_date_epoch,
        artifacts,
    );

    let manifest_path = staged_dir.join(release::manifest::MANIFEST_FILE_NAME);
    manifest.save(&manifest_path)?;

    p::success(&format!("Wrote {}", manifest_path.display()));
    p::kv("Artifacts", &manifest.artifacts.len().to_string());
    p::kv(
        "Reproducible",
        if manifest.source_date_epoch.is_some() {
            "yes"
        } else {
            "no"
        },
    );
    Ok(())
}

fn handle_sbom(args: SbomArgs) -> Result<()> {
    let repo_root = args.repo_root.unwrap_or_else(default_repo_root);
    let version = resolve_version(&repo_root, args.version)?;
    let timestamp = chrono::Utc::now().to_rfc3339();
    let asset_dirs: Vec<&str> = args.include_assets.iter().map(|s| s.as_str()).collect();

    let sbom =
        release::sbom::generate_sbom(&repo_root, &args.name, &version, &timestamp, &asset_dirs)?;
    let bytes = serde_json::to_vec_pretty(&sbom)?;
    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&args.out, &bytes)
        .with_context(|| format!("failed to write {}", args.out.display()))?;

    p::success(&format!("Wrote {}", args.out.display()));
    p::kv("Components", &sbom.components.len().to_string());
    Ok(())
}

fn handle_attest(args: AttestArgs) -> Result<()> {
    let repo_root = args.repo_root.unwrap_or_else(default_repo_root);
    let manifest_path = args.dir.join(release::manifest::MANIFEST_FILE_NAME);
    let sbom_path = args.dir.join(verify::SBOM_FILE);

    let manifest = ReleaseManifest::load(&manifest_path).with_context(|| {
        format!(
            "run `starforge release manifest` before attest ({})",
            manifest_path.display()
        )
    })?;

    let key = match ReleaseKeyPair::load(args.signing_key.as_deref()) {
        Ok(k) => k,
        Err(e) => {
            if args.generate_key_if_missing {
                let path = args.signing_key.clone().ok_or_else(|| {
                    anyhow::anyhow!("--generate-key-if-missing requires --signing-key <path>")
                })?;
                let generated = ReleaseKeyPair::generate();
                generated.save(&path)?;
                p::warn(&format!(
                    "Generated a new release signing key at {}. Back this file up securely — losing it means future releases can't be verified against past ones.",
                    path.display()
                ));
                generated
            } else {
                return Err(e);
            }
        }
    };

    let source_commit = args
        .source_commit
        .or_else(|| release::git_commit(&repo_root));
    let build_time = chrono::Utc::now().to_rfc3339();

    let sbom_sha256 = if sbom_path.exists() {
        Some(checksum::sha256_file(&sbom_path)?)
    } else {
        p::warn("No sbom.json found in --dir; provenance will not cover the SBOM. Run `starforge release sbom` first for full coverage.");
        None
    };

    let statement = provenance::build_provenance(provenance::BuildProvenanceArgs {
        manifest: &manifest,
        sbom_sha256: sbom_sha256.as_deref(),
        source_commit: source_commit.as_deref(),
        builder_id: &args.builder_id,
        build_started_on: &build_time,
        build_finished_on: &build_time,
    });

    let provenance_path = args.dir.join(verify::PROVENANCE_FILE);
    let provenance_bytes = serde_json::to_vec_pretty(&statement)?;
    std::fs::write(&provenance_path, &provenance_bytes)
        .with_context(|| format!("failed to write {}", provenance_path.display()))?;

    let manifest_bytes = std::fs::read(&manifest_path)?;
    std::fs::write(
        args.dir.join(verify::MANIFEST_SIG_FILE),
        key.sign(&manifest_bytes),
    )?;
    if sbom_path.exists() {
        let sbom_bytes = std::fs::read(&sbom_path)?;
        std::fs::write(args.dir.join(verify::SBOM_SIG_FILE), key.sign(&sbom_bytes))?;
    }
    std::fs::write(
        args.dir.join(verify::PROVENANCE_SIG_FILE),
        key.sign(&provenance_bytes),
    )?;
    std::fs::write(
        args.dir.join(verify::PUBLIC_KEY_FILE),
        key.public_key_base64(),
    )?;

    p::success(&format!("Wrote {}", provenance_path.display()));
    p::kv("Builder", &args.builder_id);
    p::kv("Subjects", &statement.subject.len().to_string());
    p::kv("Public key", &key.public_key_base64());
    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    let report = verify::verify_release(&verify::VerifyOptions {
        dir: &args.dir,
        pubkey_b64: args.pubkey.as_deref(),
        check_lock: args.check_lock.as_deref(),
    })?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        p::header(&format!("Release verification: {}", args.dir.display()));
        for check in &report.checks {
            if check.passed {
                println!(
                    "  {} {:<40} {}",
                    "✓".green().bold(),
                    check.name,
                    check.detail.dimmed()
                );
            } else {
                println!(
                    "  {} {:<40} {}",
                    "✗".red().bold(),
                    check.name,
                    check.detail.red()
                );
            }
        }
        println!();
        if report.ok {
            p::success("All checks passed.");
        } else {
            p::error("One or more checks failed.");
        }
    }

    if !report.ok {
        std::process::exit(1);
    }
    Ok(())
}
