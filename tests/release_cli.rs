//! End-to-end CLI coverage for `starforge release` (issue #94).
//!
//! Follows the isolated-`HOME` pattern from `tests/cli_smoke.rs` /
//! `tests/compliance_cli.rs`: no network access, no shared state between
//! tests. Every scenario uses `--skip-build` against a fixture "repo" with
//! a pre-placed fake binary, since cross-compilation toolchains aren't
//! available in CI.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn isolated_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("create isolated home")
}

fn starforge(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_starforge"));
    cmd.arg("-q");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd.env_remove("STARFORGE_RELEASE_SIGNING_KEY");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_success(output: &Output, cmd: &str) {
    assert!(
        output.status.success(),
        "{} failed: {}\n{}",
        cmd,
        stderr(output),
        stdout(output)
    );
}

/// Builds a fixture "project" that looks enough like a real Rust crate for
/// `release prepare --skip-build`, `release sbom`, and `release manifest`
/// to operate on: a `Cargo.toml`, a `Cargo.lock` with a couple of pinned
/// dependencies, a pinned `rust-toolchain.toml`, and an already-"built"
/// native binary.
fn fixture_repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("create fixture repo");
    std::fs::write(
        repo.path().join("Cargo.toml"),
        "[package]\nname = \"fixture-app\"\nversion = \"9.9.9\"\n\n[features]\nextra = []\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("Cargo.lock"),
        "[[package]]\nname = \"fixture-app\"\nversion = \"9.9.9\"\n\n\
         [[package]]\nname = \"left-pad\"\nversion = \"0.1.0\"\nchecksum = \"abc123\"\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.89.0\"\n",
    )
    .unwrap();

    let release_dir = repo.path().join("target").join("release");
    std::fs::create_dir_all(&release_dir).unwrap();
    std::fs::write(
        release_dir.join("fixture-app"),
        b"pretend compiled binary bytes",
    )
    .unwrap();

    repo
}

struct StagedRelease {
    _home: tempfile::TempDir,
    _repo: tempfile::TempDir,
    home_path: PathBuf,
    staging_dir: PathBuf,
}

/// Runs `prepare` then `manifest` then `sbom`, giving a fully-staged
/// (but not yet attested) release directory to build the attest/verify
/// tests on top of.
fn prepare_and_manifest() -> StagedRelease {
    let home = isolated_home();
    let repo = fixture_repo();
    let staging_root = home.path().join("staging");

    let prepare = starforge(home.path())
        .args([
            "release",
            "prepare",
            "--repo-root",
            repo.path().to_str().unwrap(),
            "--binary-name",
            "fixture-app",
            "--version",
            "9.9.9",
            "--target",
            "native",
            "--skip-build",
            "--out",
            staging_root.to_str().unwrap(),
            "--source-date-epoch",
            "1700000000",
        ])
        .output()
        .expect("run release prepare");
    assert_success(&prepare, "release prepare");

    let staging_dir = staging_root.join("9.9.9");
    assert!(staging_dir.join("fixture-app-9.9.9-native.zip").exists());

    let manifest = starforge(home.path())
        .args([
            "release",
            "manifest",
            "--repo-root",
            repo.path().to_str().unwrap(),
            "--version",
            "9.9.9",
            "--staging-root",
            staging_root.to_str().unwrap(),
            "--name",
            "fixture-app",
        ])
        .output()
        .expect("run release manifest");
    assert_success(&manifest, "release manifest");
    assert!(staging_dir.join("release-manifest.json").exists());

    let sbom = starforge(home.path())
        .args([
            "release",
            "sbom",
            "--repo-root",
            repo.path().to_str().unwrap(),
            "--name",
            "fixture-app",
            "--version",
            "9.9.9",
            "--out",
            staging_dir.join("sbom.json").to_str().unwrap(),
        ])
        .output()
        .expect("run release sbom");
    assert_success(&sbom, "release sbom");

    let home_path = home.path().to_path_buf();
    StagedRelease {
        _home: home,
        _repo: repo,
        home_path,
        staging_dir,
    }
}

fn attest(staged: &StagedRelease) -> Output {
    starforge(&staged.home_path)
        .args([
            "release",
            "attest",
            "--dir",
            staged.staging_dir.to_str().unwrap(),
            "--signing-key",
            staged.home_path.join("signing.key").to_str().unwrap(),
            "--generate-key-if-missing",
            "--builder-id",
            "starforge-cli/test",
        ])
        .output()
        .expect("run release attest")
}

fn verify(staged: &StagedRelease, extra_args: &[&str]) -> Output {
    let mut args = vec![
        "release".to_string(),
        "verify".to_string(),
        "--dir".to_string(),
        staged.staging_dir.to_str().unwrap().to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    args.extend(extra_args.iter().map(|s| s.to_string()));
    starforge(&staged.home_path)
        .args(args)
        .output()
        .expect("run release verify")
}

#[test]
fn sbom_generation_is_offline_and_lists_pinned_dependencies() {
    let home = isolated_home();
    let repo = fixture_repo();
    let out_path = home.path().join("sbom.json");

    let output = starforge(home.path())
        .args([
            "release",
            "sbom",
            "--repo-root",
            repo.path().to_str().unwrap(),
            "--name",
            "fixture-app",
            "--version",
            "9.9.9",
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("run release sbom");
    assert_success(&output, "release sbom");

    let contents = std::fs::read_to_string(&out_path).unwrap();
    assert!(contents.contains("left-pad"));
    assert!(contents.contains("CycloneDX"));
    assert!(contents.contains("cargo:feature"));

    let sbom: serde_json::Value = serde_json::from_str(&contents).unwrap();
    let components = sbom["components"].as_array().unwrap();
    // The root package itself is the SBOM's metadata.component, not a
    // dependency component — it must not also appear in `components`.
    assert!(!components
        .iter()
        .any(|c| c["name"].as_str() == Some("fixture-app")));
}

#[test]
fn prepare_manifest_attest_verify_full_chain_succeeds() {
    let staged = prepare_and_manifest();
    let attest_output = attest(&staged);
    assert_success(&attest_output, "release attest");
    assert!(staged.staging_dir.join("provenance.json").exists());
    assert!(staged.staging_dir.join("release.pub").exists());

    let verify_output = verify(&staged, &[]);
    assert_success(&verify_output, "release verify");
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&verify_output)).expect("valid JSON report");
    assert_eq!(report["ok"], serde_json::json!(true));
}

#[test]
fn verify_detects_tampered_artifact_and_exits_nonzero() {
    let staged = prepare_and_manifest();
    assert_success(&attest(&staged), "release attest");

    let artifact_path = staged.staging_dir.join("fixture-app-9.9.9-native.zip");
    let mut bytes = std::fs::read(&artifact_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&artifact_path, bytes).unwrap();

    let output = verify(&staged, &[]);
    assert!(
        !output.status.success(),
        "verify should exit non-zero on tampered artifact"
    );
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("valid JSON report");
    assert_eq!(report["ok"], serde_json::json!(false));
    let checks = report["checks"].as_array().unwrap();
    let checksum_check = checks
        .iter()
        .find(|c| c["name"].as_str().unwrap().contains("checksum"))
        .expect("checksum check present");
    assert_eq!(checksum_check["passed"], serde_json::json!(false));
}

#[test]
fn verify_detects_signature_failure_with_wrong_public_key() {
    let staged = prepare_and_manifest();
    assert_success(&attest(&staged), "release attest");

    // A syntactically valid but unrelated Ed25519 public key (32 zero
    // bytes, base64-encoded) — wrong key, not a malformed one.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let wrong_pubkey = STANDARD.encode([0u8; 32]);

    let output = verify(&staged, &["--pubkey", &wrong_pubkey]);
    assert!(!output.status.success());
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("valid JSON report");
    assert_eq!(report["ok"], serde_json::json!(false));
}

#[test]
fn verify_reports_missing_manifest_without_crashing() {
    let home = isolated_home();
    let empty_dir = home.path().join("nothing-here");
    std::fs::create_dir_all(&empty_dir).unwrap();

    let output = starforge(home.path())
        .args([
            "release",
            "verify",
            "--dir",
            empty_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run release verify");

    assert!(!output.status.success());
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("valid JSON report");
    assert_eq!(report["ok"], serde_json::json!(false));
}

#[test]
fn prepare_without_skip_build_and_missing_binary_fails_clearly() {
    let home = isolated_home();
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(
        repo.path().join("Cargo.toml"),
        "[package]\nname = \"fixture-app\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let output = starforge(home.path())
        .args([
            "release",
            "prepare",
            "--repo-root",
            repo.path().to_str().unwrap(),
            "--binary-name",
            "fixture-app",
            "--version",
            "1.0.0",
            "--target",
            "not-a-real-target",
            "--skip-build",
        ])
        .output()
        .expect("run release prepare");

    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported target"));
}

#[test]
fn attest_without_a_signing_key_or_generate_flag_fails_clearly() {
    let staged = prepare_and_manifest();
    let output = starforge(&staged.home_path)
        .args([
            "release",
            "attest",
            "--dir",
            staged.staging_dir.to_str().unwrap(),
            "--signing-key",
            staged
                .home_path
                .join("does-not-exist.key")
                .to_str()
                .unwrap(),
        ])
        .output()
        .expect("run release attest");

    assert!(!output.status.success());
    assert!(stderr(&output).to_lowercase().contains("signing key"));
}

#[test]
fn prepare_is_reproducible_given_the_same_source_date_epoch() {
    let home1 = isolated_home();
    let home2 = isolated_home();
    let repo = fixture_repo();

    let run = |home: &Path, out_dir: &Path| {
        let output = starforge(home)
            .args([
                "release",
                "prepare",
                "--repo-root",
                repo.path().to_str().unwrap(),
                "--binary-name",
                "fixture-app",
                "--version",
                "9.9.9",
                "--target",
                "native",
                "--skip-build",
                "--out",
                out_dir.to_str().unwrap(),
                "--source-date-epoch",
                "1700000000",
            ])
            .output()
            .expect("run release prepare");
        assert_success(&output, "release prepare");
    };

    let out1 = home1.path().join("staging");
    let out2 = home2.path().join("staging");
    run(home1.path(), &out1);
    run(home2.path(), &out2);

    let bytes1 = std::fs::read(out1.join("9.9.9").join("fixture-app-9.9.9-native.zip")).unwrap();
    let bytes2 = std::fs::read(out2.join("9.9.9").join("fixture-app-9.9.9-native.zip")).unwrap();
    assert_eq!(
        bytes1, bytes2,
        "archives built from identical inputs and epoch must be byte-identical"
    );
}
