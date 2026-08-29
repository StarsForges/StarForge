//! CLI integration tests for `starforge interop stellar` workflows.

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interop/stellar")
}

fn starforge(home: &Path, stellar_config: &Path, args: &[&str]) -> Output {
    let mut cmd_args: Vec<String> = vec!["--quiet".into()];
    if args.is_empty() {
        cmd_args.extend(["interop".into(), "stellar".into()]);
    } else {
        cmd_args.extend(["interop".into(), "stellar".into(), args[0].into()]);
        cmd_args.push("--stellar-config-dir".into());
        cmd_args.push(stellar_config.to_string_lossy().into());
        for arg in &args[1..] {
            cmd_args.push((*arg).into());
        }
    }
    Command::new(env!("CARGO_BIN_EXE_starforge"))
        .args(&cmd_args)
        .env("HOME", home)
        .output()
        .expect("run starforge")
}

fn copy_fixture_tree(src: &Path, dst: &Path) {
    if !dst.exists() {
        fs::create_dir_all(dst).unwrap();
    }
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_fixture_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn setup_isolated_home() -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let stellar = home.path().join("stellar-config");
    copy_fixture_tree(&fixture_root(), &stellar);
    (home, stellar)
}

#[test]
fn discover_json_is_versioned_and_banner_free() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let output = starforge(
        home.path(),
        &stellar,
        &["discover", "--format", "json", "--target", "both"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("StarForge"));
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert!(report["starforge"]["networks"].as_object().unwrap().len() >= 2);
    assert_eq!(
        report["stellar_cli"]["networks"]["testnet"]["name"],
        "testnet"
    );
}

#[test]
fn discover_does_not_modify_external_files() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let before = fs::read(stellar.join("network/testnet.toml")).unwrap();
    let _ = starforge(home.path(), &stellar, &["discover", "--format", "json"]);
    let after = fs::read(stellar.join("network/testnet.toml")).unwrap();
    assert_eq!(before, after);
}

#[test]
fn diff_reports_missing_network_in_starforge() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let output = starforge(
        home.path(),
        &stellar,
        &["diff", "--format", "json", "--direction", "import"],
    );
    assert!(output.status.success());
    let diff: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(diff["schema_version"], 1);
    assert!(diff["summary"]["missing_in_target"].as_u64().unwrap() >= 1);
}

#[test]
fn diff_detects_network_mismatch() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    // Add conflicting network to starforge config
    let sf_dir = home.path().join(".starforge");
    fs::create_dir_all(&sf_dir).unwrap();
    fs::write(
        sf_dir.join("config.toml"),
        r#"
version = "2"
network = "testnet"
wallets = []

[networks.testnet]
horizon_url = "https://horizon-conflict.example.org"
soroban_rpc_url = "https://rpc-conflict.example.org"
passphrase = "Test SDF Network ; September 2015"
"#,
    )
    .unwrap();

    let output = starforge(home.path(), &stellar, &["diff", "--format", "json"]);
    assert_eq!(output.status.code(), Some(2));
    let diff: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mismatches = diff["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "network_mismatch");
    assert!(mismatches, "expected network mismatch entry");
}

#[test]
fn import_dry_run_does_not_modify_starforge_config() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let cfg_path = home.path().join(".starforge/config.toml");
    assert!(!cfg_path.exists());
    let output = starforge(home.path(), &stellar, &["import", "--format", "json"]);
    assert!(output.status.success());
    assert!(!cfg_path.exists() || fs::metadata(&cfg_path).unwrap().len() == 0);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
}

#[test]
fn import_apply_adds_custom_network() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let output = starforge(
        home.path(),
        &stellar,
        &[
            "import",
            "--apply",
            "--format",
            "json",
            "--category",
            "network",
            "--name",
            "future",
            "--precedence",
            "additive_only",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cfg = fs::read_to_string(home.path().join(".starforge/config.toml")).unwrap();
    assert!(cfg.contains("horizon-future.example.org"));
}

#[test]
fn export_public_only_skips_secrets() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let secret_path = stellar.join("identities/secret-alice.toml");
    fs::write(
        &secret_path,
        "secret_key = \"SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();

    let export_path = home.path().join("bundle.json");
    let output = starforge(
        home.path(),
        &stellar,
        &[
            "export",
            "--format",
            "json",
            "--source",
            "stellar",
            "--output",
            export_path.to_str().unwrap(),
        ],
    );
    assert!(output.status.success());
    let bundle: Value = serde_json::from_slice(&fs::read(&export_path).unwrap()).unwrap();
    let serialized = bundle.to_string();
    assert!(!serialized.contains("SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT"));
    assert_eq!(bundle["redacted"], true);
}

#[test]
fn export_bundle_has_restrictive_permissions() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let export_path = home.path().join("bundle.json");
    let output = starforge(
        home.path(),
        &stellar,
        &[
            "export",
            "--source",
            "stellar",
            "--output",
            export_path.to_str().unwrap(),
        ],
    );
    assert!(output.status.success());
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&export_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn doctor_reports_stale_provenance_after_config_change() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let output = starforge(home.path(), &stellar, &["doctor", "--format", "json"]);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["code"] == "provenance.never_synced"));
}

#[test]
fn doctor_flags_insecure_identity_permissions() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let insecure = stellar.join("identities/insecure.toml");
    fs::write(
        &insecure,
        "secret_key = \"SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o644)).unwrap();

    let output = starforge(home.path(), &stellar, &["doctor", "--format", "json"]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["code"] == "identity.insecure_permissions"));
}

#[test]
fn sync_round_trip_preserves_public_identities() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let import = starforge(
        home.path(),
        &stellar,
        &[
            "import",
            "--apply",
            "--format",
            "json",
            "--category",
            "identity",
            "--name",
            "alice",
            "--precedence",
            "stellar_cli_wins",
        ],
    );
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );

    let export_dir = home.path().join("stellar-export");
    fs::create_dir_all(export_dir.join("identities")).unwrap();
    let export = starforge(
        home.path(),
        &export_dir,
        &[
            "sync",
            "--apply",
            "--yes",
            "--format",
            "json",
            "--direction",
            "export",
            "--category",
            "identity",
            "--name",
            "alice",
        ],
    );
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(export_dir.join("identities/alice.toml").exists());
}

#[test]
fn diff_duplicate_names_are_reported_via_doctor_warnings() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    fs::write(
        stellar.join("network/testnet-local.toml"),
        fs::read_to_string(stellar.join("network/testnet.toml")).unwrap(),
    )
    .unwrap();
    // Same network name from two different file stems still maps to unique keys;
    // duplicate detection covers repeated inserts during multi-root discovery.
    let legacy_net = home.path().join(".config/soroban/network");
    fs::create_dir_all(&legacy_net).unwrap();
    fs::copy(
        stellar.join("network/testnet.toml"),
        legacy_net.join("testnet.toml"),
    )
    .unwrap();

    let output = starforge(
        home.path(),
        &stellar,
        &["discover", "--format", "json", "--target", "stellar"],
    );
    assert!(output.status.success());
    let snap: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(snap["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w["code"] == "network.duplicate"));
}

#[test]
fn symlink_is_skipped_by_default() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            stellar.join("identities/alice.toml"),
            stellar.join("identities/alice-link.toml"),
        )
        .unwrap();
    }
    let output = starforge(
        home.path(),
        &stellar,
        &["discover", "--format", "json", "--target", "stellar"],
    );
    assert!(output.status.success());
    #[cfg(unix)]
    {
        let snap: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(snap["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "identity.symlink_skipped"));
    }
}

#[test]
fn interop_help_lists_complete_workflow() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_starforge"))
        .arg("--quiet")
        .args(["interop", "stellar", "--help"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for cmd in ["discover", "diff", "import", "export", "sync", "doctor"] {
        assert!(help.contains(cmd), "help missing subcommand {cmd}");
    }
}

#[test]
fn fail_on_conflict_exits_nonzero_on_mismatch() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let sf_dir = home.path().join(".starforge");
    fs::create_dir_all(&sf_dir).unwrap();
    fs::write(
        sf_dir.join("config.toml"),
        r#"
version = "2"
network = "testnet"
wallets = []

[networks.testnet]
horizon_url = "https://horizon-conflict.example.org"
"#,
    )
    .unwrap();

    let output = starforge(
        home.path(),
        &stellar,
        &[
            "sync",
            "--apply",
            "--format",
            "json",
            "--precedence",
            "fail_on_conflict",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn contract_alias_import_round_trip() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let output = starforge(
        home.path(),
        &stellar,
        &[
            "import",
            "--apply",
            "--format",
            "json",
            "--category",
            "contract_alias",
            "--name",
            "token",
            "--precedence",
            "stellar_cli_wins",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let alias_path = home.path().join(".starforge/contract-aliases/token.json");
    assert!(alias_path.exists());
    let contents = fs::read_to_string(alias_path).unwrap();
    assert!(contents.contains("CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A"));
}

#[test]
fn encrypted_secret_requires_explicit_opt_in() {
    let _guard = env_guard();
    let (home, stellar) = setup_isolated_home();
    let enc_path = stellar.join("identities/encrypted.toml");
    fs::write(
        &enc_path,
        r#"
public_key = "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T"
encrypted_secret = "salt:nonce:ciphertext:32768:3:1"
"#,
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&enc_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = starforge(
        home.path(),
        &stellar,
        &[
            "diff",
            "--format",
            "json",
            "--category",
            "identity",
            "--name",
            "encrypted",
        ],
    );
    assert!(output.status.success());
    let diff: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(diff["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "encrypted_secret"));
}

#[test]
fn legacy_soroban_path_is_scanned_when_enabled() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let stellar = home.path().join("empty-stellar");
    fs::create_dir_all(&stellar).unwrap();
    let legacy = home.path().join(".config/soroban/identity");
    fs::create_dir_all(&legacy).unwrap();
    fs::write(
        legacy.join("legacy.toml"),
        "public_key = \"GBBO4ZDDZTSM2IUKQYBAST3CFHNPFXECGEFTGWTA3WUYC3IDATK4YALU\"\n",
    )
    .unwrap();

    let output = starforge(
        home.path(),
        &stellar,
        &[
            "discover",
            "--format",
            "json",
            "--target",
            "stellar",
            "--include-legacy",
        ],
    );
    assert!(output.status.success());
    let snap: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(snap["identities"].as_object().unwrap().len() >= 1);
}
