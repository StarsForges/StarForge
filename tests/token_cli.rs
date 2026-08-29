//! CLI integration tests for `starforge token` workflows.

use serde_json::Value;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const CONTRACT: &str = "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A";
const ALICE: &str = "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T";
const BOB: &str = "GBBO4ZDDZTSM2IUKQYBAST3CFHNPFXECGEFTGWTA3WUYC3IDATK4YALU";

fn starforge(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_starforge"))
        .arg("--quiet")
        .args(args)
        .env("HOME", home)
        .output()
        .expect("run starforge")
}

#[test]
fn inspect_json_is_versioned_with_capabilities() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token", "inspect", "--id", CONTRACT, "--format", "json", "--mock",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["metadata"]["capabilities"]["is_sep41"], true);
}

#[test]
fn balance_returns_decimal_safe_amount() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token", "balance", ALICE, "--id", CONTRACT, "--format", "json", "--mock",
        ],
    );
    assert!(output.status.success());
    let balance: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(balance["amount"]["raw"], 1_500_000_000);
    assert!(balance["amount"]["display"].as_str().unwrap().contains('.'));
}

#[test]
fn allowance_read_returns_state() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "allowance",
            ALICE,
            BOB,
            "--id",
            CONTRACT,
            "--format",
            "json",
            "--mock",
        ],
    );
    assert!(output.status.success());
    let state: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(state["owner"], ALICE);
    assert_eq!(state["spender"], BOB);
}

#[test]
fn transfer_simulation_produces_receipt() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "transfer",
            "--id",
            CONTRACT,
            "--from",
            ALICE,
            "--to",
            BOB,
            "--amount",
            "1.0",
            "--format",
            "json",
            "--mock",
            "--simulate",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["schema_version"], 1);
    assert_eq!(receipt["status"], "simulated");
}

#[test]
fn approve_respects_expiration_ledger_flag() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "approve",
            "--id",
            CONTRACT,
            "--from",
            ALICE,
            "--spender",
            BOB,
            "--amount",
            "0.5",
            "--expiration-ledger",
            "12345",
            "--format",
            "json",
            "--mock",
            "--simulate",
        ],
    );
    assert!(output.status.success());
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["operation"], "approve");
}

#[test]
fn mint_requires_admin_capability() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "mint",
            "--id",
            CONTRACT,
            "--from",
            ALICE,
            "--to",
            BOB,
            "--amount",
            "1",
            "--format",
            "json",
            "--mock",
            "--simulate",
            "--yes",
        ],
    );
    assert!(output.status.success());
}

#[test]
fn burn_simulates_successfully() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "burn",
            "--id",
            CONTRACT,
            "--from",
            ALICE,
            "--amount",
            "0.1",
            "--format",
            "json",
            "--mock",
            "--simulate",
        ],
    );
    assert!(output.status.success());
}

#[test]
fn admin_rotate_simulates_with_confirmation_flag() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "admin",
            "--id",
            CONTRACT,
            "--from",
            ALICE,
            "--new-admin",
            BOB,
            "--format",
            "json",
            "--mock",
            "--simulate",
            "--yes",
        ],
    );
    assert!(output.status.success());
}

#[test]
fn batch_manifest_executes_with_partial_results() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/token/batch_manifest.json");
    let output = starforge(
        home.path(),
        &[
            "token",
            "batch",
            manifest.to_str().unwrap(),
            "--id",
            CONTRACT,
            "--format",
            "json",
            "--mock",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert!(report["succeeded"].as_u64().unwrap() >= 1);
}

#[test]
fn token_help_lists_all_subcommands() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(home.path(), &["token", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for cmd in [
        "inspect",
        "balance",
        "allowance",
        "transfer",
        "approve",
        "mint",
        "burn",
        "authorize",
        "admin",
        "batch",
    ] {
        assert!(help.contains(cmd), "missing {cmd} in help");
    }
}

#[test]
fn json_output_is_banner_free() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token", "inspect", "--id", CONTRACT, "--format", "json", "--mock",
        ],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("StarForge"));
}

#[test]
fn negative_amount_is_rejected() {
    let _guard = env_guard();
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &[
            "token",
            "transfer",
            "--id",
            CONTRACT,
            "--from",
            ALICE,
            "--to",
            BOB,
            "--amount",
            "-1",
            "--format",
            "json",
            "--mock",
            "--simulate",
        ],
    );
    assert!(!output.status.success());
}
