//! End-to-end CLI coverage for `starforge budget` (issue #100).
//!
//! Follows the isolated-`HOME` pattern from `tests/cli_smoke.rs` /
//! `tests/cost_estimate_cli.rs`: every test gets its own temp `HOME`, so
//! policy files, baselines, and the audit log never leak between tests or
//! depend on network access.

use std::path::Path;
use std::process::{Command, Output};

fn isolated_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("create isolated home")
}

fn starforge(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_starforge"));
    cmd.arg("-q");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd.env_remove("STARFORGE_BUDGET_POLICY");
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
        "{} failed (status {:?}): stdout={} stderr={}",
        cmd,
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn fixture_path(name: &str) -> String {
    format!(
        "{}/tests/fixtures/soroban_rpc/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

#[test]
fn init_writes_default_policy_and_second_init_requires_force() {
    let home = isolated_home();

    let output = starforge(home.path())
        .args(["budget", "init"])
        .output()
        .expect("spawn budget init");
    assert_success(&output, "budget init");
    assert!(stdout(&output).contains("Budget Policy Initialized"));

    let policy_path = home.path().join(".starforge/data/budget/policy.json");
    assert!(
        policy_path.exists(),
        "expected policy at {}",
        policy_path.display()
    );

    let second = starforge(home.path())
        .args(["budget", "init"])
        .output()
        .expect("spawn second budget init");
    assert!(
        !second.status.success(),
        "second init without --force should fail"
    );
    assert!(stderr(&second).contains("already exists"));

    let forced = starforge(home.path())
        .args(["budget", "init", "--force"])
        .output()
        .expect("spawn forced budget init");
    assert_success(&forced, "budget init --force");
}

#[test]
fn check_without_policy_errors_with_actionable_message() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--classic-fee-stroops",
            "100",
        ])
        .output()
        .expect("spawn budget check");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("budget init"));
}

#[test]
fn check_passes_when_within_limits() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "testnet",
            "--classic-fee-stroops",
            "500",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget check");
    assert_success(&output, "budget check (within limits)");
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert_eq!(json["decision"], "allow");
}

#[test]
fn check_blocks_and_exits_nonzero_when_over_limit() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--classic-fee-stroops",
            "999999999",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget check");
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert_eq!(json["decision"], "block");
    assert!(stderr(&output).contains("budget-override-reason"));
}

#[test]
fn check_allows_over_limit_with_valid_override_reason() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--classic-fee-stroops",
            "999999999",
            "--budget-override-reason",
            "approved by release manager for hotfix",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget check");
    assert_success(&output, "budget check with override");
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert_eq!(json["decision"], "override-allowed");
}

/// An override reason is free text typed under time pressure and could
/// accidentally contain a secret. `redact_text` (see
/// `src/commands/ai/impact/redactor.rs`) is applied before the reason
/// reaches the audit log — this proves it actually happens end-to-end
/// through the CLI, not just at the unit level.
#[test]
fn override_reason_containing_a_secret_is_redacted_before_reaching_the_audit_log() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    let fake_stellar_secret = "SAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGG";
    let reason = format!("approved after rotating {}", fake_stellar_secret);

    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--classic-fee-stroops",
            "999999999",
            "--budget-override-reason",
            &reason,
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget check");
    assert_success(&output, "budget check with secret-bearing override");

    let audit_output = starforge(home.path())
        .args(["budget", "audit", "--format", "json"])
        .output()
        .expect("spawn budget audit");
    assert_success(&audit_output, "budget audit");
    let raw_audit = stdout(&audit_output);
    assert!(
        !raw_audit.contains(fake_stellar_secret),
        "raw secret leaked into the audit log: {}",
        raw_audit
    );
    assert!(
        raw_audit.contains("REDACTED_STELLAR_SECRET_KEY"),
        "expected a redaction placeholder in the audit log, got: {}",
        raw_audit
    );
}

#[test]
fn check_rejects_override_reason_that_is_too_short() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--classic-fee-stroops",
            "999999999",
            "--budget-override-reason",
            "nah",
        ])
        .output()
        .expect("spawn budget check");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("at least"));
}

#[test]
fn check_normalizes_resource_usage_from_simulation_fixture() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    // Tighten the CPU limit for this function below the fixture's 480000
    // instructions so the check has something to flag.
    let policy_path = home.path().join(".starforge/data/budget/policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&policy_path).unwrap()).unwrap();
    policy["functions"]["CCONTRACT::transfer"] = serde_json::json!({ "max_cpu_insns": 1000 });
    std::fs::write(&policy_path, serde_json::to_string_pretty(&policy).unwrap()).unwrap();

    let output = starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "invoke",
            "--contract",
            "CCONTRACT",
            "--function",
            "transfer",
            "--simulation-file",
            &fixture_path("simulate_cost_with_footprint.json"),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget check");
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert_eq!(json["decision"], "block");
    assert_eq!(json["metrics"]["cpu_insns"], 480000);
}

#[test]
fn explain_shows_effective_limits_and_contributing_layers() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    let output = starforge(home.path())
        .args([
            "budget",
            "explain",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget explain");
    assert_success(&output, "budget explain");
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert!(json["contributing_layers"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("network:mainnet")));
    assert!(json["limits"]["max_classic_fee_stroops"].as_u64().unwrap() < 1_000_000);
}

#[test]
fn baseline_then_diff_flags_regression_beyond_threshold() {
    let home = isolated_home();

    assert_success(
        &starforge(home.path())
            .args([
                "budget",
                "baseline",
                "--label",
                "ci-run",
                "--cpu-insns",
                "10000",
            ])
            .output()
            .unwrap(),
        "budget baseline (first)",
    );
    assert_success(
        &starforge(home.path())
            .args([
                "budget",
                "baseline",
                "--label",
                "ci-run",
                "--cpu-insns",
                "50000",
            ])
            .output()
            .unwrap(),
        "budget baseline (second)",
    );

    let output = starforge(home.path())
        .args([
            "budget",
            "diff",
            "--label",
            "ci-run",
            "--threshold-percent",
            "10",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget diff");
    assert!(!output.status.success(), "regression should exit nonzero");
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert_eq!(json["regressed"], true);
}

#[test]
fn baseline_then_diff_within_threshold_passes() {
    let home = isolated_home();

    for cpu in ["10000", "10100"] {
        assert_success(
            &starforge(home.path())
                .args([
                    "budget",
                    "baseline",
                    "--label",
                    "stable",
                    "--cpu-insns",
                    cpu,
                ])
                .output()
                .unwrap(),
            "budget baseline",
        );
    }

    let output = starforge(home.path())
        .args([
            "budget",
            "diff",
            "--label",
            "stable",
            "--threshold-percent",
            "50",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn budget diff");
    assert_success(&output, "budget diff (stable)");
}

#[test]
fn audit_log_records_check_decisions() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );

    // One allowed, one blocked.
    starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--classic-fee-stroops",
            "10",
        ])
        .output()
        .unwrap();
    starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--classic-fee-stroops",
            "999999999",
        ])
        .output()
        .unwrap();

    let output = starforge(home.path())
        .args(["budget", "audit", "--format", "json"])
        .output()
        .expect("spawn budget audit");
    assert_success(&output, "budget audit");
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    let records = json.as_array().expect("array of records");
    assert_eq!(records.len(), 2);
    // Most recent first.
    assert_eq!(records[0]["decision"], "block");
    assert_eq!(records[1]["decision"], "allow");
}

#[test]
fn audit_log_filters_by_decision() {
    let home = isolated_home();
    assert_success(
        &starforge(home.path())
            .args(["budget", "init"])
            .output()
            .unwrap(),
        "budget init",
    );
    starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--classic-fee-stroops",
            "10",
        ])
        .output()
        .unwrap();
    starforge(home.path())
        .args([
            "budget",
            "check",
            "--command",
            "deploy",
            "--network",
            "mainnet",
            "--classic-fee-stroops",
            "999999999",
        ])
        .output()
        .unwrap();

    let output = starforge(home.path())
        .args(["budget", "audit", "--decision", "block", "--format", "json"])
        .output()
        .expect("spawn budget audit");
    assert_success(&output, "budget audit --decision block");
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    let records = json.as_array().expect("array of records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "block");
}

/// Every fee/resource-emitting command path listed in issue #100
/// ("deploy, invoke, batch, token, path-payment, and transaction lifecycle
/// paths") must expose `--budget-override-reason` — the flag that lets an
/// operator proceed past a budget violation with an audited reason. This is
/// a flag-presence check (no network needed); behavior is covered by the
/// `utils::budget::gate` unit tests and the `check_*` tests above, which
/// exercise the same enforcement path these commands call into.
#[test]
fn budget_override_flag_is_wired_into_every_integrated_command_path() {
    let home = isolated_home();
    let cases: &[&[&str]] = &[
        &["deploy", "--help"],
        &["contract", "invoke", "--help"],
        &["batch", "pay", "--help"],
        &["tx", "send", "--help"],
        &["tx", "batch", "--help"],
    ];
    for args in cases {
        let output = starforge(home.path())
            .args(*args)
            .output()
            .unwrap_or_else(|e| panic!("spawn {:?}: {}", args, e));
        assert_success(&output, &format!("{:?}", args));
        assert!(
            stdout(&output).contains("--budget-override-reason"),
            "{:?} --help should document --budget-override-reason, got: {}",
            args,
            stdout(&output)
        );
    }
}

#[test]
fn top_level_help_lists_budget_command() {
    let home = isolated_home();
    let output = starforge(home.path())
        .arg("--help")
        .output()
        .expect("spawn --help");
    assert_success(&output, "starforge --help");
    assert!(stdout(&output).contains("budget"));
}

#[test]
fn budget_help_lists_all_required_subcommands() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args(["budget", "--help"])
        .output()
        .expect("spawn budget --help");
    assert_success(&output, "starforge budget --help");
    let out = stdout(&output);
    for sub in ["init", "check", "baseline", "diff", "explain", "audit"] {
        assert!(
            out.contains(sub),
            "budget --help missing subcommand {}",
            sub
        );
    }
}
