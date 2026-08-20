//! End-to-end CLI coverage for `starforge compliance` (issue #49 / AI-016).
//!
//! Follows the isolated-`HOME` pattern from `tests/cli_smoke.rs`: no network
//! access, no shared state between tests.

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
        "{} failed: {}",
        cmd,
        stderr(output)
    );
}

/// A tiny synthetic wasm module (via `wat`) that satisfies the wasm-based
/// controls: a `require_auth` import and a pause-shaped export, with no
/// personal-data-shaped strings in its data section.
fn compliant_wasm(dir: &Path) -> std::path::PathBuf {
    let wat = r#"
        (module
            (import "e" "require_auth" (func $ra (param i64)))
            (func (export "transfer"))
            (func (export "emergency_pause"))
        )
    "#;
    let bytes = wat::parse_str(wat).expect("parse wat");
    let path = dir.join("contract.wasm");
    std::fs::write(&path, bytes).expect("write wasm fixture");
    path
}

fn fully_compliant_metadata(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("metadata.toml");
    std::fs::write(
        &path,
        r#"
        signer_public_keys = ["GAAA", "GBBB"]
        signer_threshold = 2
        upgrade_authority_multisig = true
        upgrade_timelock_seconds = 3600
        stores_personal_data = false
        kyc_provider_integrated = true
        sanctions_screening = true
        transfer_restrictions_documented = true
        has_pause_mechanism = true
        incident_response_contact = "security@example.com"
        terms_of_service_url = "https://example.com/tos"
        privacy_policy_url = "https://example.com/privacy"
        "#,
    )
    .expect("write metadata fixture");
    path
}

#[test]
fn profile_init_then_show_lists_enabled_jurisdiction() {
    let home = isolated_home();
    let init = starforge(home.path())
        .args([
            "compliance",
            "profile",
            "init",
            "--jurisdiction",
            "global-baseline",
        ])
        .output()
        .expect("spawn init");
    assert_success(&init, "compliance profile init");

    let show = starforge(home.path())
        .args(["compliance", "profile", "show"])
        .output()
        .expect("spawn show");
    assert_success(&show, "compliance profile show");
    assert!(stdout(&show).contains("global-baseline"));
}

#[test]
fn profile_init_rejects_unknown_jurisdiction() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "compliance",
            "profile",
            "init",
            "--jurisdiction",
            "not-a-real-jurisdiction",
        ])
        .output()
        .expect("spawn init");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("Unknown jurisdiction"));
}

#[test]
fn profile_init_refuses_to_overwrite_without_force() {
    let home = isolated_home();
    let first = starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");
    assert_success(&first, "compliance profile init");

    let second = starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init again");
    assert!(!second.status.success());
    assert!(stderr(&second).contains("--force"));

    let forced = starforge(home.path())
        .args(["compliance", "profile", "init", "--force"])
        .output()
        .expect("spawn forced init");
    assert_success(&forced, "compliance profile init --force");
}

#[test]
fn check_with_no_inputs_fails_and_reports_details() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    let output = starforge(home.path())
        .args(["compliance", "check"])
        .output()
        .expect("spawn check");
    assert!(
        !output.status.success(),
        "an unconfigured profile should have failing controls"
    );
    assert!(stdout(&output).contains("NOT CLEAN"));
}

#[test]
fn check_with_fully_compliant_inputs_exits_zero() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    // AT-1 requires telemetry to be enabled.
    let telemetry = starforge(home.path())
        .args(["config", "set", "telemetry.enabled", "true"])
        .output()
        .expect("spawn config set");
    assert_success(&telemetry, "config set telemetry.enabled true");

    // AT-2 requires recent evidence on file.
    let evidence = starforge(home.path())
        .args([
            "compliance",
            "evidence",
            "record",
            "--control",
            "AT-2",
            "--description",
            "Quarterly compliance review completed",
        ])
        .output()
        .expect("spawn evidence record");
    assert_success(&evidence, "compliance evidence record");

    let wasm = compliant_wasm(home.path());
    let metadata = fully_compliant_metadata(home.path());

    let output = starforge(home.path())
        .args([
            "compliance",
            "check",
            "--wasm",
            wasm.to_str().unwrap(),
            "--metadata",
            metadata.to_str().unwrap(),
        ])
        .output()
        .expect("spawn check");
    assert_success(&output, "compliance check");
    assert!(stdout(&output).contains("Result: CLEAN"));
}

#[test]
fn waiver_add_changes_failing_control_to_waived() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    let add = starforge(home.path())
        .args([
            "compliance",
            "waiver",
            "add",
            "--control",
            "FC-1",
            "--reason",
            "Pilot phase, no regulated flows yet",
        ])
        .output()
        .expect("spawn waiver add");
    assert_success(&add, "compliance waiver add");
    let add_stdout = stdout(&add);
    assert!(add_stdout.contains("added for control FC-1"));

    let list = starforge(home.path())
        .args(["compliance", "waiver", "list"])
        .output()
        .expect("spawn waiver list");
    assert_success(&list, "compliance waiver list");
    assert!(stdout(&list).contains("FC-1"));

    let check = starforge(home.path())
        .args(["compliance", "check"])
        .output()
        .expect("spawn check");
    let check_stdout = stdout(&check);
    assert!(
        check_stdout.contains("[waived] FC-1") || check_stdout.contains("waived"),
        "expected FC-1 to show as waived: {check_stdout}"
    );
}

#[test]
fn waiver_revoke_removes_the_waiver() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    let add = starforge(home.path())
        .args([
            "compliance",
            "waiver",
            "add",
            "--control",
            "FC-1",
            "--reason",
            "temp",
        ])
        .output()
        .expect("spawn waiver add");
    assert_success(&add, "compliance waiver add");

    // Extract the waiver ID from the success message: "Waiver <id> added for control FC-1".
    let add_stdout = stdout(&add);
    let id = add_stdout
        .split_whitespace()
        .find(|tok| tok.len() == 36 && tok.chars().filter(|c| *c == '-').count() == 4)
        .expect("waiver id in output")
        .to_string();

    let revoke = starforge(home.path())
        .args(["compliance", "waiver", "revoke", &id])
        .output()
        .expect("spawn waiver revoke");
    assert_success(&revoke, "compliance waiver revoke");

    let revoke_again = starforge(home.path())
        .args(["compliance", "waiver", "revoke", &id])
        .output()
        .expect("spawn waiver revoke again");
    assert!(!revoke_again.status.success(), "revoking twice must fail");
}

#[test]
fn evidence_record_then_list_round_trips() {
    let home = isolated_home();
    let record = starforge(home.path())
        .args([
            "compliance",
            "evidence",
            "record",
            "--control",
            "AC-1",
            "--description",
            "Manual code review completed by security team",
            "--reviewer",
            "alice",
        ])
        .output()
        .expect("spawn evidence record");
    assert_success(&record, "compliance evidence record");

    let list = starforge(home.path())
        .args(["compliance", "evidence", "list"])
        .output()
        .expect("spawn evidence list");
    assert_success(&list, "compliance evidence list");
    let list_stdout = stdout(&list);
    assert!(list_stdout.contains("AC-1"));
    assert!(list_stdout.contains("alice"));
}

#[test]
fn report_export_writes_valid_json() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    let output_path = home.path().join("report.json");
    let export = starforge(home.path())
        .args([
            "compliance",
            "report",
            "export",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn report export");
    assert_success(&export, "compliance report export");

    let contents = std::fs::read_to_string(&output_path).expect("read exported report");
    let parsed: serde_json::Value =
        serde_json::from_str(&contents).expect("exported report is valid JSON");
    assert!(parsed.get("schema_version").is_some());
    assert!(parsed.get("summary").is_some());
}

#[test]
fn report_export_markdown_produces_a_table() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    let output_path = home.path().join("report.md");
    let export = starforge(home.path())
        .args([
            "compliance",
            "report",
            "export",
            "--format",
            "markdown",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn report export");
    assert_success(&export, "compliance report export --format markdown");

    let contents = std::fs::read_to_string(&output_path).expect("read exported report");
    assert!(contents.contains("| Control | Status"));
}

#[test]
fn check_explain_without_api_key_fails_fast_with_no_network_call() {
    let home = isolated_home();
    starforge(home.path())
        .args(["compliance", "profile", "init"])
        .output()
        .expect("spawn init");

    let mut cmd = starforge(home.path());
    cmd.args(["compliance", "check", "--explain"]);
    cmd.env_remove("OPENAI_API_KEY");
    cmd.env_remove("STARFORGE_AI_API_KEY");
    let output = cmd.output().expect("spawn check --explain");

    assert!(!output.status.success());
    assert!(stderr(&output).contains("OPENAI_API_KEY"));
}

#[test]
fn compliance_check_help_documents_explain_flag() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args(["compliance", "check", "--help"])
        .output()
        .expect("spawn check --help");
    assert_success(&output, "compliance check --help");
    assert!(stdout(&output).contains("--explain"));
}
