//! End-to-end CLI coverage for `starforge cost` (issue #50 / AI-015).
//!
//! Follows the isolated-`HOME` pattern from `tests/cli_smoke.rs` /
//! `tests/compliance_cli.rs`: no network access, no shared state between
//! tests. AI narrative generation is always skipped here (either via
//! `--deterministic` or by removing the API key env vars), so nothing in
//! this file depends on a live OpenAI endpoint.

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
    cmd.env_remove("OPENAI_API_KEY");
    cmd.env_remove("STARFORGE_AI_API_KEY");
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

fn fixture_path(name: &str) -> String {
    format!(
        "{}/tests/fixtures/soroban_rpc/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

#[test]
fn estimate_deterministic_markdown_reports_breakdown_and_total() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--write-entries",
            "2",
            "--write-bytes",
            "500",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate");
    assert_success(&output, "cost estimate invoke");
    let out = stdout(&output);
    assert!(out.contains("Soroban Cost Estimate"));
    assert!(out.contains("Breakdown"));
    assert!(out.contains("Total"));
    assert!(out.contains("Cost drivers"));
}

#[test]
fn estimate_json_is_valid_and_reflects_operation() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "deploy",
            "--format",
            "json",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate");
    assert_success(&output, "cost estimate deploy --format json");

    let out = stdout(&output);
    let json_start = out.find('{').expect("json object in output");
    let parsed: serde_json::Value =
        serde_json::from_str(out[json_start..].trim()).expect("estimate output is valid JSON");
    assert_eq!(parsed["operation"], "deploy");
    assert!(parsed["total_fee_stroops"].as_u64().unwrap() > 0);
}

#[test]
fn estimate_rejects_unknown_operation() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args(["cost", "estimate", "teleport", "--deterministic"])
        .output()
        .expect("spawn estimate");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("Unknown operation kind"));
}

#[test]
fn estimate_from_simulation_file_normalizes_cost_and_footprint() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--simulation-file",
            &fixture_path("simulate_cost_with_footprint.json"),
            "--format",
            "json",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate");
    assert_success(&output, "cost estimate --simulation-file");

    let out = stdout(&output);
    let json_start = out.find('{').expect("json object in output");
    let parsed: serde_json::Value = serde_json::from_str(out[json_start..].trim()).unwrap();
    assert_eq!(parsed["resource_usage"]["cpu_insns"], 480000);
    assert_eq!(parsed["resource_usage"]["mem_bytes"], 8192);
    assert_eq!(parsed["resource_usage"]["read_entries"], 1);
    assert_eq!(parsed["resource_usage"]["write_entries"], 2);
    assert_eq!(parsed["resource_usage"]["write_bytes"], 384);
}

#[test]
fn estimate_with_bad_simulation_file_json_fails_clearly() {
    let home = isolated_home();
    let bad_path = home.path().join("bad.json");
    std::fs::write(&bad_path, "{ not valid json").unwrap();

    let output = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--simulation-file",
            bad_path.to_str().unwrap(),
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("Failed to parse simulation file"));
}

#[test]
fn estimate_rejects_zero_batch_size_instead_of_silently_clamping() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--batch-size",
            "0",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--batch-size must be at least 1"));
}

#[test]
fn save_then_export_round_trips_history_as_json() {
    let home = isolated_home();
    let save = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--label",
            "my-contract",
            "--save",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate --save");
    assert_success(&save, "cost estimate --save");
    assert!(stdout(&save).contains("Saved snapshot"));

    let export = starforge(home.path())
        .args([
            "cost",
            "export",
            "--label",
            "my-contract",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn export");
    assert_success(&export, "cost export");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout(&export).trim()).expect("export output is valid JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn export_csv_has_header_and_one_row_per_snapshot() {
    let home = isolated_home();
    for _ in 0..2 {
        let save = starforge(home.path())
            .args([
                "cost",
                "estimate",
                "invoke",
                "--label",
                "csv-label",
                "--save",
                "--deterministic",
            ])
            .output()
            .expect("spawn estimate --save");
        assert_success(&save, "cost estimate --save");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    let export = starforge(home.path())
        .args(["cost", "export", "--label", "csv-label", "--format", "csv"])
        .output()
        .expect("spawn export csv");
    assert_success(&export, "cost export --format csv");
    let out = stdout(&export);
    assert!(out.contains("timestamp,operation,network"));
    assert_eq!(out.trim().lines().count(), 3);
}

#[test]
fn export_unknown_label_yields_empty_history_not_an_error() {
    let home = isolated_home();
    let export = starforge(home.path())
        .args([
            "cost",
            "export",
            "--label",
            "never-estimated",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn export");
    assert_success(&export, "cost export unknown label");
    let parsed: serde_json::Value = serde_json::from_str(stdout(&export).trim()).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn budget_passes_when_under_and_fails_when_over() {
    let home = isolated_home();
    let save = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--label",
            "budget-label",
            "--write-entries",
            "3",
            "--write-bytes",
            "900",
            "--save",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate --save");
    assert_success(&save, "cost estimate --save");

    let under = starforge(home.path())
        .args([
            "cost",
            "budget",
            "--label",
            "budget-label",
            "--max-fee-stroops",
            "1000000000",
        ])
        .output()
        .expect("spawn budget (under)");
    assert_success(&under, "cost budget (under budget)");
    assert!(stdout(&under).contains("within budget"));

    let over = starforge(home.path())
        .args([
            "cost",
            "budget",
            "--label",
            "budget-label",
            "--max-fee-stroops",
            "1",
        ])
        .output()
        .expect("spawn budget (over)");
    assert!(
        !over.status.success(),
        "expected budget check to fail when over budget"
    );
    assert!(stdout(&over).contains("OVER BUDGET") || stderr(&over).contains("exceeds budget"));
}

#[test]
fn budget_on_unknown_label_fails_with_clear_message() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args([
            "cost",
            "budget",
            "--label",
            "nonexistent",
            "--max-fee-stroops",
            "1000",
        ])
        .output()
        .expect("spawn budget");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("No cost history found"));
}

#[test]
fn check_regression_passes_on_first_run_and_fails_on_large_increase() {
    let home = isolated_home();

    let first = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--label",
            "regress-label",
            "--write-entries",
            "1",
            "--write-bytes",
            "100",
            "--save",
            "--deterministic",
        ])
        .output()
        .expect("spawn first estimate");
    assert_success(&first, "cost estimate (baseline)");

    let first_check = starforge(home.path())
        .args([
            "cost",
            "check-regression",
            "--label",
            "regress-label",
            "--threshold-percent",
            "10",
        ])
        .output()
        .expect("spawn check-regression");
    assert_success(&first_check, "cost check-regression (first run)");
    assert!(stdout(&first_check).contains("OK"));

    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--label",
            "regress-label",
            "--write-entries",
            "50",
            "--write-bytes",
            "50000",
            "--save",
            "--deterministic",
        ])
        .output()
        .expect("spawn second estimate");
    assert_success(&second, "cost estimate (regressed)");

    let second_check = starforge(home.path())
        .args([
            "cost",
            "check-regression",
            "--label",
            "regress-label",
            "--threshold-percent",
            "10",
        ])
        .output()
        .expect("spawn check-regression");
    assert!(
        !second_check.status.success(),
        "expected regression to be detected"
    );
    assert!(stdout(&second_check).contains("REGRESSED"));
}

#[test]
fn compare_by_label_reports_delta_between_last_two_snapshots() {
    let home = isolated_home();
    for writes in [1u32, 10u32] {
        let save = starforge(home.path())
            .args([
                "cost",
                "estimate",
                "invoke",
                "--label",
                "compare-label",
                "--write-entries",
                &writes.to_string(),
                "--write-bytes",
                "1000",
                "--save",
                "--deterministic",
            ])
            .output()
            .expect("spawn estimate --save");
        assert_success(&save, "cost estimate --save");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    let compare = starforge(home.path())
        .args(["cost", "compare", "--label", "compare-label"])
        .output()
        .expect("spawn compare");
    assert_success(&compare, "cost compare --label");
    assert!(stdout(&compare).contains("Cost Comparison"));
}

#[test]
fn compare_with_fewer_than_two_snapshots_fails_clearly() {
    let home = isolated_home();
    let save = starforge(home.path())
        .args([
            "cost",
            "estimate",
            "invoke",
            "--label",
            "solo-label",
            "--save",
            "--deterministic",
        ])
        .output()
        .expect("spawn estimate --save");
    assert_success(&save, "cost estimate --save");

    let compare = starforge(home.path())
        .args(["cost", "compare", "--label", "solo-label"])
        .output()
        .expect("spawn compare");
    assert!(!compare.status.success());
    assert!(stderr(&compare).contains("Need at least 2"));
}

#[test]
fn estimate_help_documents_operation_and_save_flags() {
    let home = isolated_home();
    let output = starforge(home.path())
        .args(["cost", "estimate", "--help"])
        .output()
        .expect("spawn estimate --help");
    assert_success(&output, "cost estimate --help");
    let out = stdout(&output);
    assert!(out.contains("--save"));
    assert!(out.contains("--deterministic"));
}
