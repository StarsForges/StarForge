//! End-to-end and integration tests for the AI-assisted performance profiling system.
//! All tests use fixtures or in-process operations; no external network calls are made.

use std::process::Command;

fn isolated_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("create isolated home")
}

fn starforge(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_starforge"));
    cmd.arg("-q");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    // Disable AI calls in all tests
    cmd.env("OPENAI_API_KEY", "");
    cmd
}

fn assert_success(output: &std::process::Output, ctx: &str) {
    assert!(
        output.status.success(),
        "{} failed:\nstdout: {}\nstderr: {}",
        ctx,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &std::process::Output, ctx: &str) {
    assert!(
        !output.status.success(),
        "{} should have failed but succeeded:\nstdout: {}",
        ctx,
        String::from_utf8_lossy(&output.stdout)
    );
}

fn heavy_fixture() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/soroban_rpc/simulate_profile_heavy.json")
}

fn light_fixture() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/soroban_rpc/simulate_profile_light.json")
}

fn success_fixture() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/soroban_rpc/simulate_success.json")
}

// ── Help and discovery ────────────────────────────────────────────────────────

#[test]
fn profile_help_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["profile", "--help"])
        .output()
        .expect("spawn profile --help");
    assert_success(&out, "profile --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("run") || stdout.contains("compare") || stdout.contains("export"),
        "help should list subcommands"
    );
}

#[test]
fn profile_run_help_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["profile", "run", "--help"])
        .output()
        .expect("spawn profile run --help");
    assert_success(&out, "profile run --help");
}

#[test]
fn profile_budget_help_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["profile", "budget", "--help"])
        .output()
        .expect("spawn profile budget --help");
    assert_success(&out, "profile budget --help");
}

// ── Run subcommand ────────────────────────────────────────────────────────────

#[test]
fn profile_run_from_simulation_file_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "test-contract",
            "--simulation-file",
            success_fixture().to_str().unwrap(),
        ])
        .output()
        .expect("spawn profile run");
    assert_success(&out, "profile run --simulation-file");
}

#[test]
fn profile_run_json_output_is_valid() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "json-test",
            "--simulation-file",
            success_fixture().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile run --format json");
    assert_success(&out, "profile run --format json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("profile run JSON output is valid JSON");
    assert!(
        parsed.get("metrics").is_some(),
        "JSON should contain 'metrics'"
    );
    assert!(
        parsed.get("optimization_report").is_some(),
        "JSON should contain 'optimization_report'"
    );
}

#[test]
fn profile_run_json_contains_expected_cpu_from_fixture() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "cpu-check",
            "--simulation-file",
            success_fixture().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn");
    assert_success(&out, "profile run cpu check");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let cpu = parsed["metrics"]["cpu_insns"].as_u64().unwrap_or(0);
    assert_eq!(cpu, 150_000, "should parse cpuInsns=150000 from fixture");
}

#[test]
fn profile_run_from_manual_params_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "manual-test",
            "--cpu-insns",
            "500000",
            "--mem-bytes",
            "4096",
            "--write-entries",
            "2",
            "--event-count",
            "3",
        ])
        .output()
        .expect("spawn profile run manual");
    assert_success(&out, "profile run manual params");
}

#[test]
fn profile_run_with_no_params_produces_info_recommendation() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "empty-test",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile run empty");
    assert_success(&out, "profile run empty");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let empty_arr = vec![];
    let recs = parsed["optimization_report"]["recommendations"]
        .as_array()
        .unwrap_or(&empty_arr);
    let has_no_metrics_rec = recs
        .iter()
        .any(|r| r["rule_id"].as_str() == Some("no-metrics"));
    assert!(
        has_no_metrics_rec,
        "empty profile should have no-metrics recommendation"
    );
}

#[test]
fn profile_run_save_creates_baseline() {
    let home = isolated_home();
    // Save a baseline
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "save-test",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("spawn profile run --save");
    assert_success(&out, "profile run --save");

    // List should find it
    let list_out = starforge(home.path())
        .args([
            "profile",
            "list",
            "--label",
            "save-test",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile list");
    assert_success(&list_out, "profile list after save");
    let list_json = String::from_utf8_lossy(&list_out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&list_json).unwrap();
    assert!(
        parsed.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "baseline list should not be empty after save"
    );
}

#[test]
fn profile_run_with_flame_flag_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "flame-test",
            "--simulation-file",
            success_fixture().to_str().unwrap(),
            "--flame",
        ])
        .output()
        .expect("spawn profile run --flame");
    assert_success(&out, "profile run --flame");
}

#[test]
fn profile_run_heavy_fixture_produces_high_severity_recs() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "heavy-test",
            "--simulation-file",
            heavy_fixture().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile run heavy");
    assert_success(&out, "profile run heavy");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let counts = &parsed["optimization_report"]["severity_counts"];
    let high = counts["high"].as_u64().unwrap_or(0);
    let critical = counts["critical"].as_u64().unwrap_or(0);
    assert!(
        high + critical > 0,
        "heavy fixture should produce at least one high/critical recommendation"
    );
}

#[test]
fn profile_run_write_output_to_file() {
    let home = isolated_home();
    let out_file = home.path().join("profile_out.json");
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "file-out",
            "--cpu-insns",
            "100000",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("spawn profile run --output");
    assert_success(&out, "profile run --output file");
    assert!(out_file.exists(), "output file should have been created");
    let content = std::fs::read_to_string(&out_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed.get("metrics").is_some());
}

// ── Compare subcommand ────────────────────────────────────────────────────────

#[test]
fn profile_compare_two_baselines_exits_zero() {
    let home = isolated_home();
    // Save two baselines
    for fixture in [light_fixture(), success_fixture()] {
        let out = starforge(home.path())
            .args([
                "profile",
                "run",
                "--label",
                "cmp-test",
                "--simulation-file",
                fixture.to_str().unwrap(),
                "--save",
            ])
            .output()
            .expect("spawn profile run save for compare");
        assert_success(&out, "profile run --save for compare");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let out = starforge(home.path())
        .args([
            "profile", "compare", "--label", "cmp-test", "--format", "json",
        ])
        .output()
        .expect("spawn profile compare");
    assert_success(&out, "profile compare");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.get("comparison").is_some());
    assert!(parsed.get("delta").is_some() || parsed["comparison"].get("delta").is_some());
}

#[test]
fn profile_compare_too_few_baselines_returns_error() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["profile", "compare", "--label", "nonexistent-label"])
        .output()
        .expect("spawn profile compare no baseline");
    assert_failure(&out, "profile compare with no history should fail");
}

// ── Budget subcommand ─────────────────────────────────────────────────────────

#[test]
fn profile_budget_passes_when_under_limit() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "budget",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--max-cpu-insns",
            "1000000",
            "--max-mem-bytes",
            "1048576",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile budget passes");
    assert_success(&out, "profile budget under limit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["passed"], true);
}

#[test]
fn profile_budget_fails_when_over_cpu_limit() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "budget",
            "--simulation-file",
            heavy_fixture().to_str().unwrap(),
            "--max-cpu-insns",
            "1000",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile budget fails");
    // Should exit non-zero when budget exceeded
    assert_failure(&out, "profile budget over cpu limit should fail");
}

#[test]
fn profile_budget_json_reports_violations() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "budget",
            "--simulation-file",
            heavy_fixture().to_str().unwrap(),
            "--max-cpu-insns",
            "1000",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile budget json violations");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["passed"], false);
    let violations = parsed["violations"].as_array().unwrap();
    assert!(
        !violations.is_empty(),
        "violations array should be non-empty"
    );
    assert!(
        violations[0].as_str().unwrap().contains("CPU"),
        "violation should mention CPU"
    );
}

// ── Export subcommand ─────────────────────────────────────────────────────────

#[test]
fn profile_export_json_produces_valid_output() {
    let home = isolated_home();
    // Save a baseline first
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "export-test",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save baseline for export");

    let out = starforge(home.path())
        .args([
            "profile",
            "export",
            "--label",
            "export-test",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile export json");
    assert_success(&out, "profile export json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        parsed.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "export JSON should be a non-empty array"
    );
}

#[test]
fn profile_export_csv_contains_header() {
    let home = isolated_home();
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "csv-export-test",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save baseline for csv export");

    let out = starforge(home.path())
        .args([
            "profile",
            "export",
            "--label",
            "csv-export-test",
            "--format",
            "csv",
        ])
        .output()
        .expect("spawn profile export csv");
    assert_success(&out, "profile export csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("timestamp,label"),
        "CSV should start with header"
    );
    assert!(
        stdout.lines().count() >= 2,
        "CSV should have header + data row"
    );
}

// ── Check-regression subcommand ───────────────────────────────────────────────

#[test]
fn check_regression_passes_for_stable_profile() {
    let home = isolated_home();
    // Two nearly identical profiles
    for _ in 0..2 {
        starforge(home.path())
            .args([
                "profile",
                "run",
                "--label",
                "regression-stable",
                "--simulation-file",
                light_fixture().to_str().unwrap(),
                "--save",
            ])
            .output()
            .expect("save stable baseline");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let out = starforge(home.path())
        .args([
            "profile",
            "check-regression",
            "--label",
            "regression-stable",
            "--threshold",
            "50.0",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn check-regression stable");
    assert_success(&out, "check-regression stable");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["regressed"], false);
}

#[test]
fn check_regression_fails_for_regressed_profile() {
    let home = isolated_home();
    // First: save light profile as baseline
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "regression-bad",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save light baseline");
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Second: save heavy profile — massive regression
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "regression-bad",
            "--simulation-file",
            heavy_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save heavy baseline");

    let out = starforge(home.path())
        .args([
            "profile",
            "check-regression",
            "--label",
            "regression-bad",
            "--threshold",
            "5.0",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn check-regression regressed");
    assert_failure(&out, "check-regression should fail on regression");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["regressed"], true);
    assert!(
        !parsed["regression_details"]
            .as_array()
            .unwrap_or(&vec![])
            .is_empty(),
        "regression_details should be non-empty"
    );
}

#[test]
fn check_regression_passes_when_no_prior_baseline() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "check-regression",
            "--label",
            "brand-new-label-xyz",
        ])
        .output()
        .expect("spawn check-regression no prior");
    assert_success(&out, "check-regression no prior baseline");
}

// ── Flame subcommand ──────────────────────────────────────────────────────────

#[test]
fn profile_flame_exits_zero() {
    let home = isolated_home();
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "flame-subcommand-test",
            "--simulation-file",
            success_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save for flame");

    let out = starforge(home.path())
        .args(["profile", "flame", "--label", "flame-subcommand-test"])
        .output()
        .expect("spawn profile flame");
    assert_success(&out, "profile flame");
}

#[test]
fn profile_flame_json_is_valid() {
    let home = isolated_home();
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "flame-json-test",
            "--simulation-file",
            success_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save for flame json");

    let out = starforge(home.path())
        .args([
            "profile",
            "flame",
            "--label",
            "flame-json-test",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile flame json");
    assert_success(&out, "profile flame json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.get("contract_label").is_some());
    assert!(parsed.get("total_cpu_insns").is_some());
    assert!(parsed.get("rows").is_some());
}

// ── List subcommand ───────────────────────────────────────────────────────────

#[test]
fn profile_list_all_labels_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["profile", "list", "--format", "json"])
        .output()
        .expect("spawn profile list");
    assert_success(&out, "profile list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array(), "list output should be a JSON array");
}

#[test]
fn profile_list_specific_label_exits_zero_empty() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "list",
            "--label",
            "never-existed",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile list never-existed");
    assert_success(&out, "profile list nonexistent label");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        parsed.as_array().map(|a| a.is_empty()).unwrap_or(false),
        "list for unknown label should be empty array"
    );
}

// ── Compare with baseline-file ────────────────────────────────────────────────

#[test]
fn profile_compare_with_explicit_baseline_file() {
    let home = isolated_home();
    let baseline_snap_file = home.path().join("baseline_snap.json");

    // Save a baseline snapshot first
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "cmp-file-test",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("profile run save for compare file");

    // Export the snapshot to a standalone JSON file usable as --baseline-file
    let export_out = starforge(home.path())
        .args([
            "profile",
            "export",
            "--label",
            "cmp-file-test",
            "--format",
            "json",
        ])
        .output()
        .expect("export for compare file");
    assert_success(&export_out, "export for compare file");

    let export_json = String::from_utf8_lossy(&export_out.stdout);
    let arr: serde_json::Value = serde_json::from_str(&export_json).unwrap();
    let snap = serde_json::to_string_pretty(&arr[0]).unwrap();
    std::fs::write(&baseline_snap_file, snap).unwrap();

    // Compare using explicit --baseline-file and --candidate-file (both the same snap)
    let out = starforge(home.path())
        .args([
            "profile",
            "compare",
            "--label",
            "cmp-file-test",
            "--baseline-file",
            baseline_snap_file.to_str().unwrap(),
            "--candidate-file",
            baseline_snap_file.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile compare with file");
    assert_success(&out, "profile compare with explicit candidate file");
}

// ── Schema version ────────────────────────────────────────────────────────────

#[test]
fn profile_run_json_schema_version_is_1() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "schema-ver",
            "--cpu-insns",
            "100000",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn profile run schema ver");
    assert_success(&out, "profile schema version check");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let schema_v = parsed["metrics"]["schema_version"].as_u64().unwrap_or(0);
    assert_eq!(schema_v, 1, "schema_version must be 1");
}

// ── Baseline compare-inline ───────────────────────────────────────────────────

#[test]
fn profile_run_compare_baseline_inline() {
    let home = isolated_home();
    // Save first
    starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "inline-cmp",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--save",
        ])
        .output()
        .expect("save for inline compare");

    // Second run with --compare-baseline
    let out = starforge(home.path())
        .args([
            "profile",
            "run",
            "--label",
            "inline-cmp",
            "--simulation-file",
            light_fixture().to_str().unwrap(),
            "--compare-baseline",
            "--format",
            "json",
        ])
        .output()
        .expect("profile run --compare-baseline");
    assert_success(&out, "profile run --compare-baseline");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        parsed["baseline_comparison"].is_object(),
        "should contain baseline_comparison when --compare-baseline given"
    );
}
