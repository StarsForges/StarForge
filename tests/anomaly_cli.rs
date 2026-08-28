//! End-to-end CLI tests for real-time anomaly detection (`starforge anomaly ...`).
//! All tests use fixtures under tests/fixtures/anomaly/ or synthetic
//! WindowMetrics JSON; no external network calls are made.

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn isolated_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("create isolated home")
}

fn starforge(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_starforge"));
    cmd.arg("-q");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    // Disable AI calls in all tests so output is deterministic.
    cmd.env("OPENAI_API_KEY", "");
    cmd.env_remove("STARFORGE_AI_API_KEY");
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

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/anomaly")
        .join(name)
}

/// Generates a fresh, valid-looking 56-char contract id (charset `A-Z2-7`,
/// per `config::validate_contract_id`) for each test. Baseline/alert
/// persistence is keyed by contract id, so giving every test its own id
/// keeps tests independent even if `$HOME` isolation is ever imperfect for a
/// given platform — home directory resolution (`dirs::home_dir`) is
/// OS-specific and StarForge CI only exercises Linux, so this keeps local
/// verification on any platform meaningful too.
fn unique_contract() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut n = (COUNTER.fetch_add(1, Ordering::SeqCst) as u64)
        .wrapping_mul(2_654_435_761)
        .wrapping_add(std::process::id() as u64);
    let mut suffix = Vec::with_capacity(12);
    for _ in 0..12 {
        suffix.push(ALPHABET[(n % ALPHABET.len() as u64) as usize]);
        n /= ALPHABET.len() as u64;
    }
    let mut id = String::from("C");
    id.push_str(std::str::from_utf8(&suffix).unwrap());
    while id.len() < 56 {
        id.push('A');
    }
    id.truncate(56);
    id
}

// ── Help and discovery ────────────────────────────────────────────────────────

#[test]
fn anomaly_help_lists_subcommands() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["anomaly", "--help"])
        .output()
        .expect("spawn anomaly --help");
    assert_success(&out, "anomaly --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["monitor", "baseline", "alert-test", "export", "report"] {
        assert!(
            stdout.contains(sub),
            "help should list '{}' subcommand",
            sub
        );
    }
}

#[test]
fn anomaly_monitor_help_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["anomaly", "monitor", "--help"])
        .output()
        .expect("spawn anomaly monitor --help");
    assert_success(&out, "anomaly monitor --help");
}

#[test]
fn anomaly_baseline_help_exits_zero() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args(["anomaly", "baseline", "--help"])
        .output()
        .expect("spawn anomaly baseline --help");
    assert_success(&out, "anomaly baseline --help");
}

#[test]
fn anomaly_rejects_invalid_contract_id() {
    let home = isolated_home();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            "not-a-valid-contract",
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_failure(&out, "anomaly monitor with invalid contract id");
}

// ── Monitor (fixture replay) ────────────────────────────────────────────────

#[test]
fn monitor_with_normal_events_reports_no_anomalies() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
            "--no-persist",
            "--deterministic",
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_success(&out, "anomaly monitor (normal events)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No anomalies detected"));
}

#[test]
fn monitor_with_volume_spike_detects_anomaly_via_cold_start_fallback() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_spike.json").to_str().unwrap(),
            "--no-persist",
            "--deterministic",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_success(&out, "anomaly monitor (volume spike)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("expected valid JSON, got error {}: {}", e, stdout));
    let alerts = parsed["alerts"].as_array().expect("alerts array");
    assert!(!alerts.is_empty(), "expected at least one anomaly alert");
    assert!(alerts
        .iter()
        .any(|a| a["kind"] == "volume_spike" && a["used_fallback_threshold"] == true));
}

#[test]
fn monitor_fail_on_severity_exits_nonzero_when_matched() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_spike.json").to_str().unwrap(),
            "--no-persist",
            "--deterministic",
            "--fail-on",
            "low",
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_failure(&out, "anomaly monitor --fail-on low with anomalies present");
}

#[test]
fn monitor_fail_on_severity_is_silent_when_clean() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
            "--no-persist",
            "--deterministic",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_success(&out, "anomaly monitor --fail-on critical with no anomalies");
}

#[test]
fn monitor_merges_transaction_outcomes() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
            "--transactions-file",
            fixture("transactions_errors.json").to_str().unwrap(),
            "--no-persist",
            "--deterministic",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_success(&out, "anomaly monitor with transactions file");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // 3 normal events (success) + 2 failed / 1 successful tx merged in.
    assert_eq!(parsed["window"]["error_count"], 2);
}

#[test]
fn monitor_follow_incompatible_with_fixtures() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "monitor",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
            "--follow",
        ])
        .output()
        .expect("spawn anomaly monitor");
    assert_failure(&out, "anomaly monitor --follow with fixtures");
}

// ── Baseline ─────────────────────────────────────────────────────────────────

#[test]
fn baseline_update_then_show_round_trips() {
    let home = isolated_home();
    let contract = unique_contract();
    let update = starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "update",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
        ])
        .output()
        .expect("spawn baseline update");
    assert_success(&update, "baseline update");

    let show = starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "show",
            "--contract",
            contract.as_str(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn baseline show");
    assert_success(&show, "baseline show");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&show.stdout)).unwrap();
    assert_eq!(parsed["sample_count"], 1);
}

#[test]
fn baseline_show_without_update_fails_clearly() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "show",
            "--contract",
            contract.as_str(),
        ])
        .output()
        .expect("spawn baseline show");
    assert_failure(&out, "baseline show with no baseline saved");
}

#[test]
fn baseline_reset_requires_confirmation() {
    let home = isolated_home();
    let contract = unique_contract();
    starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "update",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
        ])
        .output()
        .expect("spawn baseline update");

    let without_yes = starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "reset",
            "--contract",
            contract.as_str(),
        ])
        .output()
        .expect("spawn baseline reset");
    assert_failure(&without_yes, "baseline reset without --yes");

    let with_yes = starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "reset",
            "--contract",
            contract.as_str(),
            "--yes",
        ])
        .output()
        .expect("spawn baseline reset --yes");
    assert_success(&with_yes, "baseline reset --yes");
}

#[test]
fn baseline_list_reports_saved_baselines() {
    let home = isolated_home();
    let contract = unique_contract();
    starforge(home.path())
        .args([
            "anomaly",
            "baseline",
            "update",
            "--contract",
            contract.as_str(),
            "--events-file",
            fixture("events_normal.json").to_str().unwrap(),
        ])
        .output()
        .expect("spawn baseline update");

    let list = starforge(home.path())
        .args(["anomaly", "baseline", "list", "--format", "json"])
        .output()
        .expect("spawn baseline list");
    assert_success(&list, "baseline list");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&list.stdout)).unwrap();
    let entries = parsed.as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|b| b["contract_id"] == contract.as_str()),
        "expected {} to appear in baseline list: {:?}",
        contract,
        entries
    );
}

// ── alert-test ───────────────────────────────────────────────────────────────

#[test]
fn alert_test_clean_window_reports_nothing() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            fixture("window_metrics_clean.json").to_str().unwrap(),
        ])
        .output()
        .expect("spawn alert-test");
    assert_success(&out, "alert-test (clean)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("no anomalies detected"));
}

#[test]
fn alert_test_critical_window_detects_multiple_anomaly_kinds() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            fixture("window_metrics_critical.json").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn alert-test");
    assert_success(&out, "alert-test (critical)");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let alerts = parsed["alerts"].as_array().unwrap();
    assert!(alerts.len() >= 3, "expected several anomaly kinds to fire");
    let kinds: Vec<&str> = alerts.iter().map(|a| a["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"suspicious_payload"));
    assert!(kinds.contains(&"health_degradation"));
}

#[test]
fn alert_test_fail_on_gates_ci() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            fixture("window_metrics_critical.json").to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("spawn alert-test");
    assert_failure(
        &out,
        "alert-test --fail-on critical with critical alerts present",
    );
}

#[test]
fn alert_test_persist_then_export_contains_alert() {
    let home = isolated_home();
    let contract = unique_contract();
    let persisted = starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            fixture("window_metrics_critical.json").to_str().unwrap(),
            "--persist",
        ])
        .output()
        .expect("spawn alert-test --persist");
    assert_success(&persisted, "alert-test --persist");

    let export = starforge(home.path())
        .args([
            "anomaly",
            "export",
            "--contract",
            contract.as_str(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn anomaly export");
    assert_success(&export, "anomaly export");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&export.stdout)).unwrap();
    assert!(!parsed.as_array().unwrap().is_empty());
}

#[test]
fn alert_test_rejects_malformed_metrics_file() {
    let home = isolated_home();
    let contract = unique_contract();
    let bad_file = home.path().join("bad.json");
    std::fs::write(&bad_file, "{ not valid json").unwrap();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            bad_file.to_str().unwrap(),
        ])
        .output()
        .expect("spawn alert-test");
    assert_failure(&out, "alert-test with malformed metrics file");
}

// ── export / report ──────────────────────────────────────────────────────────

#[test]
fn export_with_no_history_returns_empty_array() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "export",
            "--contract",
            contract.as_str(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn anomaly export");
    assert_success(&out, "anomaly export with no history");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn export_csv_format_has_header() {
    let home = isolated_home();
    let contract = unique_contract();
    starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            fixture("window_metrics_critical.json").to_str().unwrap(),
            "--persist",
        ])
        .output()
        .expect("spawn alert-test --persist");

    let out = starforge(home.path())
        .args([
            "anomaly",
            "export",
            "--contract",
            contract.as_str(),
            "--format",
            "csv",
        ])
        .output()
        .expect("spawn anomaly export csv");
    assert_success(&out, "anomaly export csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("timestamp,contract_id,network"));
}

#[test]
fn report_with_no_alerts_is_still_a_valid_markdown_report() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "report",
            "--contract",
            contract.as_str(),
            "--deterministic",
        ])
        .output()
        .expect("spawn anomaly report");
    assert_success(&out, "anomaly report (empty history)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Anomaly Incident Report"));
    assert!(stdout.contains("No anomalies were detected"));
}

#[test]
fn report_json_format_after_persisted_alert_is_valid() {
    let home = isolated_home();
    let contract = unique_contract();
    starforge(home.path())
        .args([
            "anomaly",
            "alert-test",
            "--contract",
            contract.as_str(),
            "--metrics-file",
            fixture("window_metrics_critical.json").to_str().unwrap(),
            "--persist",
        ])
        .output()
        .expect("spawn alert-test --persist");

    let out = starforge(home.path())
        .args([
            "anomaly",
            "report",
            "--contract",
            contract.as_str(),
            "--format",
            "json",
            "--deterministic",
        ])
        .output()
        .expect("spawn anomaly report json");
    assert_success(&out, "anomaly report json");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(parsed["stats"]["total"].as_u64().unwrap() > 0);
    assert!(parsed["ai_narrative"].is_null());
}

#[test]
fn report_rejects_non_positive_since_hours() {
    let home = isolated_home();
    let contract = unique_contract();
    let out = starforge(home.path())
        .args([
            "anomaly",
            "report",
            "--contract",
            contract.as_str(),
            "--since-hours",
            "0",
        ])
        .output()
        .expect("spawn anomaly report");
    assert_failure(&out, "anomaly report --since-hours 0");
}
