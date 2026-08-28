//! CLI end-to-end coverage for safe account signer rotation.  Every test uses
//! committed deterministic policy evidence and opens no network connection.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/signer_rotation")
        .join(name)
}

fn starforge(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_starforge"));
    command.arg("-q");
    command.env("HOME", home);
    command.env("USERPROFILE", home);
    command
}

fn success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn account_help_exposes_required_workflows() {
    let home = tempfile::tempdir().unwrap();
    let account = starforge(home.path())
        .args(["account", "--help"])
        .output()
        .unwrap();
    success(&account, "account help");
    let text = String::from_utf8_lossy(&account.stdout);
    assert!(text.contains("signers"));
    assert!(text.contains("rotation"));

    let rotation = starforge(home.path())
        .args(["account", "rotation", "--help"])
        .output()
        .unwrap();
    success(&rotation, "rotation help");
    let text = String::from_utf8_lossy(&rotation.stdout);
    for command in ["plan", "execute", "resume", "verify"] {
        assert!(text.contains(command), "missing {command} in rotation help");
    }
}

#[test]
fn inspect_fixture_emits_stable_json_and_restricted_policy() {
    let home = tempfile::tempdir().unwrap();
    let output_path = home.path().join("normalized.json");
    let output = starforge(home.path())
        .args([
            "account",
            "signers",
            "inspect",
            "--input",
            fixture("current.json").to_str().unwrap(),
            "--availability",
            fixture("availability.json").to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    success(&output, "fixture inspect");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "account.signers.inspect");
    assert_eq!(value["policy"]["master_key"]["availability"], "hardware");
    assert_eq!(value["safety"]["operable"], true);
    assert!(output_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(output_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn plan_orders_introduction_and_verification_before_removal() {
    let home = tempfile::tempdir().unwrap();
    let plan_path = home.path().join("rotation-plan.json");
    let output = starforge(home.path())
        .args([
            "account",
            "rotation",
            "plan",
            "--current",
            fixture("current.json").to_str().unwrap(),
            "--target",
            fixture("target.json").to_str().unwrap(),
            "--output",
            plan_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    success(&output, "rotation plan");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "account.rotation.plan");
    assert!(value["plan"]["summary"]["envelopes"].as_u64().unwrap() >= 4);
    assert!(
        value["plan"]["emergency_rollback"]["steps"]
            .as_array()
            .unwrap()
            .len()
            >= 4
    );

    let steps = value["plan"]["steps"].as_array().unwrap();
    let add = steps
        .iter()
        .position(|step| step["summary"].as_str().unwrap().contains("introduce"))
        .unwrap();
    let challenge = steps
        .iter()
        .position(|step| step["summary"].as_str().unwrap().contains("verify control"))
        .unwrap();
    let removal = steps
        .iter()
        .position(|step| step["summary"].as_str().unwrap().contains("remove signer"))
        .unwrap();
    assert!(add < challenge && challenge < removal);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(plan_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn planner_rejects_lockout_target_without_writing_plan() {
    let home = tempfile::tempdir().unwrap();
    let plan_path = home.path().join("unsafe.json");
    let output = starforge(home.path())
        .args([
            "account",
            "rotation",
            "plan",
            "--current",
            fixture("current.json").to_str().unwrap(),
            "--target",
            fixture("locked_target.json").to_str().unwrap(),
            "--output",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("lockout state"));
    assert!(!plan_path.exists());
}

#[test]
fn offline_execute_creates_all_handoffs_and_resumable_state() {
    let home = tempfile::tempdir().unwrap();
    let plan_path = home.path().join("plan.json");
    let state_path = home.path().join("state.json");
    let handoffs = home.path().join("handoff");
    let planned = starforge(home.path())
        .args([
            "account",
            "rotation",
            "plan",
            "--current",
            fixture("current.json").to_str().unwrap(),
            "--target",
            fixture("target.json").to_str().unwrap(),
            "--output",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    success(&planned, "prepare plan");

    let executed = starforge(home.path())
        .args([
            "account",
            "rotation",
            "execute",
            "--plan",
            plan_path.to_str().unwrap(),
            "--state",
            state_path.to_str().unwrap(),
            "--handoff-dir",
            handoffs.to_str().unwrap(),
            "--observed-policy",
            fixture("current.json").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    success(&executed, "offline execute");
    let report: Value = serde_json::from_slice(&executed.stdout).unwrap();
    assert_eq!(
        report["execution"]["status"],
        Value::String("awaiting_approval".to_string())
    );
    assert_eq!(report["execution"]["completed_steps"], 0);
    let state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["status"], "awaiting_approval");
    assert!(handoffs.join("approvals.template.json").exists());
    assert!(fs::read_dir(&handoffs).unwrap().count() >= 6);
}

#[test]
fn verify_mismatch_has_nonzero_exit_and_fingerprints() {
    let home = tempfile::tempdir().unwrap();
    let plan_path = home.path().join("plan.json");
    let planned = starforge(home.path())
        .args([
            "account",
            "rotation",
            "plan",
            "--current",
            fixture("current.json").to_str().unwrap(),
            "--target",
            fixture("target.json").to_str().unwrap(),
            "--output",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    success(&planned, "prepare plan");
    let verified = starforge(home.path())
        .args([
            "account",
            "rotation",
            "verify",
            "--plan",
            plan_path.to_str().unwrap(),
            "--observed-policy",
            fixture("current.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!verified.status.success());
    let error = String::from_utf8_lossy(&verified.stderr);
    assert!(error.contains("does not match plan target"));
    assert!(!error.contains("SAAAA"));
}
