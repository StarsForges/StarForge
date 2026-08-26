use mockito::{Matcher, Server};
use serde_json::Value;
use std::fs;
use std::process::{Command, Output};

fn starforge(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_starforge"))
        .arg("--quiet")
        .args(args)
        .env_remove("OPENAI_API_KEY")
        .env_remove("STARFORGE_QUERY_AI_API_KEY")
        .output()
        .expect("run starforge")
}

#[test]
fn plan_json_is_versioned_and_has_no_banner() {
    let output = starforge(&[
        "query",
        "plan",
        "what is the current ledger?",
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let plan: Value = serde_json::from_str(&stdout).expect("stdout is only JSON");
    assert_eq!(plan["schema_version"], "starforge.query-plan/v1");
    assert_eq!(plan["source"], "deterministic");
    assert_eq!(plan["operations"][0]["kind"], "latest_ledger");
}

#[test]
fn unsafe_question_has_nonzero_exit_and_actionable_error() {
    let output = starforge(&["query", "plan", "show my private key", "--format", "json"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unsafe query rejected"), "{stderr}");
    assert!(stderr.contains("public on-chain data"), "{stderr}");
}

#[test]
fn missing_ai_configuration_falls_back_without_network() {
    let output = starforge(&[
        "query",
        "plan",
        "what is the current ledger?",
        "--ai",
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["source"], "ai_fallback");
    assert!(plan["warnings"][0].as_str().unwrap().contains("API_KEY"));
}

#[test]
fn execute_uses_mocked_read_only_rpc_and_links_evidence() {
    let mut server = Server::new();
    let rpc = server
        .mock("POST", "/")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "method": "getLatestLedger",
            "params": {}
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"jsonrpc":"2.0","id":1,"result":{"sequence":98765}}"#)
        .create();
    let directory = tempfile::tempdir().unwrap();
    let plan_path = directory.path().join("plan.json");
    fs::write(
        &plan_path,
        include_str!("fixtures/query/latest-ledger-plan.json"),
    )
    .unwrap();

    let output = starforge(&[
        "query",
        "execute",
        plan_path.to_str().unwrap(),
        "--format",
        "json",
        "--rpc-url",
        &server.url(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    rpc.assert();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "starforge.query-report/v1");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["evidence"][0]["method"], "getLatestLedger");
    assert_eq!(report["findings"][0]["evidence_ids"][0], "evidence-1");
    assert_eq!(report["evidence"][0]["result"]["sequence"], 98765);
}

#[test]
fn incompatible_plan_version_is_rejected_before_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let plan_path = directory.path().join("old.json");
    let old = include_str!("fixtures/query/latest-ledger-plan.json")
        .replace("starforge.query-plan/v1", "starforge.query-plan/v0");
    fs::write(&plan_path, old).unwrap();
    let output = starforge(&[
        "query",
        "execute",
        plan_path.to_str().unwrap(),
        "--format",
        "json",
        "--dry-run",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unsupported query plan schema"));
}
