//! Deterministic CLI coverage for the context-aware assistant. These tests
//! never contact an external provider.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_starforge"));
    command.arg("-q");
    command.env_remove("OPENAI_API_KEY");
    command.env_remove("STARFORGE_AI_API_KEY");
    command.env("STARFORGE_AI_TELEMETRY", "0");
    command
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("assistant")
}

fn run_json(args: &[&str]) -> Value {
    let output = binary().args(args).output().expect("run starforge");
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn assistant_help_lists_all_workflows() {
    let output = binary()
        .args(["ai", "assistant", "--help"])
        .output()
        .expect("run help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "index", "explain", "diagnose", "suggest", "scaffold", "review",
    ] {
        assert!(stdout.contains(command), "missing {command} in help");
    }
}

#[test]
fn index_json_is_versioned_redacted_and_relative() {
    let root = fixture();
    let value = run_json(&[
        "ai",
        "assistant",
        "index",
        "--root",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--no-persist",
    ]);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["persisted"], false);
    assert!(value["summary"]["files_indexed"].as_u64().unwrap() >= 5);
    assert!(value["summary"]["redactions"].as_u64().unwrap() >= 1);
    for entry in value["entries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        assert!(!path.starts_with('/'));
        assert!(!path.contains("nanle"));
    }
    assert!(!value.to_string().contains("sk-fixture-secret"));
}

#[test]
fn offline_review_has_stable_machine_readable_findings() {
    let root = fixture();
    let value = run_json(&[
        "ai",
        "assistant",
        "review",
        "review authorization and persistent storage",
        "--root",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--offline",
        "--no-persist",
    ]);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["workflow"], "review");
    assert_eq!(value["mode"], "offline");
    assert_eq!(value["privacy"]["provider_contacted"], false);
    assert_eq!(value["privacy"]["absolute_paths_shared"], false);
    let titles: Vec<&str> = value["guidance"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["title"].as_str())
        .collect();
    assert!(titles.iter().any(|title| title.contains("panic")));
    assert!(titles.iter().any(|title| title.contains("authorization")));
}

#[test]
fn prompt_preview_is_redacted_and_does_not_contact_provider() {
    let root = fixture();
    let value = run_json(&[
        "ai",
        "assistant",
        "diagnose",
        "api_key = sk-user-supplied-secret-value",
        "--root",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--preview",
        "--no-persist",
    ]);
    assert_eq!(value["mode"], "preview");
    assert_eq!(value["privacy"]["provider_contacted"], false);
    assert!(
        value["prompt_preview"]["estimated_input_tokens"]
            .as_u64()
            .unwrap()
            > 0
    );
    let serialized = value.to_string();
    assert!(!serialized.contains("sk-user-supplied"));
    assert!(!serialized.contains("sk-fixture-secret"));
    assert!(serialized.contains("[REDACTED]"));
}

#[test]
fn missing_provider_configuration_falls_back_successfully() {
    let root = fixture();
    let value = run_json(&[
        "ai",
        "assistant",
        "explain",
        "explain the token contract",
        "--root",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--no-persist",
    ]);
    assert_eq!(value["mode"], "fallback");
    assert_eq!(value["privacy"]["provider_contacted"], false);
    assert_eq!(value["provider"]["name"], "starforge-local");
    assert!(value["provider"]["fallback_reason"]
        .as_str()
        .unwrap()
        .contains("provider not configured"));
}

#[test]
fn exclusion_removes_matching_context() {
    let root = fixture();
    let value = run_json(&[
        "ai",
        "assistant",
        "index",
        "--root",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--exclude",
        "tests",
        "--no-persist",
    ]);
    assert!(value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| !entry["path"].as_str().unwrap().starts_with("tests/")));
}
