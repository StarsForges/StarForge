use mockito::{Matcher, Server};
use serde_json::Value;
use std::fs;
use std::process::{Command, Output};

fn starforge(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_starforge"))
        .arg("--quiet")
        .args(args)
        .env("HOME", home)
        .output()
        .expect("run starforge")
}

#[test]
fn matrix_json_is_stable_versioned_and_banner_free() {
    let home = tempfile::tempdir().unwrap();
    let output = starforge(
        home.path(),
        &["compatibility", "matrix", "--format", "json"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let matrix: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(matrix["schema_version"], 1);
    assert_eq!(matrix["matrix_version"], "2026-08-28");
    assert_eq!(matrix["xdr"]["protocol"]["maximum"], 22);
    assert!(matrix["features"].as_array().unwrap().len() >= 5);
}

#[test]
fn old_and_future_protocols_are_reported_as_incompatible() {
    let home = tempfile::tempdir().unwrap();
    for (protocol, code) in [(19, "protocol.too_old"), (99, "protocol.future_unverified")] {
        let output = starforge(
            home.path(),
            &[
                "compatibility",
                "status",
                "--protocol-version",
                &protocol.to_string(),
                "--format",
                "json",
            ],
        );
        assert!(output.status.success());
        let status: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["level"], "incompatible");
        assert!(status["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == code));
    }
}

#[test]
fn probe_uses_deterministic_rpc_and_redacts_endpoint_secrets() {
    let mut server = Server::new();
    let responses = [
        (
            "rpc.discover",
            include_str!("fixtures/compatibility/rpc_discover_vendor.json"),
        ),
        (
            "getNetwork",
            include_str!("fixtures/compatibility/get_network.json"),
        ),
        (
            "getLatestLedger",
            include_str!("fixtures/compatibility/get_latest_ledger.json"),
        ),
        (
            "getHealth",
            include_str!("fixtures/compatibility/get_health.json"),
        ),
        (
            "getVersionInfo",
            include_str!("fixtures/compatibility/get_version_info.json"),
        ),
    ];
    let mocks: Vec<_> = responses
        .into_iter()
        .map(|(method, response)| {
            server
                .mock("POST", "/rpc")
                .match_query(Matcher::Any)
                .match_body(Matcher::PartialJson(serde_json::json!({"method": method})))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(response)
                .create()
        })
        .collect();
    let home = tempfile::tempdir().unwrap();
    let rpc_url = format!("{}/rpc?api_key=TOP_SECRET", server.url());
    let output = starforge(
        home.path(),
        &[
            "compatibility",
            "probe",
            "--rpc-url",
            &rpc_url,
            "--no-cache",
            "--format",
            "json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for mock in mocks {
        mock.assert();
    }
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("TOP_SECRET"));
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["source"], "network");
    assert_eq!(report["status"]["protocol_version"], 22);
    assert_eq!(report["status"]["endpoint"]["retention_window"], 1000);
    assert!(report["status"]["endpoint"]["vendor_extensions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|method| method == "vendor.traceLedger"));
}

#[test]
fn audit_has_deterministic_gate_and_export_is_private() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname='audit-me'\nversion='0.1.0'\n[dependencies]\nstellar-xdr='22'\n",
    )
    .unwrap();
    fs::write(project.path().join("contract.wasm"), b"\0asm\x01\0\0\0").unwrap();
    fs::write(
        project.path().join("transaction.json"),
        r#"{"protocol_version":99,"jsonrpc":"2.0","method":"sendTransaction"}"#,
    )
    .unwrap();
    let output = starforge(
        home.path(),
        &[
            "compatibility",
            "audit",
            "--path",
            project.path().to_str().unwrap(),
            "--fail-on",
            "incompatible",
            "--format",
            "json",
        ],
    );
    assert!(!output.status.success());
    let audit: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(audit["schema_version"], 1);
    assert_eq!(audit["level"], "incompatible");

    let export_path = project.path().join("compatibility-export.json");
    let export = starforge(
        home.path(),
        &[
            "compatibility",
            "export",
            "--protocol-version",
            "22",
            "--output",
            export_path.to_str().unwrap(),
        ],
    );
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let bundle: Value = serde_json::from_slice(&fs::read(&export_path).unwrap()).unwrap();
    assert_eq!(bundle["schema_version"], 1);
    assert_eq!(bundle["status"]["protocol_version"], 22);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(export_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn compatibility_help_lists_complete_workflow() {
    let home = tempfile::tempdir().unwrap();
    let output = starforge(home.path(), &["compatibility", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in ["status", "probe", "matrix", "audit", "export"] {
        assert!(help.contains(command), "missing {command} in help: {help}");
    }
}
