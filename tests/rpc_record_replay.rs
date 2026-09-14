//! Comprehensive test suite for StarForge Privacy-Safe RPC Traffic Recording,
//! Redaction, and Deterministic Replay (Issue #87).
//!
//! Covers:
//! - Versioned recording schema, serialization, and migration (v0 -> v1)
//! - Multi-stage field-aware redaction: Stellar seeds, Bearer tokens, passwords,
//!   local paths, account identifiers (preserve, mask, pseudonymize)
//! - Redaction evasion defenses: nested JSON strings, Base64-encoded secrets
//! - Deterministic replay engine: exact, normalized, causal vs unordered matching
//! - Fault injection: delays, HTTP 429 rate limits, RPC error codes, malformed payloads
//! - Verification engine: cryptographic SHA-256 digest validation, causal chain
//!   integrity, secret leak detection, and permissions
//! - End-to-end CLI commands: `inspect`, `sanitize`, `verify`, and `replay`

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};
use starforge::utils::rpc_recording::fault::{FaultRule, FaultSuite, FaultType};
use starforge::utils::rpc_recording::redaction::{
    AccountRedactionStrategy, RedactionConfig, Redactor,
};
use starforge::utils::rpc_recording::replay::{
    ReplayEngine, ReplayMode, ReplayNormalization, ReplayOutcome, ReplayServer,
};
use starforge::utils::rpc_recording::save_recording;
use starforge::utils::rpc_recording::types::{
    EndpointMetadata, RecordedExchange, RecordedRequest, RecordedResponse, RecordingSession,
    TimingInfo, CURRENT_SCHEMA_VERSION,
};
use starforge::utils::rpc_recording::verifier::SessionVerifier;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

// ============================================================================
// CLI Test Helpers
// ============================================================================

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
        "{} failed (status: {:?}):\nstdout:\n{}\nstderr:\n{}",
        cmd,
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

// ============================================================================
// Session Fixture Generator
// ============================================================================

fn create_sample_session() -> RecordingSession {
    let endpoint = EndpointMetadata {
        upstream_url: "https://soroban-testnet.stellar.org".to_string(),
        network_passphrase: Some("Test SDF Network ; September 2015".to_string()),
        protocol: "JSON-RPC 2.0".to_string(),
        sanitized_headers: std::collections::HashMap::new(),
        user_agent: Some("starforge-test/0.1.0".to_string()),
    };

    let mut session = RecordingSession::new(endpoint);

    // Exchange 0: getHealth
    session.add_exchange(RecordedExchange {
        exchange_id: Uuid::new_v4().to_string(),
        sequence_id: 0,
        parent_id: None,
        timing: TimingInfo {
            started_at_ms: 1700000000000,
            completed_at_ms: 1700000000045,
            duration_ms: 45,
        },
        request: RecordedRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: std::collections::HashMap::new(),
            jsonrpc_method: "getHealth".to_string(),
            jsonrpc_id: json!(1),
            params: json!([]),
            raw_body_hash: "hash_0".to_string(),
        },
        response: RecordedResponse {
            status_code: 200,
            headers: std::collections::HashMap::new(),
            body: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "status": "healthy" }
            }),
            is_error: false,
            raw_body_hash: "hash_res_0".to_string(),
        },
        exchange_digest: String::new(),
    });

    // Exchange 1: getLatestLedger
    session.add_exchange(RecordedExchange {
        exchange_id: Uuid::new_v4().to_string(),
        sequence_id: 1,
        parent_id: None,
        timing: TimingInfo {
            started_at_ms: 1700000000100,
            completed_at_ms: 1700000000160,
            duration_ms: 60,
        },
        request: RecordedRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: std::collections::HashMap::new(),
            jsonrpc_method: "getLatestLedger".to_string(),
            jsonrpc_id: json!(2),
            params: json!([]),
            raw_body_hash: "hash_1".to_string(),
        },
        response: RecordedResponse {
            status_code: 200,
            headers: std::collections::HashMap::new(),
            body: json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "id": "abc123ledger",
                    "sequence": 42000,
                    "protocolVersion": 22
                }
            }),
            is_error: false,
            raw_body_hash: "hash_res_1".to_string(),
        },
        exchange_digest: String::new(),
    });

    session
}

// ============================================================================
// Unit & Domain Tests
// ============================================================================

#[test]
fn test_versioned_recording_schema_and_migration() {
    let session = create_sample_session();
    assert_eq!(session.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(session.exchanges.len(), 2);
    assert!(session.verify_digests().is_ok());

    // Serialize and deserialize
    let json_val = serde_json::to_value(&session).unwrap();
    let parsed = RecordingSession::from_json_value_migrated(json_val).unwrap();
    assert_eq!(parsed.session_id, session.session_id);
    assert_eq!(parsed.exchanges.len(), 2);

    // Test migration from legacy unversioned format (schema_version = 0)
    let legacy_json = json!({
        "session_id": "legacy-session-999",
        "created_at": "2026-01-01T00:00:00Z",
        "exchanges": [
            {
                "exchange_id": "ex-1",
                "timing": { "started_at_ms": 100, "completed_at_ms": 120, "duration_ms": 20 },
                "request": {
                    "method": "POST",
                    "path": "/",
                    "jsonrpc_method": "getHealth",
                    "jsonrpc_id": 1,
                    "params": []
                },
                "response": {
                    "status_code": 200,
                    "body": { "status": "ok" },
                    "is_error": false
                },
                "exchange_digest": ""
            }
        ]
    });

    let migrated = RecordingSession::from_json_value_migrated(legacy_json).unwrap();
    assert_eq!(migrated.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(migrated.session_id, "legacy-session-999");
    assert_eq!(migrated.exchanges[0].sequence_id, 0);
    assert!(!migrated.session_digest.is_empty());
    assert!(migrated.verify_digests().is_ok());

    // Rejection of future unknown schema version
    let future_json = json!({
        "schema_version": 99,
        "session_id": "future-session",
        "exchanges": []
    });
    assert!(RecordingSession::from_json_value_migrated(future_json).is_err());
}

#[test]
fn test_field_aware_redaction_secrets_and_paths() {
    let config = RedactionConfig {
        account_strategy: AccountRedactionStrategy::Preserve,
        ..Default::default()
    };
    let redactor = Redactor::new(config).unwrap();

    let mut payload = json!({
        "secret_seed": "SDNMALMR3V46C5S22D6OISCL6CCB4SCLW7Q6C6WOG62OEDOIFCTZFF2B",
        "account": "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
        "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_payload",
        "local_debug_file": "/home/developer/starforge/keys/secret.txt",
        "nested": {
            "password": "SuperSecretPassword123!",
            "note": "Config loaded from /Users/alice/projects/app.conf"
        }
    });

    let (summary, events) = redactor.redact_value(&mut payload, "root");

    assert!(summary.secrets_redacted_count >= 3);
    assert!(summary.paths_redacted_count >= 2);
    assert!(!events.is_empty());

    // Verify secret seed is redacted
    let seed_str = payload["secret_seed"].as_str().unwrap();
    assert_eq!(seed_str, "[REDACTED_SECRET]");

    // Verify bearer auth header pattern is redacted
    let auth_str = payload["auth_header"].as_str().unwrap();
    assert!(auth_str.contains("[REDACTED_TOKEN]") || auth_str == "[REDACTED_SECRET]");

    // Verify password is redacted
    assert_eq!(payload["nested"]["password"], "[REDACTED_SECRET]");

    // Verify paths are redacted
    let path_str = payload["local_debug_file"].as_str().unwrap();
    assert!(path_str.contains("[REDACTED_LOCAL_PATH]"));

    let note_str = payload["nested"]["note"].as_str().unwrap();
    assert!(note_str.contains("[REDACTED_LOCAL_PATH]"));

    // Verify public account address is preserved per config
    assert_eq!(
        payload["account"],
        "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
    );
}

#[test]
fn test_account_redaction_strategies() {
    let account = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    // 1. Mask strategy
    let cfg_mask = RedactionConfig {
        account_strategy: AccountRedactionStrategy::Mask,
        ..Default::default()
    };
    let redactor_mask = Redactor::new(cfg_mask).unwrap();

    let mut val1 = json!({ "target": account });
    redactor_mask.redact_value(&mut val1, "root");
    assert_eq!(val1["target"], "[REDACTED_ACCOUNT]");

    // 2. Pseudonymize strategy
    let cfg_pseudo = RedactionConfig {
        account_strategy: AccountRedactionStrategy::Pseudonymize,
        ..Default::default()
    };
    let redactor_pseudo = Redactor::new(cfg_pseudo).unwrap();

    let mut val2 = json!({ "target": account });
    redactor_pseudo.redact_value(&mut val2, "root");
    let pseudo_str = val2["target"].as_str().unwrap();
    assert!(pseudo_str.starts_with("GPSEUDO_"));
    assert_ne!(pseudo_str, account);
    assert_eq!(pseudo_str.len(), account.len());
}

#[test]
fn test_redaction_evasion_defenses() {
    let config = RedactionConfig {
        inspect_base64: true,
        ..Default::default()
    };
    let redactor = Redactor::new(config).unwrap();

    // 1. Base64 payload containing secret seed
    let raw_secret = "key=SDNMALMR3V46C5S22D6OISCL6CCB4SCLW7Q6C6WOG62OEDOIFCTZFF2B";
    let encoded = BASE64.encode(raw_secret);
    let mut val_b64 = json!({ "blob": encoded });
    redactor.redact_value(&mut val_b64, "root");

    let redacted_b64 = val_b64["blob"].as_str().unwrap();
    let decoded = String::from_utf8(BASE64.decode(redacted_b64).unwrap()).unwrap();
    assert!(!decoded.contains("SDNMALMR3V46C5S22D6OISCL6CCB4SCLW7Q6C6WOG62OEDOIFCTZFF2B"));
    assert!(decoded.contains("[REDACTED_STELLAR_SEED]"));

    // 2. Embedded stringified JSON inside params
    let inner_json = r#"{"internal_path":"/home/bob/secret.key","nested_key":"12345"}"#;
    let mut val_nested = json!({ "payload": inner_json });
    redactor.redact_value(&mut val_nested, "root");
    let res_inner = val_nested["payload"].as_str().unwrap();
    assert!(!res_inner.contains("/home/bob/secret.key"));
    assert!(res_inner.contains("[REDACTED_LOCAL_PATH]"));
}

#[test]
fn test_deterministic_replay_matching_and_normalization() {
    let session = create_sample_session();
    let engine = ReplayEngine::new(
        session,
        ReplayMode::Unordered,
        ReplayNormalization::default(),
        FaultSuite::new(),
        false,
    );

    // Exact match with different client ID
    let client_id = json!(9999);
    let outcome = engine.handle_request("getHealth", &client_id, &json!([]));
    match outcome {
        ReplayOutcome::Success {
            response_body,
            status_code,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(response_body["id"], 9999);
            assert_eq!(response_body["result"]["status"], "healthy");
        }
        other => panic!("Expected Success, got {:?}", other),
    }

    // Normalized match ignoring volatile fields (timestamp, nonce)
    let outcome_ledger = engine.handle_request(
        "getLatestLedger",
        &json!("req-abc"),
        &json!({ "timestamp": 1234567, "nonce": 42 }),
    );
    match outcome_ledger {
        ReplayOutcome::Success {
            response_body,
            status_code,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(response_body["id"], "req-abc");
            assert_eq!(response_body["result"]["sequence"], 42000);
        }
        other => panic!("Expected Success for normalized request, got {:?}", other),
    }

    // Unmatched method
    let outcome_unknown = engine.handle_request("nonExistentMethod", &json!(1), &json!([]));
    assert!(matches!(outcome_unknown, ReplayOutcome::Unmatched { .. }));
}

#[test]
fn test_causal_replay_mode() {
    let session = create_sample_session();
    let engine = ReplayEngine::new(
        session,
        ReplayMode::Causal,
        ReplayNormalization::default(),
        FaultSuite::new(),
        true,
    );

    // 1st request must be getHealth (sequence 0)
    let outcome1 = engine.handle_request("getHealth", &json!(1), &json!([]));
    assert!(matches!(outcome1, ReplayOutcome::Success { .. }));

    // 2nd request must be getLatestLedger (sequence 1)
    let outcome2 = engine.handle_request("getLatestLedger", &json!(2), &json!([]));
    assert!(matches!(outcome2, ReplayOutcome::Success { .. }));

    // 3rd request violates causal sequence (all exchanges consumed)
    let outcome3 = engine.handle_request("getHealth", &json!(3), &json!([]));
    assert!(matches!(outcome3, ReplayOutcome::Unmatched { .. }));
}

#[test]
fn test_fault_injection_rules() {
    let session = create_sample_session();
    let mut fault_suite = FaultSuite::new();

    // Add rate limit fault rule for getHealth
    fault_suite.add_rule(
        FaultRule::new(FaultType::RateLimit {
            retry_after_secs: 10,
            message: Some("Simulated testnet rate limit".to_string()),
        })
        .with_method("getHealth"),
    );

    // Add custom RPC error for getLatestLedger
    fault_suite.add_rule(
        FaultRule::new(FaultType::RpcError {
            code: -32000,
            message: "Soroban node out of sync".to_string(),
            data: Some(json!({ "ledger": 42000 })),
        })
        .with_method("getLatestLedger"),
    );

    let engine = ReplayEngine::new(
        session,
        ReplayMode::Unordered,
        ReplayNormalization::default(),
        fault_suite,
        false,
    );

    // getHealth triggers RateLimit fault
    let outcome_health = engine.handle_request("getHealth", &json!(1), &json!([]));
    match outcome_health {
        ReplayOutcome::FaultTriggered {
            fault,
            custom_response,
            http_status,
        } => {
            assert!(matches!(fault, FaultType::RateLimit { .. }));
            assert_eq!(http_status, 429);
            let resp = custom_response.unwrap();
            assert_eq!(resp["error"]["code"], -32005);
        }
        other => panic!("Expected FaultTriggered, got {:?}", other),
    }

    // getLatestLedger triggers RpcError fault
    let outcome_ledger = engine.handle_request("getLatestLedger", &json!(2), &json!([]));
    match outcome_ledger {
        ReplayOutcome::FaultTriggered {
            fault,
            custom_response,
            http_status,
        } => {
            assert!(matches!(fault, FaultType::RpcError { .. }));
            assert_eq!(http_status, 200);
            let resp = custom_response.unwrap();
            assert_eq!(resp["error"]["code"], -32000);
            assert_eq!(resp["error"]["message"], "Soroban node out of sync");
        }
        other => panic!("Expected FaultTriggered, got {:?}", other),
    }
}

#[test]
fn test_verification_engine_integrity_and_leaks() {
    let verifier = SessionVerifier::new();
    let session = create_sample_session();

    // 1. Clean session verifies successfully
    let mut clean_report = starforge::utils::rpc_recording::verifier::VerificationReport {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
        metrics: Default::default(),
    };
    verifier.verify_session_in_memory(&session, "", true, &mut clean_report);
    assert!(clean_report.is_valid);
    assert!(clean_report.errors.is_empty());
    assert!(clean_report.metrics.digests_verified);
    assert!(clean_report.metrics.causal_chain_intact);

    // 2. Tampered exchange digest is caught
    let mut tampered = session.clone();
    tampered.exchanges[0].exchange_digest = "tampered_fake_digest".to_string();
    let mut tampered_report = starforge::utils::rpc_recording::verifier::VerificationReport {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
        metrics: Default::default(),
    };
    verifier.verify_session_in_memory(&tampered, "", false, &mut tampered_report);
    assert!(!tampered_report.is_valid);
    assert!(tampered_report
        .errors
        .iter()
        .any(|e| e.contains("digest mismatch")));

    // 3. Unredacted secret leak is detected by deep scanner
    let mut leaked_report = starforge::utils::rpc_recording::verifier::VerificationReport {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
        metrics: Default::default(),
    };
    let leaked_text =
        r#"{"leaked_seed":"SDNMALMR3V46C5S22D6OISCL6CCB4SCLW7Q6C6WOG62OEDOIFCTZFF2B"}"#;
    verifier.verify_session_in_memory(&session, leaked_text, true, &mut leaked_report);
    assert!(!leaked_report.is_valid);
    assert!(leaked_report
        .errors
        .iter()
        .any(|e| e.contains("CRITICAL SECURITY LEAK")));
}

#[test]
fn test_mock_replay_http_server() {
    let session = create_sample_session();
    let engine = ReplayEngine::new(
        session,
        ReplayMode::Unordered,
        ReplayNormalization::default(),
        FaultSuite::new(),
        false,
    );

    let port = 18545;
    let addr = format!("127.0.0.1:{}", port);
    let server = Arc::new(ReplayServer::new(engine, &addr));
    let server_handle = Arc::clone(&server);

    let handle = thread::spawn(move || {
        // Serve 1 request then terminate
        let _ = server_handle.run(Some(1));
    });

    // Brief sleep for listener binding
    thread::sleep(Duration::from_millis(100));

    // Send JSON-RPC request to mock replay server
    let client_req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "getHealth",
        "params": []
    });

    let resp = ureq::post(&format!("http://{}", addr))
        .send_json(client_req)
        .expect("send request to replay server");

    assert_eq!(resp.status(), 200);
    let resp_val: Value = resp.into_json().expect("parse response json");
    assert_eq!(resp_val["id"], 42);
    assert_eq!(resp_val["result"]["status"], "healthy");

    let _ = handle.join();
}

// ============================================================================
// CLI Integration Tests
// ============================================================================

#[test]
fn test_cli_inspect_and_verify_commands() {
    let home = isolated_home();
    let session_file = home.path().join("recording.json");
    let session = create_sample_session();
    save_recording(&session_file, &session).unwrap();

    // 1. starforge rpc inspect --json
    let mut inspect_cmd = starforge(home.path());
    inspect_cmd.args([
        "rpc",
        "inspect",
        "--file",
        session_file.to_str().unwrap(),
        "--json",
    ]);
    let inspect_out = inspect_cmd.output().expect("run inspect");
    assert_success(&inspect_out, "starforge rpc inspect --json");
    let parsed_json: Value = serde_json::from_str(&stdout(&inspect_out)).unwrap();
    assert_eq!(parsed_json["schema_version"], 1);
    assert_eq!(parsed_json["exchanges"].as_array().unwrap().len(), 2);

    // 2. starforge rpc inspect (human readable)
    let mut inspect_human = starforge(home.path());
    inspect_human.args([
        "rpc",
        "inspect",
        "--file",
        session_file.to_str().unwrap(),
        "--detailed",
    ]);
    let human_out = inspect_human.output().expect("run inspect human");
    assert_success(&human_out, "starforge rpc inspect --detailed");
    let out_str = stdout(&human_out);
    assert!(out_str.contains("StarForge RPC Recording Inspector"));
    assert!(out_str.contains("getHealth"));
    assert!(out_str.contains("getLatestLedger"));

    // 3. starforge rpc verify --json
    let mut verify_cmd = starforge(home.path());
    verify_cmd.args([
        "rpc",
        "verify",
        "--file",
        session_file.to_str().unwrap(),
        "--json",
    ]);
    let verify_out = verify_cmd.output().expect("run verify");
    assert_success(&verify_out, "starforge rpc verify --json");
    let verify_json: Value = serde_json::from_str(&stdout(&verify_out)).unwrap();
    assert_eq!(verify_json["is_valid"], true);
    assert_eq!(verify_json["metrics"]["digests_verified"], true);

    // 4. starforge rpc sanitize --json
    let sanitized_file = home.path().join("sanitized.json");
    let mut sanitize_cmd = starforge(home.path());
    sanitize_cmd.args([
        "rpc",
        "sanitize",
        "--input",
        session_file.to_str().unwrap(),
        "--output",
        sanitized_file.to_str().unwrap(),
        "--account-strategy",
        "mask",
        "--json",
    ]);
    let sanitize_out = sanitize_cmd.output().expect("run sanitize");
    assert_success(&sanitize_out, "starforge rpc sanitize --json");
    assert!(sanitized_file.exists());
}
