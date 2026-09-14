#![allow(unused_imports)]

pub mod fault;
pub mod proxy;
pub mod redaction;
pub mod replay;
pub mod types;
pub mod verifier;

pub use fault::{FaultRule, FaultSuite, FaultType};
pub use proxy::{save_session_atomic, ProxyConfig, RecordingProxy};
pub use redaction::{AccountRedactionStrategy, RedactionConfig, RedactionEvent, Redactor};
pub use replay::{ReplayEngine, ReplayMode, ReplayNormalization, ReplayOutcome, ReplayServer};
pub use types::{
    EndpointMetadata, RecordedExchange, RecordedRequest, RecordedResponse, RecordingSession,
    RedactionSummary, TimingInfo, CURRENT_SCHEMA_VERSION,
};
pub use verifier::{SessionVerifier, VerificationMetrics, VerificationReport};

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Load and parse a recording session from a file, performing auto-migration if needed
pub fn load_recording<P: AsRef<Path>>(path: P) -> Result<RecordingSession> {
    let path_ref = path.as_ref();
    let content = fs::read_to_string(path_ref)
        .with_context(|| format!("Failed to read recording file {}", path_ref.display()))?;
    let raw_json: serde_json::Value = serde_json::from_str(&content).with_context(|| {
        format!(
            "Failed to parse JSON in recording file {}",
            path_ref.display()
        )
    })?;
    RecordingSession::from_json_value_migrated(raw_json)
}

/// Save a recording session to a file atomically with 0600 file permissions
pub fn save_recording<P: AsRef<Path>>(path: P, session: &RecordingSession) -> Result<()> {
    save_session_atomic(path.as_ref(), session)
}

/// Sanitize an existing recording session by running an additional redaction pass
pub fn sanitize_session(
    mut session: RecordingSession,
    redactor: &Redactor,
) -> (RecordingSession, RedactionSummary, Vec<RedactionEvent>) {
    let mut total_summary = RedactionSummary::default();
    let mut all_events = Vec::new();

    for ex in &mut session.exchanges {
        // Redact request
        let (req_sum, req_events) = redactor.redact_value(&mut ex.request.params, "request.params");
        let (head_sum, head_events) = redactor.redact_headers(&mut ex.request.headers);
        total_summary.merge(&req_sum);
        total_summary.merge(&head_sum);
        all_events.extend(req_events);
        all_events.extend(head_events);

        // Redact response
        let (resp_sum, resp_events) = redactor.redact_value(&mut ex.response.body, "response.body");
        let (resp_head_sum, resp_head_events) = redactor.redact_headers(&mut ex.response.headers);
        total_summary.merge(&resp_sum);
        total_summary.merge(&resp_head_sum);
        all_events.extend(resp_events);
        all_events.extend(resp_head_events);

        // Recompute exchange digest
        ex.exchange_digest = ex.compute_digest();
    }

    session.redaction_summary.merge(&total_summary);
    session.session_digest = session.compute_session_digest();
    session.updated_at = chrono::Utc::now().to_rfc3339();

    (session, total_summary, all_events)
}
