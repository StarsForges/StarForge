use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Represents a recorded session of JSON-RPC exchanges between client and node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordingSession {
    /// Schema version for forward/backward compatibility
    pub schema_version: u32,
    /// Unique identifier for this recording session
    pub session_id: String,
    /// ISO 8601 timestamp when session recording commenced
    pub created_at: String,
    /// ISO 8601 timestamp when session was closed or last modified
    pub updated_at: String,
    /// Target endpoint details and network parameters
    pub endpoint: EndpointMetadata,
    /// Summary of redaction metrics applied to this session
    pub redaction_summary: RedactionSummary,
    /// Chronologically and causally ordered exchanges
    pub exchanges: Vec<RecordedExchange>,
    /// Cryptographic SHA-256 digest of the session's exchanges
    pub session_digest: String,
    /// Custom key-value session metadata (environment, git commit, test tag)
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl RecordingSession {
    /// Create a new empty recording session for a target endpoint
    pub fn new(endpoint: EndpointMetadata) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            session_id: Uuid::new_v4().to_string(),
            created_at: now.clone(),
            updated_at: now,
            endpoint,
            redaction_summary: RedactionSummary::default(),
            exchanges: Vec::new(),
            session_digest: String::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add an exchange to the session, automatically computing digests and causal ordering
    pub fn add_exchange(&mut self, mut exchange: RecordedExchange) {
        let seq = self.exchanges.len() as u64;
        exchange.sequence_id = seq;
        if seq > 0 {
            exchange.parent_id = Some(self.exchanges[(seq - 1) as usize].exchange_id.clone());
        }
        exchange.exchange_digest = exchange.compute_digest();
        self.exchanges.push(exchange);
        self.updated_at = Utc::now().to_rfc3339();
        self.session_digest = self.compute_session_digest();
    }

    /// Compute composite SHA-256 digest across all exchanges in session
    pub fn compute_session_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.schema_version.to_be_bytes());
        for ex in &self.exchanges {
            hasher.update(ex.exchange_digest.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Verify the integrity of the session digest and all exchange digests
    pub fn verify_digests(&self) -> Result<()> {
        for (i, ex) in self.exchanges.iter().enumerate() {
            let expected = ex.compute_digest();
            if ex.exchange_digest != expected {
                bail!(
                    "Exchange digest mismatch at index {}: expected {}, found {}",
                    i,
                    expected,
                    ex.exchange_digest
                );
            }
        }
        let expected_session = self.compute_session_digest();
        if self.session_digest != expected_session {
            bail!(
                "Session digest mismatch: expected {}, found {}",
                expected_session,
                self.session_digest
            );
        }
        Ok(())
    }

    /// Migrate an arbitrary JSON value representing a session to CURRENT_SCHEMA_VERSION
    pub fn from_json_value_migrated(val: serde_json::Value) -> Result<Self> {
        let version = val
            .get("schema_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        match version {
            CURRENT_SCHEMA_VERSION => {
                let session: RecordingSession = serde_json::from_value(val)
                    .context("Failed to deserialize recording session v1")?;
                Ok(session)
            }
            0 => {
                // Legacy / unversioned migration: synthesize missing fields
                let mut obj = match val {
                    serde_json::Value::Object(map) => map,
                    _ => bail!("Expected JSON object for recording session"),
                };
                let now = Utc::now().to_rfc3339();
                let session_id = obj
                    .get("session_id")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| Uuid::new_v4().to_string());

                let endpoint = if let Some(ep) = obj.remove("endpoint") {
                    serde_json::from_value(ep).unwrap_or_else(|_| EndpointMetadata::default())
                } else {
                    EndpointMetadata::default()
                };

                let raw_exchanges = obj
                    .remove("exchanges")
                    .unwrap_or_else(|| serde_json::json!([]));
                let mut exchanges: Vec<RecordedExchange> = serde_json::from_value(raw_exchanges)
                    .context("Failed to deserialize legacy exchanges")?;

                // Re-sequence and compute digests for migrated exchanges
                for idx in 0..exchanges.len() {
                    let parent_id = if idx > 0 {
                        Some(exchanges[idx - 1].exchange_id.clone())
                    } else {
                        None
                    };
                    exchanges[idx].sequence_id = idx as u64;
                    exchanges[idx].parent_id = parent_id;
                    exchanges[idx].exchange_digest = exchanges[idx].compute_digest();
                }

                let mut migrated = RecordingSession {
                    schema_version: CURRENT_SCHEMA_VERSION,
                    session_id,
                    created_at: obj
                        .get("created_at")
                        .and_then(|s| s.as_str())
                        .unwrap_or(&now)
                        .to_string(),
                    updated_at: now,
                    endpoint,
                    redaction_summary: RedactionSummary::default(),
                    exchanges,
                    session_digest: String::new(),
                    metadata: HashMap::new(),
                };
                migrated.session_digest = migrated.compute_session_digest();
                Ok(migrated)
            }
            future if future > CURRENT_SCHEMA_VERSION => {
                bail!(
                    "Recording session has schema version {} which is newer than supported version {}",
                    future,
                    CURRENT_SCHEMA_VERSION
                );
            }
            unknown => {
                bail!("Unsupported recording session schema version: {}", unknown);
            }
        }
    }
}

/// Metadata about the recorded endpoint and capture context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EndpointMetadata {
    /// Upstream RPC URL
    pub upstream_url: String,
    /// Network passphrase (e.g., "Test SDF Network ; September 2015")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_passphrase: Option<String>,
    /// Protocol name / version (e.g., "JSON-RPC 2.0")
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Redacted upstream request headers
    #[serde(default)]
    pub sanitized_headers: HashMap<String, String>,
    /// Client user agent string if captured
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

fn default_protocol() -> String {
    "JSON-RPC 2.0".to_string()
}

/// A single recorded request-response exchange
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordedExchange {
    /// Unique identifier for this specific exchange
    pub exchange_id: String,
    /// Zero-based monotonic sequence index for causal ordering
    #[serde(default)]
    pub sequence_id: u64,
    /// Parent exchange ID (causal antecedent) or None for root exchange
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Detailed timing and latency metrics
    #[serde(default)]
    pub timing: TimingInfo,
    /// Recorded and redacted request
    pub request: RecordedRequest,
    /// Recorded and redacted response
    pub response: RecordedResponse,
    /// Cryptographic digest of this exchange
    #[serde(default)]
    pub exchange_digest: String,
}

impl RecordedExchange {
    /// Compute SHA-256 digest of exchange content for tamper-evidence
    pub fn compute_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence_id.to_be_bytes());
        if let Some(ref p) = self.parent_id {
            hasher.update(p.as_bytes());
        }
        hasher.update(self.request.method.as_bytes());
        hasher.update(self.request.jsonrpc_method.as_bytes());
        let req_canon = serde_json::to_string(&self.request.params).unwrap_or_default();
        hasher.update(req_canon.as_bytes());
        hasher.update(self.response.status_code.to_be_bytes());
        let res_canon = serde_json::to_string(&self.response.body).unwrap_or_default();
        hasher.update(res_canon.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Detailed timing information for network profiling and replay pacing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TimingInfo {
    /// Epoch timestamp (milliseconds) when request was received
    pub started_at_ms: u64,
    /// Epoch timestamp (milliseconds) when response was finished
    pub completed_at_ms: u64,
    /// Total round-trip duration in milliseconds
    pub duration_ms: u64,
}

/// Request details captured during recording
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordedRequest {
    /// HTTP method (e.g. POST)
    pub method: String,
    /// Path (e.g. "/" or "/rpc")
    pub path: String,
    /// Redacted request headers
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Extracted JSON-RPC method name (e.g. "getHealth", "simulateTransaction")
    pub jsonrpc_method: String,
    /// Original JSON-RPC request ID
    #[serde(default)]
    pub jsonrpc_id: serde_json::Value,
    /// Request parameters payload
    #[serde(default)]
    pub params: serde_json::Value,
    /// SHA-256 hash of raw pre-redaction request body
    #[serde(default)]
    pub raw_body_hash: String,
}

/// Response details captured during recording
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordedResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Redacted response headers
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Response body payload (JSON-RPC result or error)
    pub body: serde_json::Value,
    /// True if response represents an HTTP or JSON-RPC error
    pub is_error: bool,
    /// SHA-256 hash of raw response body
    #[serde(default)]
    pub raw_body_hash: String,
}

/// Summary counts of redactions performed on the session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RedactionSummary {
    pub secrets_redacted_count: usize,
    pub signatures_redacted_count: usize,
    pub paths_redacted_count: usize,
    pub accounts_redacted_count: usize,
    pub custom_rules_matched_count: usize,
}

impl RedactionSummary {
    pub fn total(&self) -> usize {
        self.secrets_redacted_count
            + self.signatures_redacted_count
            + self.paths_redacted_count
            + self.accounts_redacted_count
            + self.custom_rules_matched_count
    }

    pub fn merge(&mut self, other: &RedactionSummary) {
        self.secrets_redacted_count += other.secrets_redacted_count;
        self.signatures_redacted_count += other.signatures_redacted_count;
        self.paths_redacted_count += other.paths_redacted_count;
        self.accounts_redacted_count += other.accounts_redacted_count;
        self.custom_rules_matched_count += other.custom_rules_matched_count;
    }
}
