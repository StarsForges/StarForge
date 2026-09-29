use serde::{Deserialize, Serialize};
use std::fmt;

/// Configuration options for validating incoming SEP-10 challenge transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeValidationConfig {
    /// Permissible clock skew in seconds (default: 300s = 5 minutes).
    pub allowed_clock_skew_secs: u64,
    /// Maximum allowable challenge validity window in seconds (default: 3600s = 1 hour).
    pub max_challenge_duration_secs: u64,
    /// Expected home domain of the anchor (e.g. "testanchor.stellar.org").
    pub expected_home_domain: Option<String>,
    /// Expected web auth domain published in stellar.toml.
    pub expected_web_auth_domain: Option<String>,
    /// Expected client domain for client attribution.
    pub expected_client_domain: Option<String>,
    /// Stellar network passphrase.
    pub network_passphrase: String,
    /// Whether web_auth_domain check is strictly mandatory.
    pub require_web_auth_domain: bool,
    /// Whether client_domain signature is mandatory.
    pub require_client_domain: bool,
}

impl Default for ChallengeValidationConfig {
    fn default() -> Self {
        Self {
            allowed_clock_skew_secs: 300,
            max_challenge_duration_secs: 3600,
            expected_home_domain: None,
            expected_web_auth_domain: None,
            expected_client_domain: None,
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            require_web_auth_domain: false,
            require_client_domain: false,
        }
    }
}

/// Strongly typed errors encountered during SEP-10 challenge verification or session lifecycle.
#[derive(Debug)]
pub enum Sep10Error {
    InvalidEnvelope(String),
    MissingServerSignature,
    InvalidServerSignature(String),
    ServerKeyMismatch {
        server_key: String,
        expected: String,
    },
    SourceAccountMismatch {
        expected: String,
        actual: String,
    },
    InvalidSequenceNumber(i64),
    MissingTimeBounds,
    ChallengeExpired {
        max_time: u64,
        current_time: u64,
    },
    ChallengePremature {
        min_time: u64,
        current_time: u64,
    },
    ExcessiveDuration {
        duration_secs: u64,
        max_allowed: u64,
    },
    EmptyOperations,
    InvalidFirstOperation(String),
    InvalidNonce(String),
    HomeDomainMismatch {
        expected: String,
        actual: String,
    },
    WebAuthDomainMismatch {
        expected: String,
        actual: String,
    },
    ClientDomainMismatch {
        expected: String,
        actual: String,
    },
    ClientSignatureError(String),
    StellarTomlError(String, String),
    NetworkError(String),
    StorageError(String),
    SerializationError(String),
    CryptoError(String),
}

impl fmt::Display for Sep10Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope(msg) => write!(f, "Invalid transaction envelope: {msg}"),
            Self::MissingServerSignature => write!(f, "Transaction is missing server signature"),
            Self::InvalidServerSignature(msg) => write!(f, "Server signature verification failed: {msg}"),
            Self::ServerKeyMismatch { server_key, expected } => write!(
                f,
                "Server key '{server_key}' not authorized or mismatched with anchor stellar.toml: expected '{expected}'"
            ),
            Self::SourceAccountMismatch { expected, actual } => write!(
                f,
                "Source account mismatch: expected '{expected}', found '{actual}'"
            ),
            Self::InvalidSequenceNumber(seq) => write!(f, "Invalid sequence number: expected 0, got {seq}"),
            Self::MissingTimeBounds => write!(f, "Challenge transaction has no time bounds precondition"),
            Self::ChallengeExpired { max_time, current_time } => write!(
                f,
                "Challenge transaction has expired: max_time {max_time} < current_time {current_time}"
            ),
            Self::ChallengePremature { min_time, current_time } => write!(
                f,
                "Challenge transaction is premature (clock skew): min_time {min_time} > current_time {current_time}"
            ),
            Self::ExcessiveDuration { duration_secs, max_allowed } => write!(
                f,
                "Challenge duration of {duration_secs}s exceeds allowable maximum of {max_allowed}s"
            ),
            Self::EmptyOperations => write!(f, "Challenge transaction contains zero operations"),
            Self::InvalidFirstOperation(msg) => write!(f, "First operation is invalid for SEP-10: {msg}"),
            Self::InvalidNonce(msg) => write!(f, "Invalid challenge nonce: {msg}"),
            Self::HomeDomainMismatch { expected, actual } => write!(
                f,
                "Home domain mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::WebAuthDomainMismatch { expected, actual } => write!(
                f,
                "Web auth domain mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::ClientDomainMismatch { expected, actual } => write!(
                f,
                "Client domain mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::ClientSignatureError(msg) => write!(f, "Client signature validation failed: {msg}"),
            Self::StellarTomlError(domain, msg) => write!(f, "Stellar TOML error from anchor '{domain}': {msg}"),
            Self::NetworkError(msg) => write!(f, "Network/transport failure: {msg}"),
            Self::StorageError(msg) => write!(f, "Encrypted session store error: {msg}"),
            Self::SerializationError(msg) => write!(f, "Serialization/deserialization failure: {msg}"),
            Self::CryptoError(msg) => write!(f, "Crypto operation failure: {msg}"),
        }
    }
}

impl std::error::Error for Sep10Error {}

/// Detailed audit report produced after parsing and verifying a SEP-10 challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub is_valid: bool,
    pub checks_passed: Vec<String>,
    pub warnings: Vec<String>,
    pub details: ChallengeDetails,
}

/// Structural details extracted from a SEP-10 challenge transaction envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeDetails {
    pub server_account: String,
    pub client_account: String,
    pub sequence_number: i64,
    pub min_time: u64,
    pub max_time: u64,
    pub duration_secs: u64,
    pub time_to_expiry_secs: i64,
    pub home_domain: String,
    pub web_auth_domain: Option<String>,
    pub client_domain: Option<String>,
    pub nonce_length_bytes: usize,
    pub server_signature_valid: bool,
    pub existing_signatures_count: usize,
}

/// Represents an active or archived authenticated session token (JWT) for an anchor.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub anchor_domain: String,
    pub account: String,
    pub jwt: String,
    pub issued_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub client_domain: Option<String>,
    pub created_at_utc: String,
}

impl SessionToken {
    /// Returns true if the token is already expired according to system clock.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = chrono::Utc::now().timestamp();
            now >= exp
        } else {
            false
        }
    }

    /// Returns seconds remaining until expiration (negative if already expired).
    pub fn seconds_until_expiry(&self) -> i64 {
        if let Some(exp) = self.expires_at {
            let now = chrono::Utc::now().timestamp();
            exp - now
        } else {
            i64::MAX
        }
    }

    /// Produce a safe sanitized version of the JWT for logging and CLI display.
    pub fn redacted_jwt(&self) -> String {
        if self.jwt.len() > 16 {
            format!("{}...[REDACTED]", &self.jwt[..12])
        } else {
            "[REDACTED]".to_string()
        }
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionToken")
            .field("anchor_domain", &self.anchor_domain)
            .field("account", &self.account)
            .field("jwt", &self.redacted_jwt())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("client_domain", &self.client_domain)
            .field("created_at_utc", &self.created_at_utc)
            .finish()
    }
}

/// Comprehensive diagnostics report for an anchor's SEP-10 endpoint readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sep10DoctorReport {
    pub anchor_domain: String,
    pub toml_url: String,
    pub toml_fetch_ok: bool,
    pub web_auth_endpoint: Option<String>,
    pub signing_key: Option<String>,
    pub network_passphrase: Option<String>,
    pub challenge_fetch_ok: bool,
    pub measured_latency_ms: u128,
    pub estimated_clock_skew_secs: i64,
    pub tls_cert_valid: bool,
    pub issues_found: Vec<String>,
    pub is_healthy: bool,
}
