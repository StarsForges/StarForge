//! Event envelope and type definitions for the notification router

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Current schema version for events
pub const EVENT_SCHEMA_VERSION: &str = "1";

/// Maximum allowed payload size in bytes (512 KB) to prevent memory exhaustion
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 512 * 1024;

/// Versioned event envelope for StarForge events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// Schema version for forward-compatibility
    #[serde(default = "default_event_version")]
    pub version: String,
    /// Unique event identifier
    pub id: Uuid,
    /// Event type category
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Event severity level
    pub severity: Severity,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event source (command, daemon, etc.)
    pub source: String,
    /// Event title/summary
    pub title: String,
    /// Detailed event description
    pub description: String,
    /// Structured event data
    pub data: EventData,
    /// Optional correlation ID for tracking related events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Optional idempotency key for deduplication and delivery guarantees
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Optional metadata key-value pairs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

fn default_event_version() -> String {
    EVENT_SCHEMA_VERSION.to_string()
}

/// Event type categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Command execution outcome
    CommandOutcome,
    /// Transaction state change
    TransactionState,
    /// Daemon job status
    DaemonJob,
    /// Policy violation
    PolicyViolation,
    /// Health status change
    HealthChange,
    /// Deployment event
    Deployment,
    /// Soroban contract event
    ContractEvent,
    /// Wallet event
    WalletEvent,
    /// Custom event type
    Custom(String),
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::CommandOutcome => write!(f, "command_outcome"),
            EventType::TransactionState => write!(f, "transaction_state"),
            EventType::DaemonJob => write!(f, "daemon_job"),
            EventType::PolicyViolation => write!(f, "policy_violation"),
            EventType::HealthChange => write!(f, "health_change"),
            EventType::Deployment => write!(f, "deployment"),
            EventType::ContractEvent => write!(f, "contract_event"),
            EventType::WalletEvent => write!(f, "wallet_event"),
            EventType::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for EventType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        Ok(match lower.as_str() {
            "command_outcome" => EventType::CommandOutcome,
            "transaction_state" => EventType::TransactionState,
            "daemon_job" => EventType::DaemonJob,
            "policy_violation" => EventType::PolicyViolation,
            "health_change" => EventType::HealthChange,
            "deployment" => EventType::Deployment,
            "contract_event" => EventType::ContractEvent,
            "wallet_event" => EventType::WalletEvent,
            _ => EventType::Custom(s.to_string()),
        })
    }
}

/// Severity levels for events
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational only
    Info = 0,
    /// Warning condition
    Warning = 1,
    /// Error condition
    Error = 2,
    /// Critical failure
    Critical = 3,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "error" | "err" => Ok(Severity::Error),
            "critical" | "crit" => Ok(Severity::Critical),
            _ => bail!(
                "Unknown severity: '{}'. Must be info, warning, error, or critical.",
                s
            ),
        }
    }
}

/// Structured event data based on event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum EventData {
    CommandOutcome(CommandOutcomeData),
    TransactionState(TransactionStateData),
    DaemonJob(DaemonJobData),
    PolicyViolation(PolicyViolationData),
    HealthChange(HealthChangeData),
    Deployment(DeploymentData),
    ContractEvent(ContractEventData),
    WalletEvent(WalletEventData),
    Generic(HashMap<String, serde_json::Value>),
}

/// Command outcome event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandOutcomeData {
    pub command: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Transaction state event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionStateData {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_details: Option<String>,
}

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Pending,
    Success,
    Failed,
    Timeout,
}

/// Daemon job event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonJobData {
    pub job_name: String,
    pub job_type: String,
    pub status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Started,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Policy violation event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyViolationData {
    pub policy_name: String,
    pub violation_type: String,
    pub severity: Severity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_resource: Option<String>,
}

/// Health change event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthChangeData {
    pub component: String,
    pub previous_status: HealthStatus,
    pub current_status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Deployment event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentData {
    pub contract_id: String,
    pub network: String,
    pub deployment_status: DeploymentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

/// Deployment status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Started,
    Success,
    Failed,
}

/// Contract event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractEventData {
    pub contract_id: String,
    pub event_type: String,
    pub topics: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Wallet event data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletEventData {
    pub wallet_name: String,
    pub public_key: String,
    pub event_type: WalletEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

/// Wallet event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletEventType {
    Created,
    Funded,
    Rotated,
    Deleted,
}

impl Event {
    /// Create a new event with the given type and title
    pub fn new(event_type: EventType, title: impl Into<String>) -> Self {
        Self {
            version: EVENT_SCHEMA_VERSION.to_string(),
            id: Uuid::new_v4(),
            event_type,
            severity: Severity::Info,
            timestamp: Utc::now(),
            source: "starforge".to_string(),
            title: title.into(),
            description: String::new(),
            data: EventData::Generic(HashMap::new()),
            correlation_id: None,
            idempotency_key: None,
            metadata: None,
        }
    }

    /// Set the schema version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Set the event ID explicitly
    pub fn with_id(mut self, id: Uuid) -> Self {
        self.id = id;
        self
    }

    /// Set the severity level
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the event data
    pub fn with_data(mut self, data: EventData) -> Self {
        self.data = data;
        self
    }

    /// Set the source
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the correlation ID
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Set the idempotency key
    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    /// Add a single metadata key-value pair
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut metadata = self.metadata.unwrap_or_default();
        metadata.insert(key.into(), value.into());
        self.metadata = Some(metadata);
        self
    }

    /// Validate the event structure and constraints
    pub fn validate(&self) -> Result<()> {
        if self.version.is_empty() {
            bail!("Event version cannot be empty");
        }
        if self.title.trim().is_empty() {
            bail!("Event title cannot be empty");
        }
        if self.source.trim().is_empty() {
            bail!("Event source cannot be empty");
        }

        // Validate payload size
        let serialized = serde_json::to_vec(self)?;
        if serialized.len() > MAX_EVENT_PAYLOAD_BYTES {
            bail!(
                "Event payload exceeds maximum limit of {} bytes (actual: {} bytes)",
                MAX_EVENT_PAYLOAD_BYTES,
                serialized.len()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = Event::new(EventType::CommandOutcome, "Test command")
            .with_severity(Severity::Error)
            .with_description("Command failed")
            .with_idempotency_key("idem-123");

        assert_eq!(event.version, EVENT_SCHEMA_VERSION);
        assert_eq!(event.event_type, EventType::CommandOutcome);
        assert_eq!(event.severity, Severity::Error);
        assert_eq!(event.title, "Test command");
        assert_eq!(event.idempotency_key.as_deref(), Some("idem-123"));
    }

    #[test]
    fn test_event_validation() {
        let event = Event::new(EventType::CommandOutcome, "");
        assert!(event.validate().is_err());

        let event = Event::new(EventType::CommandOutcome, "Valid title");
        assert!(event.validate().is_ok());

        let mut invalid_source = Event::new(EventType::CommandOutcome, "Valid title");
        invalid_source.source = "   ".to_string();
        assert!(invalid_source.validate().is_err());
    }

    #[test]
    fn test_severity_ordering_and_parsing() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);

        assert_eq!("info".parse::<Severity>().unwrap(), Severity::Info);
        assert_eq!("warning".parse::<Severity>().unwrap(), Severity::Warning);
        assert_eq!("error".parse::<Severity>().unwrap(), Severity::Error);
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert!("invalid".parse::<Severity>().is_err());
    }

    #[test]
    fn test_event_type_from_str() {
        assert_eq!(
            "command_outcome".parse::<EventType>().unwrap(),
            EventType::CommandOutcome
        );
        assert_eq!(
            "custom_event".parse::<EventType>().unwrap(),
            EventType::Custom("custom_event".to_string())
        );
    }

    #[test]
    fn test_event_serialization() {
        let event = Event::new(EventType::CommandOutcome, "Test")
            .with_idempotency_key("idemp-456")
            .with_metadata("env", "prod");
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.version, deserialized.version);
        assert_eq!(event.idempotency_key, deserialized.idempotency_key);
        assert_eq!(event.metadata, deserialized.metadata);
    }
}
