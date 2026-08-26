//! Stable data contracts used by the natural-language query subsystem.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PLAN_SCHEMA_VERSION: &str = "starforge.query-plan/v1";
pub const REPORT_SCHEMA_VERSION: &str = "starforge.query-report/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanSource {
    Deterministic,
    Ai,
    AiFallback,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryPlan {
    pub schema_version: String,
    pub question: String,
    pub network: String,
    pub source: PlanSource,
    pub operations: Vec<PlannedOperation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl QueryPlan {
    pub fn new(
        question: impl Into<String>,
        network: impl Into<String>,
        source: PlanSource,
        operations: Vec<PlannedOperation>,
    ) -> Self {
        Self {
            schema_version: PLAN_SCHEMA_VERSION.to_string(),
            question: question.into(),
            network: network.into(),
            source,
            operations,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedOperation {
    /// Stable identifier used to link findings to evidence.
    pub id: String,
    #[serde(flatten)]
    pub query: ReadOnlyQuery,
    /// Plain-language reason shown before execution.
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReadOnlyQuery {
    LatestLedger,
    ContractState {
        contract_id: String,
    },
    ContractStorage {
        contract_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
    ContractEvents {
        contract_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        topic: Option<String>,
        #[serde(default = "default_event_limit")]
        limit: u32,
    },
    Transaction {
        hash: String,
    },
}

fn default_event_limit() -> u32 {
    20
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryReport {
    pub schema_version: String,
    pub status: ReportStatus,
    pub question: String,
    pub network: String,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub plan: QueryPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub operation_id: String,
    pub statement: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub operation_id: String,
    pub source: EvidenceSource,
    pub method: String,
    pub request: Value,
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSource {
    pub kind: String,
    pub network: String,
    /// Deliberately contains only the origin, never credentials, query text,
    /// or sensitive local paths.
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiPlanEnvelope {
    pub operations: Vec<AiOperation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiOperation {
    pub kind: String,
    #[serde(default)]
    pub contract_id: Option<String>,
    #[serde(default)]
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    pub rationale: String,
}
