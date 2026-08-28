use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const COMPATIBILITY_SCHEMA_VERSION: u32 = 1;
pub const MATRIX_VERSION: &str = "2026-08-28";
pub const MIN_PROTOCOL_VERSION: u32 = 20;
pub const MAX_PROTOCOL_VERSION: u32 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityLevel {
    Compatible,
    Degraded,
    Unknown,
    Incompatible,
}

impl CompatibilityLevel {
    pub fn rank(self) -> u8 {
        match self {
            Self::Compatible => 0,
            Self::Degraded => 1,
            Self::Unknown => 2,
            Self::Incompatible => 3,
        }
    }

    pub fn merge(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    pub fn is_hard_failure(self) -> bool {
        matches!(self, Self::Incompatible)
    }
}

impl fmt::Display for CompatibilityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatible => write!(f, "compatible"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unknown => write!(f, "unknown"),
            Self::Incompatible => write!(f, "incompatible"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

impl FindingSeverity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
        }
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRange {
    pub minimum: u32,
    pub maximum: u32,
}

impl ProtocolRange {
    pub fn contains(&self, version: u32) -> bool {
        (self.minimum..=self.maximum).contains(&version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolCapability {
    pub protocol_version: u32,
    pub status: CompatibilityLevel,
    pub xdr_supported: bool,
    pub host_function_generation: u32,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcMethodCapability {
    pub method: String,
    pub introduced_in_protocol: u32,
    pub required_for_probe: bool,
    pub required_for_core: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureCapability {
    pub feature: String,
    pub protocol: ProtocolRange,
    pub required_methods: BTreeSet<String>,
    pub optional_methods: BTreeSet<String>,
    pub hard_requirement: bool,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdrCapability {
    pub crate_name: String,
    pub crate_version: String,
    pub protocol: ProtocolRange,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrix {
    pub schema_version: u32,
    pub matrix_version: String,
    pub generated_by: String,
    pub protocols: Vec<ProtocolCapability>,
    pub rpc_methods: Vec<RpcMethodCapability>,
    pub xdr: XdrCapability,
    pub features: Vec<FeatureCapability>,
}

impl CapabilityMatrix {
    pub fn builtin() -> Self {
        let protocols = vec![
            ProtocolCapability {
                protocol_version: 20,
                status: CompatibilityLevel::Compatible,
                xdr_supported: true,
                host_function_generation: 1,
                notes: vec!["Initial production Soroban protocol supported by StarForge".into()],
            },
            ProtocolCapability {
                protocol_version: 21,
                status: CompatibilityLevel::Compatible,
                xdr_supported: true,
                host_function_generation: 2,
                notes: vec!["Soroban cost and host-function changes are represented in XDR".into()],
            },
            ProtocolCapability {
                protocol_version: 22,
                status: CompatibilityLevel::Compatible,
                xdr_supported: true,
                host_function_generation: 3,
                notes: vec!["Maximum protocol validated with stellar-xdr 22".into()],
            },
        ];
        let rpc_methods = vec![
            rpc_method(
                "getHealth",
                20,
                true,
                false,
                "RPC health and retention evidence",
            ),
            rpc_method(
                "getNetwork",
                20,
                true,
                true,
                "Network passphrase and protocol evidence",
            ),
            rpc_method(
                "getLatestLedger",
                20,
                true,
                true,
                "Latest ledger and protocol evidence",
            ),
            rpc_method(
                "getVersionInfo",
                20,
                false,
                false,
                "RPC implementation version evidence",
            ),
            rpc_method(
                "simulateTransaction",
                20,
                false,
                true,
                "Soroban transaction simulation",
            ),
            rpc_method(
                "sendTransaction",
                20,
                false,
                true,
                "Asynchronous transaction submission",
            ),
            rpc_method(
                "getTransaction",
                20,
                false,
                true,
                "Transaction status lookup",
            ),
            rpc_method("getEvents", 20, false, false, "Contract event queries"),
            rpc_method(
                "getLedgerEntries",
                20,
                false,
                false,
                "Ledger entry inspection",
            ),
            rpc_method(
                "getTransactions",
                21,
                false,
                false,
                "Historical transaction queries",
            ),
            rpc_method("getLedgers", 21, false, false, "Historical ledger queries"),
            rpc_method(
                "rpc.discover",
                20,
                false,
                false,
                "OpenRPC capability discovery",
            ),
        ];
        let features = vec![
            feature(
                "network_operations",
                20,
                22,
                &["getNetwork", "getLatestLedger"],
                &["getHealth"],
                true,
                "Select an endpoint that implements getNetwork and getLatestLedger.",
            ),
            feature(
                "contract_simulation",
                20,
                22,
                &["simulateTransaction"],
                &["getLedgerEntries"],
                true,
                "Upgrade the Soroban RPC service or disable simulation-dependent commands.",
            ),
            feature(
                "transaction_submission",
                20,
                22,
                &["sendTransaction", "getTransaction"],
                &[],
                true,
                "Use an RPC provider supporting sendTransaction and getTransaction.",
            ),
            feature(
                "contract_events",
                20,
                22,
                &["getEvents"],
                &["getTransactions"],
                false,
                "Event-based monitoring is degraded; configure an endpoint with getEvents.",
            ),
            feature(
                "ledger_inspection",
                20,
                22,
                &["getLedgerEntries"],
                &["getLedgers"],
                false,
                "Deep ledger inspection is degraded; use a full-history RPC endpoint.",
            ),
            feature(
                "upgrade_analysis",
                20,
                22,
                &["simulateTransaction", "getLedgerEntries"],
                &["getEvents"],
                true,
                "Run upgrade analysis against an RPC endpoint with simulation and ledger access.",
            ),
        ];
        Self {
            schema_version: COMPATIBILITY_SCHEMA_VERSION,
            matrix_version: MATRIX_VERSION.into(),
            generated_by: format!("starforge/{}", env!("CARGO_PKG_VERSION")),
            protocols,
            rpc_methods,
            xdr: XdrCapability {
                crate_name: "stellar-xdr".into(),
                crate_version: "22.0.0".into(),
                protocol: ProtocolRange {
                    minimum: MIN_PROTOCOL_VERSION,
                    maximum: MAX_PROTOCOL_VERSION,
                },
                evidence: "Cargo.lock and StarForge protocol/XDR fixture suite".into(),
            },
            features,
        }
    }

    pub fn protocol(&self, version: u32) -> Option<&ProtocolCapability> {
        self.protocols
            .iter()
            .find(|entry| entry.protocol_version == version)
    }

    pub fn feature(&self, name: &str) -> Option<&FeatureCapability> {
        self.features.iter().find(|feature| feature.feature == name)
    }

    pub fn known_methods(&self) -> BTreeSet<String> {
        self.rpc_methods
            .iter()
            .map(|entry| entry.method.clone())
            .collect()
    }

    pub fn required_probe_methods(&self) -> BTreeSet<String> {
        self.rpc_methods
            .iter()
            .filter(|entry| entry.required_for_probe)
            .map(|entry| entry.method.clone())
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != COMPATIBILITY_SCHEMA_VERSION {
            return Err(format!(
                "unsupported matrix schema {}; expected {}",
                self.schema_version, COMPATIBILITY_SCHEMA_VERSION
            ));
        }
        if self.protocols.is_empty() || self.features.is_empty() {
            return Err("matrix must contain protocols and features".into());
        }
        let methods = self.known_methods();
        for feature in &self.features {
            if feature.protocol.minimum > feature.protocol.maximum {
                return Err(format!(
                    "feature {} has an inverted protocol range",
                    feature.feature
                ));
            }
            for method in feature
                .required_methods
                .iter()
                .chain(feature.optional_methods.iter())
            {
                if !methods.contains(method) {
                    return Err(format!(
                        "feature {} refers to unknown RPC method {}",
                        feature.feature, method
                    ));
                }
            }
        }
        Ok(())
    }
}

fn rpc_method(
    method: &str,
    introduced_in_protocol: u32,
    required_for_probe: bool,
    required_for_core: bool,
    description: &str,
) -> RpcMethodCapability {
    RpcMethodCapability {
        method: method.into(),
        introduced_in_protocol,
        required_for_probe,
        required_for_core,
        description: description.into(),
    }
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn feature(
    name: &str,
    minimum: u32,
    maximum: u32,
    required: &[&str],
    optional: &[&str],
    hard_requirement: bool,
    remediation: &str,
) -> FeatureCapability {
    FeatureCapability {
        feature: name.into(),
        protocol: ProtocolRange { minimum, maximum },
        required_methods: string_set(required),
        optional_methods: string_set(optional),
        hard_requirement,
        remediation: remediation.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HorizonEvidence {
    pub display_endpoint: String,
    pub network_identity: Option<String>,
    pub latest_ledger: Option<u64>,
    pub protocol_version: Option<u32>,
    pub core_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointEvidence {
    pub schema_version: u32,
    pub endpoint_id: String,
    pub display_endpoint: String,
    pub observed_at: DateTime<Utc>,
    pub network_identity: Option<String>,
    pub latest_ledger: Option<u64>,
    pub protocol_version: Option<u32>,
    pub oldest_ledger: Option<u64>,
    pub retention_window: Option<u64>,
    pub rpc_version: Option<String>,
    pub supported_methods: BTreeSet<String>,
    pub missing_methods: BTreeSet<String>,
    pub vendor_extensions: BTreeSet<String>,
    pub limits: BTreeMap<String, u64>,
    pub horizon: Option<HorizonEvidence>,
    pub warnings: Vec<String>,
}

impl EndpointEvidence {
    pub fn new(display_endpoint: String, endpoint_key: &str, observed_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: COMPATIBILITY_SCHEMA_VERSION,
            endpoint_id: endpoint_identifier(endpoint_key),
            display_endpoint,
            observed_at,
            network_identity: None,
            latest_ledger: None,
            protocol_version: None,
            oldest_ledger: None,
            retention_window: None,
            rpc_version: None,
            supported_methods: BTreeSet::new(),
            missing_methods: BTreeSet::new(),
            vendor_extensions: BTreeSet::new(),
            limits: BTreeMap::new(),
            horizon: None,
            warnings: Vec::new(),
        }
    }

    pub fn age_seconds(&self, now: DateTime<Utc>) -> i64 {
        now.signed_duration_since(self.observed_at)
            .num_seconds()
            .max(0)
    }
}

pub fn endpoint_identifier(endpoint: &str) -> String {
    let digest = Sha256::digest(endpoint.as_bytes());
    format!("sha256:{}", hex::encode(&digest[..12]))
}

pub fn network_identity(passphrase: &str) -> String {
    let digest = Sha256::digest(passphrase.as_bytes());
    format!("sha256:{}", hex::encode(&digest[..16]))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityFinding {
    pub code: String,
    pub severity: FindingSeverity,
    pub component: String,
    pub summary: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub evidence: BTreeMap<String, String>,
}

impl CompatibilityFinding {
    pub fn new(
        code: impl Into<String>,
        severity: FindingSeverity,
        component: impl Into<String>,
        summary: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            component: component.into(),
            summary: summary.into(),
            action: action.into(),
            evidence: BTreeMap::new(),
        }
    }

    pub fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureDecision {
    pub feature: String,
    pub level: CompatibilityLevel,
    pub missing_required_methods: BTreeSet<String>,
    pub missing_optional_methods: BTreeSet<String>,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityStatus {
    pub schema_version: u32,
    pub matrix_version: String,
    pub evaluated_at: DateTime<Utc>,
    pub level: CompatibilityLevel,
    pub protocol_version: Option<u32>,
    pub endpoint: Option<EndpointEvidence>,
    pub features: Vec<FeatureDecision>,
    pub findings: Vec<CompatibilityFinding>,
}

impl CompatibilityStatus {
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Error)
    }

    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Warning)
    }
}

pub struct CompatibilityEvaluator<'a> {
    matrix: &'a CapabilityMatrix,
}

impl<'a> CompatibilityEvaluator<'a> {
    pub fn new(matrix: &'a CapabilityMatrix) -> Self {
        Self { matrix }
    }

    pub fn evaluate_protocol(&self, protocol_version: Option<u32>) -> CompatibilityStatus {
        self.evaluate(protocol_version, None, Utc::now())
    }

    pub fn evaluate_endpoint(
        &self,
        endpoint: EndpointEvidence,
        evaluated_at: DateTime<Utc>,
    ) -> CompatibilityStatus {
        self.evaluate(endpoint.protocol_version, Some(endpoint), evaluated_at)
    }

    pub fn evaluate(
        &self,
        protocol_version: Option<u32>,
        endpoint: Option<EndpointEvidence>,
        evaluated_at: DateTime<Utc>,
    ) -> CompatibilityStatus {
        let mut level = CompatibilityLevel::Compatible;
        let mut findings = Vec::new();
        match protocol_version {
            None => {
                level = level.merge(CompatibilityLevel::Unknown);
                findings.push(CompatibilityFinding::new(
                    "protocol.unknown",
                    FindingSeverity::Warning,
                    "protocol",
                    "The endpoint did not provide a protocol version.",
                    "Re-probe the endpoint and verify getLatestLedger returns protocolVersion.",
                ));
            }
            Some(version) if version < self.matrix.xdr.protocol.minimum => {
                level = CompatibilityLevel::Incompatible;
                findings.push(
                    CompatibilityFinding::new(
                        "protocol.too_old",
                        FindingSeverity::Error,
                        "protocol",
                        format!(
                            "Protocol {version} predates supported Soroban protocol {}.",
                            self.matrix.xdr.protocol.minimum
                        ),
                        "Upgrade the network or select a network running a supported protocol.",
                    )
                    .with_evidence("observed", version.to_string())
                    .with_evidence("minimum", self.matrix.xdr.protocol.minimum.to_string()),
                );
            }
            Some(version) if version > self.matrix.xdr.protocol.maximum => {
                level = CompatibilityLevel::Incompatible;
                findings.push(
                    CompatibilityFinding::new(
                        "protocol.future_unverified",
                        FindingSeverity::Error,
                        "protocol",
                        format!("Protocol {version} is newer than the evidence-backed matrix."),
                        "Upgrade StarForge/XDR support after validating the new protocol before submitting transactions.",
                    )
                    .with_evidence("observed", version.to_string())
                    .with_evidence("maximum_validated", self.matrix.xdr.protocol.maximum.to_string()),
                );
            }
            Some(version) => {
                let status = self
                    .matrix
                    .protocol(version)
                    .map(|entry| entry.status)
                    .unwrap_or(CompatibilityLevel::Unknown);
                level = level.merge(status);
                if status != CompatibilityLevel::Compatible {
                    findings.push(CompatibilityFinding::new(
                        "protocol.not_validated",
                        FindingSeverity::Warning,
                        "protocol",
                        format!("Protocol {version} has no fully compatible matrix entry."),
                        "Review the matrix evidence before running transaction commands.",
                    ));
                }
            }
        }

        if let Some(ref evidence) = endpoint {
            for required in self.matrix.required_probe_methods() {
                if !evidence.supported_methods.contains(&required) {
                    level = CompatibilityLevel::Incompatible;
                    findings.push(
                        CompatibilityFinding::new(
                            "rpc.required_method_missing",
                            FindingSeverity::Error,
                            "rpc",
                            format!("Required RPC method {required} is missing."),
                            "Upgrade or replace the RPC endpoint, then run compatibility probe again.",
                        )
                        .with_evidence("method", required),
                    );
                }
            }
            if let Some(horizon) = &evidence.horizon {
                if let (Some(rpc), Some(horizon_id)) =
                    (&evidence.network_identity, &horizon.network_identity)
                {
                    if rpc != horizon_id {
                        level = CompatibilityLevel::Incompatible;
                        findings.push(CompatibilityFinding::new(
                            "endpoint.network_identity_mismatch",
                            FindingSeverity::Error,
                            "endpoint",
                            "Horizon and Soroban RPC identify different networks.",
                            "Correct the configured endpoint pair before signing or submitting transactions.",
                        ));
                    }
                }
                if let (Some(rpc), Some(horizon_protocol)) =
                    (evidence.protocol_version, horizon.protocol_version)
                {
                    if rpc != horizon_protocol {
                        level = level.merge(CompatibilityLevel::Degraded);
                        findings.push(
                            CompatibilityFinding::new(
                                "endpoint.protocol_mismatch",
                                FindingSeverity::Warning,
                                "endpoint",
                                "Horizon and Soroban RPC report different protocol versions.",
                                "Wait for endpoint convergence or select a consistent endpoint pair.",
                            )
                            .with_evidence("rpc", rpc.to_string())
                            .with_evidence("horizon", horizon_protocol.to_string()),
                        );
                    }
                }
            }
            if evidence.retention_window == Some(0) {
                level = level.merge(CompatibilityLevel::Degraded);
                findings.push(CompatibilityFinding::new(
                    "rpc.no_retention",
                    FindingSeverity::Warning,
                    "retention",
                    "The RPC endpoint reports no retained historical ledger window.",
                    "Use an archival endpoint for fixture replay, event history, and upgrade audits.",
                ));
            }
            for warning in &evidence.warnings {
                findings.push(CompatibilityFinding::new(
                    "probe.warning",
                    FindingSeverity::Warning,
                    "probe",
                    warning.clone(),
                    "Review endpoint health and repeat the probe.",
                ));
                level = level.merge(CompatibilityLevel::Degraded);
            }
        }

        let mut features = Vec::new();
        for feature in &self.matrix.features {
            let decision = self.gate_feature(feature, protocol_version, endpoint.as_ref());
            level = level.merge(decision.level);
            if decision.level != CompatibilityLevel::Compatible {
                let severity = if decision.level == CompatibilityLevel::Incompatible {
                    FindingSeverity::Error
                } else {
                    FindingSeverity::Warning
                };
                findings.push(
                    CompatibilityFinding::new(
                        format!("feature.{}", feature.feature),
                        severity,
                        "feature",
                        format!(
                            "Feature {} is {} under the observed capabilities.",
                            feature.feature, decision.level
                        ),
                        decision.action.clone(),
                    )
                    .with_evidence(
                        "missing_required_methods",
                        decision
                            .missing_required_methods
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                );
            }
            features.push(decision);
        }
        findings.sort_by(|left, right| {
            right
                .severity
                .rank()
                .cmp(&left.severity.rank())
                .then_with(|| left.code.cmp(&right.code))
        });
        CompatibilityStatus {
            schema_version: COMPATIBILITY_SCHEMA_VERSION,
            matrix_version: self.matrix.matrix_version.clone(),
            evaluated_at,
            level,
            protocol_version,
            endpoint,
            features,
            findings,
        }
    }

    pub fn gate_named_feature(
        &self,
        name: &str,
        endpoint: Option<&EndpointEvidence>,
    ) -> Result<FeatureDecision, Box<CompatibilityFinding>> {
        let feature = self.matrix.feature(name).ok_or_else(|| {
            Box::new(CompatibilityFinding::new(
                "feature.unknown",
                FindingSeverity::Error,
                "feature",
                format!("Feature {name} is not declared in the capability matrix."),
                "Update the versioned compatibility matrix before using this feature.",
            ))
        })?;
        let protocol = endpoint.and_then(|value| value.protocol_version);
        Ok(self.gate_feature(feature, protocol, endpoint))
    }

    fn gate_feature(
        &self,
        feature: &FeatureCapability,
        protocol: Option<u32>,
        endpoint: Option<&EndpointEvidence>,
    ) -> FeatureDecision {
        let mut level = CompatibilityLevel::Compatible;
        if protocol.is_none() {
            level = CompatibilityLevel::Unknown;
        }
        if let Some(version) = protocol {
            if !feature.protocol.contains(version) {
                level = if feature.hard_requirement {
                    CompatibilityLevel::Incompatible
                } else {
                    CompatibilityLevel::Degraded
                };
            }
        }
        let mut missing_required_methods = BTreeSet::new();
        let mut missing_optional_methods = BTreeSet::new();
        if let Some(evidence) = endpoint {
            for method in &feature.required_methods {
                if !evidence.supported_methods.contains(method) {
                    missing_required_methods.insert(method.clone());
                }
            }
            for method in &feature.optional_methods {
                if !evidence.supported_methods.contains(method) {
                    missing_optional_methods.insert(method.clone());
                }
            }
            if !missing_required_methods.is_empty() {
                level = if feature.hard_requirement {
                    CompatibilityLevel::Incompatible
                } else {
                    CompatibilityLevel::Degraded
                };
            } else if !missing_optional_methods.is_empty() {
                level = level.merge(CompatibilityLevel::Degraded);
            }
        }
        FeatureDecision {
            feature: feature.feature.clone(),
            level,
            missing_required_methods,
            missing_optional_methods,
            action: feature.remediation.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityExport {
    pub schema_version: u32,
    pub exported_at: DateTime<Utc>,
    pub matrix: CapabilityMatrix,
    pub status: CompatibilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<crate::compatibility::audit::AuditReport>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn evidence(protocol: u32, methods: &[&str]) -> EndpointEvidence {
        let now = Utc.with_ymd_and_hms(2026, 8, 28, 12, 0, 0).unwrap();
        let mut value = EndpointEvidence::new("https://rpc.example".into(), "key", now);
        value.protocol_version = Some(protocol);
        value.supported_methods = string_set(methods);
        value
    }

    #[test]
    fn builtin_matrix_is_self_consistent() {
        assert!(CapabilityMatrix::builtin().validate().is_ok());
    }

    #[test]
    fn old_protocol_is_hard_incompatible() {
        let matrix = CapabilityMatrix::builtin();
        let status = CompatibilityEvaluator::new(&matrix).evaluate_protocol(Some(19));
        assert_eq!(status.level, CompatibilityLevel::Incompatible);
        assert!(status.findings.iter().any(|f| f.code == "protocol.too_old"));
    }

    #[test]
    fn unknown_future_protocol_is_not_assumed_safe() {
        let matrix = CapabilityMatrix::builtin();
        let status = CompatibilityEvaluator::new(&matrix).evaluate_protocol(Some(99));
        assert_eq!(status.level, CompatibilityLevel::Incompatible);
        assert!(status
            .findings
            .iter()
            .any(|f| f.code == "protocol.future_unverified"));
    }

    #[test]
    fn optional_feature_degrades_when_method_is_missing() {
        let matrix = CapabilityMatrix::builtin();
        let evidence = evidence(22, &["getHealth", "getNetwork", "getLatestLedger"]);
        let decision = CompatibilityEvaluator::new(&matrix)
            .gate_named_feature("contract_events", Some(&evidence))
            .unwrap();
        assert_eq!(decision.level, CompatibilityLevel::Degraded);
        assert!(decision.missing_required_methods.contains("getEvents"));
    }

    #[test]
    fn inconsistent_network_identity_is_hard_failure() {
        let matrix = CapabilityMatrix::builtin();
        let mut evidence = evidence(22, &["getHealth", "getNetwork", "getLatestLedger"]);
        evidence.network_identity = Some("sha256:a".into());
        evidence.horizon = Some(HorizonEvidence {
            display_endpoint: "https://horizon.example".into(),
            network_identity: Some("sha256:b".into()),
            latest_ledger: Some(1),
            protocol_version: Some(22),
            core_version: None,
        });
        let status = CompatibilityEvaluator::new(&matrix).evaluate_endpoint(
            evidence,
            Utc.with_ymd_and_hms(2026, 8, 28, 12, 0, 1).unwrap(),
        );
        assert_eq!(status.level, CompatibilityLevel::Incompatible);
        assert!(status
            .findings
            .iter()
            .any(|f| f.code == "endpoint.network_identity_mismatch"));
    }
}
