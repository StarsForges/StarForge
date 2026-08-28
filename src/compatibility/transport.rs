use crate::compatibility::domain::{
    network_identity, CapabilityMatrix, EndpointEvidence, HorizonEvidence,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeErrorKind {
    Timeout,
    Transport,
    InvalidResponse,
    Rpc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError {
    pub kind: ProbeErrorKind,
    pub endpoint: String,
    pub operation: String,
    pub detail: String,
}

impl ProbeError {
    fn new(
        kind: ProbeErrorKind,
        endpoint: impl Into<String>,
        operation: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            endpoint: endpoint.into(),
            operation: operation.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed for {}: {}",
            self.operation, self.endpoint, self.detail
        )
    }
}

impl Error for ProbeError {}

pub trait RpcTransport: Send + Sync {
    fn post_json(&self, endpoint: &str, body: &Value) -> Result<Value, ProbeError>;
    fn get_json(&self, endpoint: &str) -> Result<Value, ProbeError>;
}

#[derive(Clone)]
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new(timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .build();
        Self { agent }
    }

    fn parse_response(
        &self,
        response: ureq::Response,
        endpoint: &str,
        operation: &str,
    ) -> Result<Value, ProbeError> {
        response.into_json::<Value>().map_err(|_| {
            ProbeError::new(
                ProbeErrorKind::InvalidResponse,
                display_endpoint(endpoint),
                operation,
                "response body is not valid JSON",
            )
        })
    }

    fn transport_error(
        &self,
        error: ureq::Transport,
        endpoint: &str,
        operation: &str,
    ) -> ProbeError {
        let timeout = matches!(
            error.kind(),
            ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::Io
        ) && error
            .message()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("timed out");
        ProbeError::new(
            if timeout {
                ProbeErrorKind::Timeout
            } else {
                ProbeErrorKind::Transport
            },
            display_endpoint(endpoint),
            operation,
            if timeout {
                "bounded request timeout elapsed"
            } else {
                "endpoint transport failed"
            },
        )
    }
}

impl RpcTransport for UreqTransport {
    fn post_json(&self, endpoint: &str, body: &Value) -> Result<Value, ProbeError> {
        let request = self
            .agent
            .post(endpoint)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json");
        match request.send_json(body) {
            Ok(response) => self.parse_response(response, endpoint, "JSON-RPC request"),
            Err(ureq::Error::Status(_, response)) => {
                self.parse_response(response, endpoint, "JSON-RPC request")
            }
            Err(ureq::Error::Transport(error)) => {
                Err(self.transport_error(error, endpoint, "JSON-RPC request"))
            }
        }
    }

    fn get_json(&self, endpoint: &str) -> Result<Value, ProbeError> {
        match self
            .agent
            .get(endpoint)
            .set("Accept", "application/json")
            .call()
        {
            Ok(response) => self.parse_response(response, endpoint, "Horizon request"),
            Err(ureq::Error::Status(_, response)) => {
                self.parse_response(response, endpoint, "Horizon request")
            }
            Err(ureq::Error::Transport(error)) => {
                Err(self.transport_error(error, endpoint, "Horizon request"))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub probe_optional_methods: bool,
    pub include_horizon: bool,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            probe_optional_methods: true,
            include_horizon: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodSupport {
    Supported,
    Missing,
}

#[derive(Debug, Clone)]
struct RpcReply {
    result: Option<Value>,
    support: MethodSupport,
    warning: Option<String>,
}

pub struct EndpointProber<T> {
    transport: T,
    matrix: CapabilityMatrix,
    options: ProbeOptions,
}

impl<T: RpcTransport> EndpointProber<T> {
    pub fn new(transport: T, matrix: CapabilityMatrix, options: ProbeOptions) -> Self {
        Self {
            transport,
            matrix,
            options,
        }
    }

    pub fn probe(
        &self,
        rpc_endpoint: &str,
        horizon_endpoint: Option<&str>,
    ) -> Result<EndpointEvidence, ProbeError> {
        self.probe_at(rpc_endpoint, horizon_endpoint, Utc::now())
    }

    pub fn probe_at(
        &self,
        rpc_endpoint: &str,
        horizon_endpoint: Option<&str>,
        observed_at: DateTime<Utc>,
    ) -> Result<EndpointEvidence, ProbeError> {
        validate_endpoint(rpc_endpoint)?;
        if let Some(endpoint) = horizon_endpoint {
            validate_endpoint(endpoint)?;
        }
        let mut evidence =
            EndpointEvidence::new(display_endpoint(rpc_endpoint), rpc_endpoint, observed_at);

        let discovery = self.rpc_call(rpc_endpoint, "rpc.discover", json!({}), 1)?;
        let discovered_methods = discovery
            .result
            .as_ref()
            .map(discover_method_names)
            .unwrap_or_default();
        if discovery.support == MethodSupport::Supported {
            evidence.supported_methods.insert("rpc.discover".into());
        } else {
            evidence.missing_methods.insert("rpc.discover".into());
        }
        let known = self.matrix.known_methods();
        for method in &discovered_methods {
            if known.contains(method) {
                evidence.supported_methods.insert(method.clone());
            } else {
                evidence.vendor_extensions.insert(method.clone());
            }
        }
        if let Some(warning) = discovery.warning {
            evidence.warnings.push(warning);
        }

        let network = self.rpc_call(rpc_endpoint, "getNetwork", json!({}), 2)?;
        self.record_support(&mut evidence, "getNetwork", &network);
        if let Some(result) = network.result.as_ref() {
            let passphrase = string_field(result, &["passphrase", "networkPassphrase"]);
            evidence.network_identity = passphrase.map(network_identity);
            evidence.protocol_version = u32_field(result, &["protocolVersion", "protocol_version"]);
        }

        let latest = self.rpc_call(rpc_endpoint, "getLatestLedger", json!({}), 3)?;
        self.record_support(&mut evidence, "getLatestLedger", &latest);
        if let Some(result) = latest.result.as_ref() {
            evidence.latest_ledger = u64_field(
                result,
                &["sequence", "ledger", "latestLedger", "latest_ledger"],
            );
            evidence.protocol_version = u32_field(result, &["protocolVersion", "protocol_version"])
                .or(evidence.protocol_version);
        }

        let health = self.rpc_call(rpc_endpoint, "getHealth", json!({}), 4)?;
        self.record_support(&mut evidence, "getHealth", &health);
        if let Some(result) = health.result.as_ref() {
            evidence.oldest_ledger = u64_field(
                result,
                &["oldestLedger", "oldest_ledger", "oldestLedgerSequence"],
            );
            evidence.latest_ledger = u64_field(
                result,
                &["latestLedger", "latest_ledger", "latestLedgerSequence"],
            )
            .or(evidence.latest_ledger);
            evidence.retention_window = u64_field(
                result,
                &[
                    "ledgerRetentionWindow",
                    "retentionWindow",
                    "retention_window",
                ],
            )
            .or_else(|| {
                evidence
                    .latest_ledger
                    .zip(evidence.oldest_ledger)
                    .map(|(latest, oldest)| latest.saturating_sub(oldest).saturating_add(1))
            });
            evidence.limits.extend(extract_limits(result));
        }

        let version = self.rpc_call(rpc_endpoint, "getVersionInfo", json!({}), 5)?;
        self.record_support(&mut evidence, "getVersionInfo", &version);
        if let Some(result) = version.result.as_ref() {
            evidence.rpc_version = string_field(
                result,
                &["version", "versionString", "commitHash", "commit_hash"],
            )
            .map(ToOwned::to_owned);
            evidence.limits.extend(extract_limits(result));
        }

        let core_methods: BTreeSet<String> = [
            "rpc.discover",
            "getNetwork",
            "getLatestLedger",
            "getHealth",
            "getVersionInfo",
        ]
        .iter()
        .map(|value| (*value).to_string())
        .collect();
        if self.options.probe_optional_methods {
            for (index, method) in known.difference(&core_methods).enumerate() {
                if !discovered_methods.is_empty() {
                    if discovered_methods.contains(method) {
                        evidence.supported_methods.insert(method.clone());
                    } else {
                        evidence.missing_methods.insert(method.clone());
                    }
                    continue;
                }
                let reply = self.rpc_call(
                    rpc_endpoint,
                    method,
                    safe_probe_params(method),
                    100 + index as u64,
                )?;
                self.record_support(&mut evidence, method, &reply);
            }
        }

        if self.options.include_horizon {
            if let Some(endpoint) = horizon_endpoint {
                match self.probe_horizon(endpoint) {
                    Ok(horizon) => evidence.horizon = Some(horizon),
                    Err(error) => evidence.warnings.push(format!(
                        "Horizon evidence was unavailable: {} ({:?})",
                        error.detail, error.kind
                    )),
                }
            }
        }
        evidence.warnings.sort();
        evidence.warnings.dedup();
        Ok(evidence)
    }

    fn rpc_call(
        &self,
        endpoint: &str,
        method: &str,
        params: Value,
        id: u64,
    ) -> Result<RpcReply, ProbeError> {
        let response = self.transport.post_json(
            endpoint,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )?;
        parse_rpc_reply(&response, method, endpoint)
    }

    fn record_support(&self, evidence: &mut EndpointEvidence, method: &str, reply: &RpcReply) {
        match reply.support {
            MethodSupport::Supported => {
                evidence.supported_methods.insert(method.into());
                evidence.missing_methods.remove(method);
            }
            MethodSupport::Missing => {
                evidence.missing_methods.insert(method.into());
                evidence.supported_methods.remove(method);
            }
        }
        if let Some(warning) = &reply.warning {
            evidence.warnings.push(warning.clone());
        }
    }

    fn probe_horizon(&self, endpoint: &str) -> Result<HorizonEvidence, ProbeError> {
        let value = self.transport.get_json(endpoint)?;
        if !value.is_object() {
            return Err(ProbeError::new(
                ProbeErrorKind::InvalidResponse,
                display_endpoint(endpoint),
                "Horizon request",
                "root response must be a JSON object",
            ));
        }
        let passphrase = string_field(
            &value,
            &["network_passphrase", "networkPassphrase", "passphrase"],
        );
        Ok(HorizonEvidence {
            display_endpoint: display_endpoint(endpoint),
            network_identity: passphrase.map(network_identity),
            latest_ledger: u64_field(
                &value,
                &[
                    "history_latest_ledger",
                    "historyLatestLedger",
                    "latest_ledger",
                ],
            ),
            protocol_version: u32_field(
                &value,
                &[
                    "current_protocol_version",
                    "protocolVersion",
                    "protocol_version",
                ],
            ),
            core_version: string_field(&value, &["core_version", "coreVersion"])
                .map(ToOwned::to_owned),
        })
    }
}

fn parse_rpc_reply(response: &Value, method: &str, endpoint: &str) -> Result<RpcReply, ProbeError> {
    let object = response.as_object().ok_or_else(|| {
        ProbeError::new(
            ProbeErrorKind::InvalidResponse,
            display_endpoint(endpoint),
            method,
            "JSON-RPC response must be an object",
        )
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ProbeError::new(
            ProbeErrorKind::InvalidResponse,
            display_endpoint(endpoint),
            method,
            "missing JSON-RPC 2.0 marker",
        ));
    }
    if let Some(error) = object.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        let missing = code == -32601
            || error
                .get("message")
                .and_then(Value::as_str)
                .map(|message| message.to_ascii_lowercase().contains("method not found"))
                .unwrap_or(false);
        return Ok(RpcReply {
            result: None,
            support: if missing {
                MethodSupport::Missing
            } else {
                MethodSupport::Supported
            },
            warning: if missing || code == -32602 {
                None
            } else {
                Some(format!("RPC method {method} returned error code {code}"))
            },
        });
    }
    let result = object.get("result").cloned().ok_or_else(|| {
        ProbeError::new(
            ProbeErrorKind::InvalidResponse,
            display_endpoint(endpoint),
            method,
            "JSON-RPC response contains neither result nor error",
        )
    })?;
    Ok(RpcReply {
        result: Some(result),
        support: MethodSupport::Supported,
        warning: None,
    })
}

fn safe_probe_params(method: &str) -> Value {
    match method {
        "getEvents" | "getTransactions" | "getLedgers" => json!({"startLedger": 0, "limit": 1}),
        "getLedgerEntries" => json!({"keys": []}),
        "getTransaction" => json!({"hash": "compatibility-probe-invalid-hash"}),
        "simulateTransaction" | "sendTransaction" => {
            json!({"transaction": "compatibility-probe-invalid-envelope"})
        }
        _ => json!({}),
    }
}

fn discover_method_names(value: &Value) -> BTreeSet<String> {
    let methods = value
        .get("methods")
        .or_else(|| value.pointer("/openrpc/methods"))
        .or_else(|| value.pointer("/schema/methods"));
    methods
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("name").and_then(Value::as_str))
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn string_field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
}

fn u64_field(value: &Value, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        value
            .get(*name)
            .and_then(|field| field.as_u64().or_else(|| field.as_str()?.parse().ok()))
    })
}

fn u32_field(value: &Value, names: &[&str]) -> Option<u32> {
    u64_field(value, names).and_then(|field| u32::try_from(field).ok())
}

fn extract_limits(value: &Value) -> BTreeMap<String, u64> {
    let mut limits = BTreeMap::new();
    let Some(object) = value.as_object() else {
        return limits;
    };
    for (key, field) in object {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains("limit")
            || normalized.starts_with("max")
            || normalized.contains("retention")
        {
            if let Some(number) = field
                .as_u64()
                .or_else(|| field.as_str().and_then(|item| item.parse().ok()))
            {
                limits.insert(key.clone(), number);
            }
        }
    }
    limits
}

pub fn validate_endpoint(endpoint: &str) -> Result<(), ProbeError> {
    let display = display_endpoint(endpoint);
    let valid_scheme = endpoint.starts_with("https://") || endpoint.starts_with("http://");
    let authority = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if !valid_scheme || authority.is_empty() || authority.ends_with('@') {
        return Err(ProbeError::new(
            ProbeErrorKind::Transport,
            display,
            "endpoint validation",
            "endpoint must be an absolute HTTP(S) URL with a host",
        ));
    }
    Ok(())
}

pub fn display_endpoint(endpoint: &str) -> String {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return "<invalid-endpoint>".into();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    if host.is_empty() {
        return format!("{scheme}://<redacted>");
    }
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct MockTransport {
        replies: Arc<Mutex<BTreeMap<String, Value>>>,
        horizon: Arc<Mutex<Option<Value>>>,
    }

    impl MockTransport {
        fn reply(self, method: &str, value: Value) -> Self {
            self.replies.lock().unwrap().insert(method.into(), value);
            self
        }

        fn horizon(self, value: Value) -> Self {
            *self.horizon.lock().unwrap() = Some(value);
            self
        }
    }

    impl RpcTransport for MockTransport {
        fn post_json(&self, _endpoint: &str, body: &Value) -> Result<Value, ProbeError> {
            let method = body.get("method").and_then(Value::as_str).unwrap();
            Ok(self
                .replies
                .lock()
                .unwrap()
                .get(method)
                .cloned()
                .unwrap_or_else(|| {
                    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}})
                }))
        }

        fn get_json(&self, _endpoint: &str) -> Result<Value, ProbeError> {
            self.horizon
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| ProbeError::new(ProbeErrorKind::Transport, "mock", "get", "missing"))
        }
    }

    fn rpc(result: Value) -> Value {
        json!({"jsonrpc":"2.0","id":1,"result":result})
    }

    #[test]
    fn probe_collects_protocol_retention_methods_and_vendor_extensions() {
        let transport = MockTransport::default()
            .reply(
                "rpc.discover",
                rpc(json!({"methods":[
                    {"name":"getNetwork"},{"name":"getLatestLedger"},
                    {"name":"getHealth"},{"name":"vendor.trace"}
                ]})),
            )
            .reply(
                "getNetwork",
                rpc(json!({"passphrase":"Test SDF Network ; September 2015","protocolVersion":22})),
            )
            .reply(
                "getLatestLedger",
                rpc(json!({"sequence":500,"protocolVersion":22})),
            )
            .reply(
                "getHealth",
                rpc(json!({"oldestLedger":401,"latestLedger":500,"maxHealthyLedgerLatency":30})),
            )
            .reply("getVersionInfo", rpc(json!({"version":"22.1.0"})))
            .horizon(json!({
                "network_passphrase":"Test SDF Network ; September 2015",
                "history_latest_ledger":500,
                "current_protocol_version":22
            }));
        let prober = EndpointProber::new(
            transport,
            CapabilityMatrix::builtin(),
            ProbeOptions::default(),
        );
        let at = Utc.with_ymd_and_hms(2026, 8, 28, 12, 0, 0).unwrap();
        let evidence = prober
            .probe_at(
                "https://user:secret@rpc.example/path?token=secret",
                Some("https://horizon.example/api?key=secret"),
                at,
            )
            .unwrap();
        assert_eq!(evidence.display_endpoint, "https://rpc.example");
        assert_eq!(evidence.protocol_version, Some(22));
        assert_eq!(evidence.retention_window, Some(100));
        assert!(evidence.vendor_extensions.contains("vendor.trace"));
        assert_eq!(
            evidence.horizon.as_ref().unwrap().display_endpoint,
            "https://horizon.example"
        );
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn malformed_json_rpc_response_is_rejected() {
        let transport = MockTransport::default().reply("rpc.discover", json!({"result": {}}));
        let prober = EndpointProber::new(
            transport,
            CapabilityMatrix::builtin(),
            ProbeOptions::default(),
        );
        let error = prober.probe("https://rpc.example", None).unwrap_err();
        assert_eq!(error.kind, ProbeErrorKind::InvalidResponse);
    }

    #[test]
    fn invalid_params_proves_method_exists() {
        let value =
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}});
        let parsed = parse_rpc_reply(&value, "sendTransaction", "https://rpc.example").unwrap();
        assert_eq!(parsed.support, MethodSupport::Supported);
    }

    #[test]
    fn endpoint_display_redacts_credentials_paths_and_queries() {
        assert_eq!(
            display_endpoint("https://alice:password@example.test:443/rpc?api_key=secret"),
            "https://example.test:443"
        );
    }
}
