//! Read-only Soroban RPC execution and evidence construction.

use super::model::{
    Evidence, EvidenceSource, Finding, QueryPlan, QueryReport, ReadOnlyQuery, ReportStatus,
    REPORT_SCHEMA_VERSION,
};
use super::safety;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::{json, Value};
use stellar_strkey::Contract;
use stellar_xdr::curr::{
    ContractDataDurability, Hash, LedgerKey, LedgerKeyContractData, Limits, ScAddress, ScVal,
    WriteXdr,
};

const ALLOWED_RPC_METHODS: &[&str] = &[
    "getLatestLedger",
    "getLedgerEntries",
    "getEvents",
    "getTransaction",
];

pub trait RpcTransport {
    fn endpoint(&self) -> &str;
    fn call(&self, method: &str, params: Value) -> Result<Value>;
}

pub struct HttpRpcTransport {
    endpoint: String,
}

impl HttpRpcTransport {
    pub fn for_network(network: &str, override_url: Option<&str>) -> Result<Self> {
        crate::utils::config::validate_network(network)?;
        let endpoint = match override_url {
            Some(url) => url.to_string(),
            None => crate::utils::soroban::rpc_url(network)?,
        };
        validate_rpc_endpoint(&endpoint)?;
        Ok(Self { endpoint })
    }
}

impl RpcTransport for HttpRpcTransport {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        if !ALLOWED_RPC_METHODS.contains(&method) {
            anyhow::bail!("RPC method '{}' is not in the read-only allowlist.", method);
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response: Value = ureq::post(&self.endpoint)
            .set("Content-Type", "application/json")
            .send_json(body)
            .with_context(|| format!("Soroban RPC {} request failed", method))?
            .into_json()
            .with_context(|| format!("Soroban RPC {} response was not valid JSON", method))?;
        if let Some(error) = response.get("error") {
            anyhow::bail!(
                "Soroban RPC {} failed: {}",
                method,
                summarize_rpc_error(error)
            );
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Soroban RPC {} returned no result", method))
    }
}

pub fn execute(plan: QueryPlan, transport: &dyn RpcTransport) -> Result<QueryReport> {
    safety::validate_plan(&plan)?;
    let endpoint = safe_endpoint_origin(transport.endpoint());
    let mut findings = Vec::with_capacity(plan.operations.len());
    let mut evidence = Vec::with_capacity(plan.operations.len());
    let mut failures = 0usize;

    for operation in &plan.operations {
        let evidence_id = format!("evidence-{}", evidence.len() + 1);
        let (method, params, response) = execute_query(&operation.query, transport)?;
        let result = match response {
            Ok(result) => result,
            Err(error) => {
                failures += 1;
                json!({ "error": safety::redact_text(&format!("{error:#}")) })
            }
        };
        let statement = summarize_result(&operation.query, &result);
        evidence.push(Evidence {
            id: evidence_id.clone(),
            operation_id: operation.id.clone(),
            source: EvidenceSource {
                kind: "soroban_rpc".to_string(),
                network: plan.network.clone(),
                endpoint: endpoint.clone(),
            },
            method,
            request: safety::redact_json(&params),
            result: safety::redact_json(&result),
        });
        findings.push(Finding {
            operation_id: operation.id.clone(),
            statement,
            evidence_ids: vec![evidence_id],
        });
    }

    let success_count = plan.operations.len() - failures;
    let status = if failures == 0 {
        ReportStatus::Complete
    } else {
        ReportStatus::Partial
    };
    let summary = if failures == 0 {
        format!(
            "Completed {} read-only operation{} with linked RPC evidence.",
            success_count,
            plural(success_count)
        )
    } else {
        format!(
            "Completed {} of {} read-only operations; {} failed. See linked evidence for details.",
            success_count,
            plan.operations.len(),
            failures
        )
    };

    Ok(QueryReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        status,
        question: plan.question.clone(),
        network: plan.network.clone(),
        summary,
        findings,
        evidence,
        plan,
    })
}

fn execute_query(
    query: &ReadOnlyQuery,
    transport: &dyn RpcTransport,
) -> Result<(String, Value, Result<Value>)> {
    if let ReadOnlyQuery::ContractEvents {
        contract_id,
        topic,
        limit,
    } = query
    {
        // getEvents needs a recent start ledger. Resolve it at execution time
        // instead of baking a stale sequence into a persistent plan.
        let latest_params = json!({});
        let latest = match transport.call("getLatestLedger", latest_params.clone()) {
            Ok(result) => result,
            Err(error) => {
                return Ok((
                    "getLatestLedger".to_string(),
                    latest_params,
                    Err(error.context("Could not establish an event-query ledger window")),
                ));
            }
        };
        let sequence = latest
            .get("sequence")
            .or_else(|| latest.get("latestLedger"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                anyhow::anyhow!("getLatestLedger response did not contain a numeric sequence")
            })?;
        let start_ledger = sequence.saturating_sub(1_000).max(1);
        let params = event_params(contract_id, topic.as_deref(), *limit, start_ledger);
        let response = transport.call("getEvents", params.clone());
        return Ok(("getEvents".to_string(), params, response));
    }

    let (method, params) = rpc_request(query)?;
    let response = transport.call(method, params.clone());
    Ok((method.to_string(), params, response))
}

fn rpc_request(query: &ReadOnlyQuery) -> Result<(&'static str, Value)> {
    match query {
        ReadOnlyQuery::LatestLedger => Ok(("getLatestLedger", json!({}))),
        ReadOnlyQuery::ContractState { contract_id }
        | ReadOnlyQuery::ContractStorage { contract_id, .. } => Ok((
            "getLedgerEntries",
            json!({
                "keys": [contract_instance_key_xdr(contract_id)?],
                "xdrFormat": "base64"
            }),
        )),
        ReadOnlyQuery::ContractEvents { .. } => {
            anyhow::bail!("Event queries require a dynamic ledger window")
        }
        ReadOnlyQuery::Transaction { hash } => Ok(("getTransaction", json!({ "hash": hash }))),
    }
}

fn event_params(contract_id: &str, topic: Option<&str>, limit: u32, start_ledger: u64) -> Value {
    let mut filter = json!({
        "type": "contract",
        "contractIds": [contract_id]
    });
    if let Some(topic) = topic {
        filter["topics"] = json!([[topic]]);
    }
    json!({
        "startLedger": start_ledger,
        "filters": [filter],
        "pagination": { "limit": limit }
    })
}

fn contract_instance_key_xdr(contract_id: &str) -> Result<String> {
    let contract = Contract::from_string(contract_id).map_err(|_| {
        anyhow::anyhow!("Contract ID passed syntax validation but has an invalid checksum")
    })?;
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract.0)),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let bytes = key
        .to_xdr(Limits::none())
        .context("Failed to encode contract ledger key as XDR")?;
    Ok(BASE64.encode(bytes))
}

fn summarize_result(query: &ReadOnlyQuery, result: &Value) -> String {
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        return format!("Query failed: {}", safety::redact_text(error));
    }
    match query {
        ReadOnlyQuery::LatestLedger => {
            let sequence = result
                .get("sequence")
                .or_else(|| result.get("latestLedger"))
                .map(compact_value)
                .unwrap_or_else(|| "unknown".to_string());
            format!("The latest reported ledger sequence is {}.", sequence)
        }
        ReadOnlyQuery::ContractState { contract_id } => {
            let count = result
                .get("entries")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            format!(
                "Contract {} returned {} instance ledger entr{}.",
                contract_id,
                count,
                if count == 1 { "y" } else { "ies" }
            )
        }
        ReadOnlyQuery::ContractStorage { contract_id, key } => {
            let count = result
                .get("entries")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            match key {
                Some(key) => format!(
                    "Contract {} storage evidence for key '{}' contains {} instance entr{}; inspect the linked XDR evidence for the encoded value.",
                    contract_id,
                    safety::redact_text(key),
                    count,
                    if count == 1 { "y" } else { "ies" }
                ),
                None => format!(
                    "Contract {} returned {} storage-bearing instance entr{}.",
                    contract_id,
                    count,
                    if count == 1 { "y" } else { "ies" }
                ),
            }
        }
        ReadOnlyQuery::ContractEvents { contract_id, .. } => {
            let count = result
                .get("events")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            format!(
                "Found {} recent event{} for contract {}.",
                count,
                plural(count),
                contract_id
            )
        }
        ReadOnlyQuery::Transaction { hash } => {
            let status = result
                .get("status")
                .map(compact_value)
                .unwrap_or_else(|| "unknown".to_string());
            format!("Transaction {} has status {}.", hash, status)
        }
    }
}

fn compact_value(value: &Value) -> String {
    match value {
        Value::String(text) => safety::redact_text(text),
        other => other.to_string(),
    }
}

fn summarize_rpc_error(error: &Value) -> String {
    let code = error.get("code").map(Value::to_string).unwrap_or_default();
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown RPC error");
    safety::redact_text(format!("{} {}", code, message).trim())
}

fn safe_endpoint_origin(endpoint: &str) -> String {
    let without_scheme = endpoint
        .split_once("://")
        .map(|(scheme, rest)| (format!("{}://", scheme), rest))
        .unwrap_or_else(|| (String::new(), endpoint));
    let authority = without_scheme
        .1
        .split('/')
        .next()
        .unwrap_or("[invalid-endpoint]");
    let authority_without_credentials = authority.rsplit('@').next().unwrap_or(authority);
    format!("{}{}", without_scheme.0, authority_without_credentials)
}

fn validate_rpc_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.trim().is_empty() {
        anyhow::bail!("Soroban RPC endpoint cannot be empty.");
    }
    if endpoint.contains('@') {
        anyhow::bail!("Soroban RPC endpoint must not contain embedded credentials.");
    }
    let lower = endpoint.to_ascii_lowercase();
    if !(lower.starts_with("https://")
        || lower.starts_with("http://127.0.0.1:")
        || lower.starts_with("http://localhost:"))
    {
        anyhow::bail!(
            "Soroban RPC endpoint must use HTTPS (plain HTTP is allowed only for localhost development)."
        );
    }
    Ok(())
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::query::model::{PlanSource, PlannedOperation, QueryPlan};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FixtureTransport {
        responses: Mutex<VecDeque<Result<Value>>>,
    }

    impl RpcTransport for FixtureTransport {
        fn endpoint(&self) -> &str {
            "https://rpc.example.test/path?token=hidden"
        }

        fn call(&self, method: &str, _params: Value) -> Result<Value> {
            assert!(ALLOWED_RPC_METHODS.contains(&method));
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    #[test]
    fn creates_stable_linked_evidence() {
        let plan = QueryPlan::new(
            "current ledger",
            "testnet",
            PlanSource::Deterministic,
            vec![PlannedOperation {
                id: "op-1".to_string(),
                query: ReadOnlyQuery::LatestLedger,
                rationale: "Read latest ledger.".to_string(),
            }],
        );
        let transport = FixtureTransport {
            responses: Mutex::new(VecDeque::from([Ok(json!({ "sequence": 42 }))])),
        };
        let report = execute(plan, &transport).unwrap();
        assert_eq!(report.status, ReportStatus::Complete);
        assert_eq!(report.findings[0].evidence_ids, ["evidence-1"]);
        assert_eq!(
            report.evidence[0].source.endpoint,
            "https://rpc.example.test"
        );
    }

    #[test]
    fn encodes_real_contract_instance_xdr() {
        let contract_id = Contract([7; 32]).to_string();
        let encoded = contract_instance_key_xdr(&contract_id).unwrap();
        assert!(!BASE64.decode(encoded).unwrap().is_empty());
    }

    #[test]
    fn records_rpc_failure_as_partial_evidence() {
        let plan = QueryPlan::new(
            "current ledger",
            "testnet",
            PlanSource::Deterministic,
            vec![PlannedOperation {
                id: "op-1".to_string(),
                query: ReadOnlyQuery::LatestLedger,
                rationale: "Read latest ledger.".to_string(),
            }],
        );
        let transport = FixtureTransport {
            responses: Mutex::new(VecDeque::from([Err(anyhow::anyhow!("offline"))])),
        };
        let report = execute(plan, &transport).unwrap();
        assert_eq!(report.status, ReportStatus::Partial);
        assert_eq!(report.evidence[0].result["error"], "offline");
    }

    #[test]
    fn event_query_uses_a_recent_dynamic_ledger_window() {
        let query = ReadOnlyQuery::ContractEvents {
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            topic: None,
            limit: 5,
        };
        let transport = FixtureTransport {
            responses: Mutex::new(VecDeque::from([
                Ok(json!({ "sequence": 10_000 })),
                Ok(json!({ "events": [] })),
            ])),
        };
        let (method, params, result) = execute_query(&query, &transport).unwrap();
        assert_eq!(method, "getEvents");
        assert_eq!(params["startLedger"], 9_000);
        assert!(result.is_ok());
    }
}
