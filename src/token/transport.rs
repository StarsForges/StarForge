//! Soroban RPC transport for token read/simulate operations.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct RpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

pub trait TokenRpcTransport: Send + Sync {
    fn simulate_contract_call(
        &self,
        network: &str,
        contract_id: &str,
        function: &str,
        args: &[String],
        arg_types: &[String],
    ) -> Result<SimulateResponse>;

    fn get_contract_spec(&self, network: &str, contract_id: &str) -> Result<String>;

    fn latest_ledger(&self, network: &str) -> Result<u32>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulateResponse {
    pub return_value: Option<String>,
    pub return_raw: Option<i128>,
    pub fee_stroops: u64,
    pub events: Vec<String>,
    pub errors: Vec<String>,
    pub auth: Vec<String>,
}

pub struct UreqTokenTransport {
    timeout: Duration,
}

impl Default for UreqTokenTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(5_000),
        }
    }
}

impl UreqTokenTransport {
    pub fn with_timeout_ms(ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(ms),
        }
    }

    fn rpc_url(&self, network: &str) -> Result<String> {
        crate::utils::soroban::rpc_url(network)
    }

    fn post<T: DeserializeOwned>(&self, url: &str, request: &RpcRequest) -> Result<T> {
        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let response = agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_json(request)
            .context("token RPC request failed")?;
        let parsed: RpcResponse<T> = response.into_json().context("invalid RPC JSON")?;
        if let Some(err) = parsed.error {
            anyhow::bail!("RPC error: {err}");
        }
        parsed
            .result
            .context("RPC response missing result field")
    }
}

impl TokenRpcTransport for UreqTokenTransport {
    fn simulate_contract_call(
        &self,
        network: &str,
        contract_id: &str,
        function: &str,
        args: &[String],
        arg_types: &[String],
    ) -> Result<SimulateResponse> {
        let sim = crate::utils::soroban::simulate_transaction(
            contract_id,
            function,
            args,
            arg_types,
            network,
        )?;
        Ok(SimulateResponse {
            return_value: Some(sim.return_value.clone()),
            return_raw: parse_i128_return(&sim.return_value),
            fee_stroops: sim.fee,
            events: sim.events,
            errors: sim.errors,
            auth: vec![],
        })
    }

    fn get_contract_spec(&self, network: &str, contract_id: &str) -> Result<String> {
        let url = self.rpc_url(network)?;
        let request = RpcRequest {
            jsonrpc: "2.0".into(),
            id: 1,
            method: "getContractSpec".into(),
            params: serde_json::json!({ "contractId": contract_id }),
        };
        let result: serde_json::Value = self.post(&url, &request)?;
        Ok(result.to_string())
    }

    fn latest_ledger(&self, network: &str) -> Result<u32> {
        let url = self.rpc_url(network)?;
        let request = RpcRequest {
            jsonrpc: "2.0".into(),
            id: 1,
            method: "getLatestLedger".into(),
            params: serde_json::json!({}),
        };
        #[derive(Deserialize)]
        struct Latest {
            #[serde(rename = "sequence")]
            seq: u32,
        }
        let result: Latest = self.post(&url, &request)?;
        Ok(result.seq)
    }
}

/// Deterministic in-memory transport for tests.
pub struct MockTokenTransport {
    pub spec_json: String,
    pub responses: std::collections::BTreeMap<String, SimulateResponse>,
    pub latest_ledger: u32,
}

impl MockTokenTransport {
    pub fn from_fixture_spec(spec_json: &str) -> Self {
        Self {
            spec_json: spec_json.to_string(),
            responses: default_mock_responses(),
            latest_ledger: 1_000_000,
        }
    }

    pub fn key(function: &str, args: &[String]) -> String {
        format!("{function}:{}", args.join(","))
    }
}

impl TokenRpcTransport for MockTokenTransport {
    fn simulate_contract_call(
        &self,
        _network: &str,
        _contract_id: &str,
        function: &str,
        args: &[String],
        _arg_types: &[String],
    ) -> Result<SimulateResponse> {
        let key = Self::key(function, args);
        self.responses
            .get(&key)
            .or_else(|| self.responses.get(function))
            .cloned()
            .context(format!("no mock response for {key}"))
    }

    fn get_contract_spec(&self, _network: &str, _contract_id: &str) -> Result<String> {
        Ok(self.spec_json.clone())
    }

    fn latest_ledger(&self, _network: &str) -> Result<u32> {
        Ok(self.latest_ledger)
    }
}

fn parse_i128_return(value: &str) -> Option<i128> {
    value.parse().ok()
}

pub enum AnyTokenTransport {
    Live(UreqTokenTransport),
    Mock(MockTokenTransport),
}

impl TokenRpcTransport for AnyTokenTransport {
    fn simulate_contract_call(
        &self,
        network: &str,
        contract_id: &str,
        function: &str,
        args: &[String],
        arg_types: &[String],
    ) -> Result<SimulateResponse> {
        match self {
            Self::Live(t) => {
                t.simulate_contract_call(network, contract_id, function, args, arg_types)
            }
            Self::Mock(t) => {
                t.simulate_contract_call(network, contract_id, function, args, arg_types)
            }
        }
    }

    fn get_contract_spec(&self, network: &str, contract_id: &str) -> Result<String> {
        match self {
            Self::Live(t) => t.get_contract_spec(network, contract_id),
            Self::Mock(t) => t.get_contract_spec(network, contract_id),
        }
    }

    fn latest_ledger(&self, network: &str) -> Result<u32> {
        match self {
            Self::Live(t) => t.latest_ledger(network),
            Self::Mock(t) => t.latest_ledger(network),
        }
    }
}

fn default_mock_responses() -> std::collections::BTreeMap<String, SimulateResponse> {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "name".into(),
        SimulateResponse {
            return_value: Some("\"TestToken\"".into()),
            return_raw: None,
            fee_stroops: 100,
            events: vec![],
            errors: vec![],
            auth: vec![],
        },
    );
    map.insert(
        "symbol".into(),
        SimulateResponse {
            return_value: Some("\"TST\"".into()),
            return_raw: None,
            fee_stroops: 100,
            events: vec![],
            errors: vec![],
            auth: vec![],
        },
    );
    map.insert(
        "decimals".into(),
        SimulateResponse {
            return_value: Some("7".into()),
            return_raw: Some(7),
            fee_stroops: 100,
            events: vec![],
            errors: vec![],
            auth: vec![],
        },
    );
    map.insert(
        "balance".into(),
        SimulateResponse {
            return_value: Some("1500000000".into()),
            return_raw: Some(1_500_000_000),
            fee_stroops: 100,
            events: vec![],
            errors: vec![],
            auth: vec![],
        },
    );
    map.insert(
        "allowance".into(),
        SimulateResponse {
            return_value: Some("500000000".into()),
            return_raw: Some(500_000_000),
            fee_stroops: 100,
            events: vec![],
            errors: vec![],
            auth: vec![],
        },
    );
    map.insert(
        "transfer".into(),
        SimulateResponse {
            return_value: Some("void".into()),
            return_raw: None,
            fee_stroops: 12_345,
            events: vec!["transfer".into()],
            errors: vec![],
            auth: vec![],
        },
    );
    map.insert(
        "approve".into(),
        SimulateResponse {
            return_value: Some("void".into()),
            return_raw: None,
            fee_stroops: 11_000,
            events: vec![],
            errors: vec![],
            auth: vec![],
        },
    );
    for function in ["mint", "burn", "set_admin", "set_authorized"] {
        map.insert(
            function.into(),
            SimulateResponse {
                return_value: Some("void".into()),
                return_raw: None,
                fee_stroops: 10_000,
                events: vec![function.into()],
                errors: vec![],
                auth: vec![],
            },
        );
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::spec::builtin_test_token_spec;

    #[test]
    fn mock_transport_returns_balance() {
        let transport = MockTokenTransport::from_fixture_spec(builtin_test_token_spec());
        let resp = transport
            .simulate_contract_call(
                "testnet",
                "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A",
                "balance",
                &["GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T".into()],
                &["address".into()],
            )
            .unwrap();
        assert_eq!(resp.return_raw, Some(1_500_000_000));
    }
}
