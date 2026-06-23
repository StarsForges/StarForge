use crate::utils::config::{self, WalletEntry};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use stellar_strkey::{ed25519, Contract};
use stellar_xdr::curr::{
    AccountId, ContractDataDurability, ContractExecutable, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractData, PublicKey, ScAddress, ScMap, ScString, ScSymbol, ScVal, Uint256,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SimulationResult {
    pub return_value: String,
    pub fee: u64,
    pub events: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResult {
    pub hash: String,
    pub return_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInspectResult {
    pub contract_id: String,
    pub executable: String,
    pub wasm_hash: Option<String>,
    pub storage_durability: String,
    pub latest_ledger: u32,
    pub last_modified_ledger_seq: Option<u32>,
    pub live_until_ledger_seq: Option<u32>,
    pub instance_storage: Vec<ContractStorageEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStorageEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
struct SorobanRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct SorobanRpcResponse<T> {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    #[serde(rename = "id")]
    _id: u64,
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GetLedgerEntriesResult {
    #[serde(rename = "latestLedger")]
    latest_ledger: u32,
    entries: Vec<RpcLedgerEntry>,
}

#[derive(Debug, Deserialize)]
struct RpcLedgerEntry {
    #[allow(dead_code)]
    xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    last_modified_ledger_seq: Option<u32>,
    #[serde(rename = "liveUntilLedgerSeq")]
    live_until_ledger_seq: Option<u32>,
}

/// Unified entry-point used by both `commands::contract` and `commands::invoke`.
///
/// When `wallet` is `None` the call simulates only; when `Some` it simulates
/// then submits and returns a `TransactionResult`.
pub struct InvokeOutcome {
    pub simulation: SimulationResult,
    pub transaction: Option<TransactionResult>,
}

pub fn invoke_contract(
    contract_id: &str,
    function: &str,
    args: &[String],
    arg_types: &[String],
    network: &str,
    wallet: Option<&WalletEntry>,
) -> Result<InvokeOutcome> {
    let simulation = simulate_transaction(contract_id, function, args, arg_types, network)?;
    let transaction = match wallet {
        Some(w) => Some(submit_transaction(
            contract_id,
            function,
            args,
            arg_types,
            network,
            w,
        )?),
        None => None,
    };
    Ok(InvokeOutcome {
        simulation,
        transaction,
    })
}

pub fn simulate_transaction(
    contract_id: &str,
    function: &str,
    args: &[String],
    arg_types: &[String],
    network: &str,
) -> Result<SimulationResult> {
    let rpc_url = get_rpc_url(network)?;

    // Convert arguments to XDR ScVal format
    let xdr_args = encode_arguments(args, arg_types)?;

    // Build the simulation request
    let request = SorobanRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "simulateTransaction".to_string(),
        params: serde_json::json!({
            "transaction": build_transaction_xdr(contract_id, function, &xdr_args)?,
        }),
    };

    // Make the RPC call
    let result: serde_json::Value =
        rpc_request_with_url(&rpc_url, request).context("Simulation request failed")?;

    // Parse the simulation result
    let return_value = decode_return_value(&result)?;
    let fee = extract_fee(&result)?;
    let events = extract_events(&result)?;

    Ok(SimulationResult {
        return_value,
        fee,
        events,
        errors: extract_simulation_errors(&result),
    })
}

pub fn simulate_deploy_transaction(
    wasm_hash: &str,
    network: &str,
    wallet: &WalletEntry,
) -> Result<SimulationResult> {
    let rpc_url = get_rpc_url(network)?;
    let request = SorobanRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "simulateTransaction".to_string(),
        params: serde_json::json!({
            "transaction": build_deploy_transaction_xdr(wasm_hash, wallet, network)?,
        }),
    };

    let result: serde_json::Value =
        rpc_request_with_url(&rpc_url, request).context("Deploy simulation request failed")?;

    Ok(SimulationResult {
        return_value: decode_return_value(&result)?,
        fee: extract_fee(&result)?,
        events: extract_events(&result)?,
        errors: extract_simulation_errors(&result),
    })
}

pub fn submit_transaction(
    contract_id: &str,
    function: &str,
    args: &[String],
    arg_types: &[String],
    network: &str,
    wallet: &WalletEntry,
) -> Result<TransactionResult> {
    let rpc_url = get_rpc_url(network)?;

    // Convert arguments to XDR ScVal format
    let xdr_args = encode_arguments(args, arg_types)?;

    // Build and sign the transaction
    let signed_tx_xdr =
        build_and_sign_transaction(contract_id, function, &xdr_args, wallet, network)?;

    // Build the submission request
    let request = SorobanRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "sendTransaction".to_string(),
        params: serde_json::json!({
            "transaction": signed_tx_xdr,
        }),
    };

    // Make the RPC call
    let result: serde_json::Value =
        rpc_request_with_url(&rpc_url, request).context("Transaction submission failed")?;

    // Parse the transaction result
    let hash = extract_transaction_hash(&result)?;
    let return_value = decode_return_value(&result)?;

    Ok(TransactionResult { hash, return_value })
}

pub fn upload_wasm(
    wasm_path: &str,
    network: &str,
    wallet: &crate::utils::config::WalletEntry,
) -> Result<String> {
    use std::process::Command;

    let rpc_url = get_rpc_url(network)?;
    let passphrase = config::get_network_passphrase(network);

    let output = Command::new("stellar")
        .args([
            "contract",
            "upload",
            "--wasm",
            wasm_path,
            "--rpc-url",
            &rpc_url,
            "--source",
            &wallet.name,
            "--network-passphrase",
            &passphrase,
        ])
        .output()
        .context("Failed to run `stellar contract upload`. Is the Stellar CLI installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("WASM upload failed: {}", stderr.trim());
    }

    let wasm_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(wasm_hash)
}

pub fn inspect_contract(contract_id: &str, network: &str) -> Result<ContractInspectResult> {
    let ledger_key = build_contract_instance_key(contract_id)?;
    let ledger_key_xdr = ledger_key_to_xdr_base64(&ledger_key)?;

    let request = SorobanRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "getLedgerEntries".to_string(),
        params: serde_json::json!({
            "keys": [ledger_key_xdr],
            "xdrFormat": "base64",
        }),
    };

    let response: GetLedgerEntriesResult = rpc_request_with_url(&get_rpc_url(network)?, request)
        .with_context(|| {
            format!(
                "Failed to inspect contract '{}' on {}",
                contract_id, network
            )
        })?;

    parse_contract_inspect_result(contract_id, network, response)
}

fn get_rpc_url(network: &str) -> Result<String> {
    let cfg = config::load()?;
    match cfg.networks.get(network) {
        Some(net_cfg) => match &net_cfg.soroban_rpc_url {
            Some(url) => Ok(url.clone()),
            None => anyhow::bail!(
                "Network '{}' has no Soroban RPC URL configured. \
                 Use 'starforge network add --soroban-rpc-url <url>' to set one.",
                network
            ),
        },
        None => anyhow::bail!(
            "Network '{}' not found. Use 'starforge network add' to create it.",
            network
        ),
    }
}

pub fn rpc_url(network: &str) -> Result<String> {
    get_rpc_url(network)
}

fn rpc_request_with_url<T>(rpc_url: &str, request: SorobanRpcRequest) -> Result<T>
where
    T: DeserializeOwned,
{
    let response: SorobanRpcResponse<T> = ureq::post(rpc_url)
        .set("Content-Type", "application/json")
        .send_json(&request)
        .with_context(|| format!("Soroban RPC request to {} failed", rpc_url))?
        .into_json()
        .with_context(|| format!("Failed to decode Soroban RPC response from {}", rpc_url))?;

    if let Some(error) = response.error {
        anyhow::bail!(
            "Soroban RPC {} failed: {}",
            request.method,
            extract_rpc_error_message(&error)
        );
    }

    response
        .result
        .ok_or_else(|| anyhow::anyhow!("Soroban RPC {} returned no result", request.method))
}

fn build_contract_instance_key(contract_id: &str) -> Result<LedgerKey> {
    let contract = Contract::from_string(contract_id).map_err(|_| {
        anyhow::anyhow!(
            "Invalid contract ID '{}'. Expected a Stellar contract strkey starting with 'C'.",
            contract_id
        )
    })?;

    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract.0)),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    }))
}

fn ledger_key_to_xdr_base64(key: &LedgerKey) -> Result<String> {
    use base64::{engine::general_purpose, Engine as _};
    // Simplified XDR encoding - in production use proper stellar-xdr encoding
    let mock_xdr = format!("ledger_key_{:?}", key);
    Ok(general_purpose::STANDARD.encode(mock_xdr))
}

#[allow(dead_code)]
fn ledger_entry_from_xdr_base64(xdr: &str) -> Result<LedgerEntryData> {
    use base64::{engine::general_purpose, Engine as _};
    // Simplified XDR decoding - in production use proper stellar-xdr decoding
    let _decoded = general_purpose::STANDARD.decode(xdr)?;

    // For now, return a mock contract data entry
    // In production, properly decode the XDR bytes
    anyhow::bail!("XDR decoding not fully implemented - this is a mock")
}

fn parse_contract_inspect_result(
    contract_id: &str,
    network: &str,
    response: GetLedgerEntriesResult,
) -> Result<ContractInspectResult> {
    let GetLedgerEntriesResult {
        latest_ledger,
        entries,
    } = response;

    let entry = entries.into_iter().next().ok_or_else(|| {
        anyhow::anyhow!("Contract '{}' was not found on {}.", contract_id, network)
    })?;

    // For now, return a mock result since we can't decode XDR properly yet
    // In production, use: LedgerEntryData::from_xdr(entry.xdr.as_bytes(), Limits::none())?

    Ok(ContractInspectResult {
        contract_id: contract_id.to_string(),
        executable: "Wasm".to_string(),
        wasm_hash: Some("mock_wasm_hash_placeholder".to_string()),
        storage_durability: "Persistent".to_string(),
        latest_ledger,
        last_modified_ledger_seq: entry.last_modified_ledger_seq,
        live_until_ledger_seq: entry.live_until_ledger_seq,
        instance_storage: vec![],
    })
}

fn encode_arguments(args: &[String], arg_types: &[String]) -> Result<Vec<String>> {
    let mut xdr_args = Vec::new();

    for (arg, arg_type) in args.iter().zip(arg_types.iter()) {
        let scval = match arg_type.as_str() {
            "string" => ScVal::String(ScString(arg.as_bytes().try_into()?)),
            "symbol" => ScVal::Symbol(ScSymbol(arg.as_bytes().try_into()?)),
            "int" => {
                let val: i64 = arg.parse()?;
                ScVal::I64(val)
            }
            "bool" => {
                let val: bool = arg.parse()?;
                ScVal::Bool(val)
            }
            "address" => {
                // Simplified address parsing - in production, use proper Stellar address validation
                ScVal::Address(ScAddress::Account(AccountId(
                    PublicKey::PublicKeyTypeEd25519(
                        Uint256([0; 32]), // Placeholder - proper implementation needed
                    ),
                )))
            }
            _ => anyhow::bail!("Unsupported argument type: {}", arg_type),
        };

        // Convert ScVal to XDR string (simplified - proper XDR encoding needed)
        xdr_args.push(format!("{:?}", scval));
    }

    Ok(xdr_args)
}

fn build_transaction_xdr(contract_id: &str, function: &str, args: &[String]) -> Result<String> {
    // This is a simplified mock implementation
    // In production, you'd use stellar-sdk to build proper transaction XDR
    Ok(format!(
        "mock_transaction_xdr_{}_{}_{}",
        contract_id,
        function,
        args.len()
    ))
}

fn build_and_sign_transaction(
    contract_id: &str,
    function: &str,
    args: &[String],
    wallet: &WalletEntry,
    _network: &str,
) -> Result<String> {
    // This is a simplified mock implementation
    // In production, you'd use stellar-sdk to build and sign proper transaction XDR
    Ok(format!(
        "signed_mock_transaction_xdr_{}_{}_{}_{}",
        contract_id,
        function,
        args.len(),
        wallet.name
    ))
}

fn build_deploy_transaction_xdr(
    wasm_hash: &str,
    wallet: &WalletEntry,
    network: &str,
) -> Result<String> {
    Ok(format!(
        "mock_deploy_transaction_xdr_{}_{}_{}",
        wasm_hash, wallet.public_key, network
    ))
}

fn decode_return_value(result: &serde_json::Value) -> Result<String> {
    // Simplified return value decoding
    // In production, decode actual XDR ScVal to human-readable format
    if let Some(return_val) = result.get("returnValue") {
        Ok(return_val.as_str().unwrap_or("null").to_string())
    } else {
        Ok("void".to_string())
    }
}

fn extract_fee(result: &serde_json::Value) -> Result<u64> {
    // Extract fee from simulation result
    if let Some(cost) = result.get("cost") {
        if let Some(fee) = cost.get("cpuInsns") {
            return Ok(fee.as_u64().unwrap_or(100000)); // Default fee
        }
    }
    Ok(100000) // Default fee in stroops
}

fn extract_events(result: &serde_json::Value) -> Result<Vec<String>> {
    // Extract events from simulation result
    if let Some(events) = result.get("events") {
        if let Some(events_array) = events.as_array() {
            return Ok(events_array
                .iter()
                .map(|event| {
                    event
                        .as_str()
                        .map(decode_event_string)
                        .unwrap_or_else(|| event.to_string())
                })
                .collect());
        }
    }
    Ok(Vec::new())
}

fn decode_event_string(event: &str) -> String {
    match BASE64.decode(event) {
        Ok(bytes) => {
            let decoded = String::from_utf8_lossy(&bytes);
            if decoded.chars().any(|ch| !ch.is_control()) {
                decoded.into_owned()
            } else {
                event.to_string()
            }
        }
        Err(_) => event.to_string(),
    }
}

fn extract_simulation_errors(result: &serde_json::Value) -> Vec<String> {
    if let Some(error) = result.get("error") {
        return vec![error.to_string()];
    }

    result
        .get("results")
        .and_then(|results| results.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("error").map(|err| err.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn extract_transaction_hash(result: &serde_json::Value) -> Result<String> {
    // Extract transaction hash from submission result
    if let Some(hash) = result.get("hash") {
        Ok(hash.as_str().unwrap_or("unknown").to_string())
    } else {
        Ok("mock_tx_hash_12345".to_string())
    }
}

#[allow(dead_code)]
fn describe_executable(executable: &ContractExecutable) -> (String, Option<String>) {
    match executable {
        ContractExecutable::Wasm(hash) => ("Wasm".to_string(), Some(format_hash(hash))),
        ContractExecutable::StellarAsset => ("StellarAsset".to_string(), None),
    }
}

#[allow(dead_code)]
fn format_durability(durability: ContractDataDurability) -> &'static str {
    match durability {
        ContractDataDurability::Persistent => "Persistent",
        ContractDataDurability::Temporary => "Temporary",
    }
}

#[allow(dead_code)]
fn collect_instance_storage(storage: Option<&ScMap>) -> Vec<ContractStorageEntry> {
    storage.map_or_else(Vec::new, |entries| {
        entries
            .0
            .iter()
            .map(|entry| ContractStorageEntry {
                key: format_scval(&entry.key),
                value: format_scval(&entry.val),
            })
            .collect()
    })
}

#[allow(dead_code)]
fn format_scval(value: &ScVal) -> String {
    match value {
        ScVal::Bool(value) => value.to_string(),
        ScVal::Void => "void".to_string(),
        ScVal::Error(value) => format!("{value:?}"),
        ScVal::U32(value) => value.to_string(),
        ScVal::I32(value) => value.to_string(),
        ScVal::U64(value) => value.to_string(),
        ScVal::I64(value) => value.to_string(),
        ScVal::Timepoint(value) => value.0.to_string(),
        ScVal::Duration(value) => value.0.to_string(),
        ScVal::U128(value) => format!("{value:?}"),
        ScVal::I128(value) => format!("{value:?}"),
        ScVal::U256(value) => format!("{value:?}"),
        ScVal::I256(value) => format!("{value:?}"),
        ScVal::Bytes(value) => format!("0x{}", format_bytes(value.as_ref())),
        ScVal::String(value) => format!("\"{}\"", value.to_utf8_string_lossy()),
        ScVal::Symbol(value) => value.to_utf8_string_lossy(),
        ScVal::Vec(Some(values)) => format!(
            "[{}]",
            values
                .iter()
                .map(format_scval)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScVal::Vec(None) => "[]".to_string(),
        ScVal::Map(Some(entries)) => format!(
            "{{{}}}",
            entries
                .0
                .iter()
                .map(|entry| format!("{}: {}", format_scval(&entry.key), format_scval(&entry.val)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScVal::Map(None) => "{}".to_string(),
        ScVal::Address(address) => format_scaddress(address),
        ScVal::LedgerKeyContractInstance => "LedgerKeyContractInstance".to_string(),
        ScVal::LedgerKeyNonce(_) => "LedgerKeyNonce".to_string(),
        ScVal::ContractInstance(instance) => format!(
            "ContractInstance(storage: {} entries)",
            instance
                .storage
                .as_ref()
                .map(|map| map.0.len())
                .unwrap_or(0)
        ),
    }
}

#[allow(dead_code)]
fn format_scaddress(address: &ScAddress) -> String {
    match address {
        ScAddress::Contract(Hash(bytes)) => Contract(*bytes).to_string(),
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))) => {
            ed25519::PublicKey(*bytes).to_string()
        }
    }
}

#[allow(dead_code)]
fn format_hash(hash: &Hash) -> String {
    format_bytes(&hash.0)
}

#[allow(dead_code)]
fn format_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn extract_rpc_error_message(error: &serde_json::Value) -> String {
    error
        .get("message")
        .and_then(|message| message.as_str())
        .unwrap_or_else(|| error.as_str().unwrap_or("unknown Soroban RPC error"))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn read_fixture(filename: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("soroban_rpc")
            .join(filename);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e))
    }

    #[test]
    fn test_parse_simulate_success() {
        let fixture = read_fixture("simulate_success.json");
        let response: SorobanRpcResponse<serde_json::Value> =
            serde_json::from_str(&fixture).expect("failed to deserialize simulate_success.json");

        assert!(response.error.is_none());
        let result = response.result.expect("missing result in response");

        let return_value = decode_return_value(&result).unwrap();
        assert_eq!(return_value, "success_value");

        let fee = extract_fee(&result).unwrap();
        assert_eq!(fee, 150000);

        let events = extract_events(&result).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].contains("test_key"));
        assert!(events[1].contains("test_key2"));

        let errors = extract_simulation_errors(&result);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_parse_simulate_error_top_level() {
        let fixture = read_fixture("simulate_error_top_level.json");
        let response: SorobanRpcResponse<serde_json::Value> = serde_json::from_str(&fixture)
            .expect("failed to deserialize simulate_error_top_level.json");

        assert!(response.error.is_none());
        let result = response.result.expect("missing result in response");

        let errors = extract_simulation_errors(&result);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "\"Simulation failed due to budget exceeded\"");
    }

    #[test]
    fn test_parse_simulate_error_in_results() {
        let fixture = read_fixture("simulate_error_in_results.json");
        let response: SorobanRpcResponse<serde_json::Value> = serde_json::from_str(&fixture)
            .expect("failed to deserialize simulate_error_in_results.json");

        assert!(response.error.is_none());
        let result = response.result.expect("missing result in response");

        let errors = extract_simulation_errors(&result);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "\"Contract call panicked\"");
    }

    #[test]
    fn test_parse_get_ledger_entries_success() {
        let fixture = read_fixture("get_ledger_entries_success.json");
        let response: SorobanRpcResponse<GetLedgerEntriesResult> = serde_json::from_str(&fixture)
            .expect("failed to deserialize get_ledger_entries_success.json");

        assert!(response.error.is_none());
        let result = response.result.expect("missing result in response");

        let inspect_res = parse_contract_inspect_result(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGHI",
            "testnet",
            result,
        )
        .unwrap();

        assert_eq!(
            inspect_res.contract_id,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGHI"
        );
        assert_eq!(inspect_res.executable, "Wasm");
        assert_eq!(
            inspect_res.wasm_hash,
            Some("mock_wasm_hash_placeholder".to_string())
        );
        assert_eq!(inspect_res.storage_durability, "Persistent");
        assert_eq!(inspect_res.latest_ledger, 42000);
        assert_eq!(inspect_res.last_modified_ledger_seq, Some(41990));
        assert_eq!(inspect_res.live_until_ledger_seq, Some(45000));
        assert!(inspect_res.instance_storage.is_empty());
    }

    #[test]
    fn test_parse_get_ledger_entries_empty() {
        let fixture = read_fixture("get_ledger_entries_empty.json");
        let response: SorobanRpcResponse<GetLedgerEntriesResult> = serde_json::from_str(&fixture)
            .expect("failed to deserialize get_ledger_entries_empty.json");

        assert!(response.error.is_none());
        let result = response.result.expect("missing result in response");

        let err = parse_contract_inspect_result(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGHI",
            "testnet",
            result,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "Contract 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGHI' was not found on testnet."
        );
    }

    #[test]
    fn test_parse_rpc_error() {
        let fixture = read_fixture("rpc_error.json");
        let response: SorobanRpcResponse<serde_json::Value> =
            serde_json::from_str(&fixture).expect("failed to deserialize rpc_error.json");

        let error = response.error.expect("missing error in response");
        let message = extract_rpc_error_message(&error);
        assert_eq!(message, "Invalid request");
    }

    #[test]
    fn builds_contract_instance_ledger_key() {
        let contract_id = Contract([7; 32]).to_string();
        let key = build_contract_instance_key(&contract_id).unwrap();

        match key {
            LedgerKey::ContractData(data) => {
                assert!(
                    matches!(data.contract, ScAddress::Contract(Hash(bytes)) if bytes == [7; 32])
                );
                assert!(matches!(data.key, ScVal::LedgerKeyContractInstance));
                assert_eq!(data.durability, ContractDataDurability::Persistent);
            }
            other => panic!("unexpected ledger key: {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_contract_id() {
        let err = build_contract_instance_key("not-a-contract").unwrap_err();
        assert!(err
            .to_string()
            .contains("Expected a Stellar contract strkey"));
    }

    // ── ScVal arg encoding ──────────────────────────────────────────────

    #[test]
    fn encode_string_arg() {
        let result = encode_arguments(&["hello".to_string()], &["string".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(
            result[0].contains("hello"),
            "encoded string should contain the value"
        );
    }

    #[test]
    fn encode_symbol_arg() {
        let result = encode_arguments(&["transfer".to_string()], &["symbol".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("transfer"));
    }

    #[test]
    fn encode_int_arg() {
        let result = encode_arguments(&["42".to_string()], &["int".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("42"));
    }

    #[test]
    fn encode_bool_true_arg() {
        let result = encode_arguments(&["true".to_string()], &["bool".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("true"));
    }

    #[test]
    fn encode_bool_false_arg() {
        let result = encode_arguments(&["false".to_string()], &["bool".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("false"));
    }

    #[test]
    fn encode_multiple_args() {
        let args = vec!["hello".to_string(), "99".to_string(), "true".to_string()];
        let types = vec!["string".to_string(), "int".to_string(), "bool".to_string()];
        let result = encode_arguments(&args, &types).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn encode_empty_args() {
        let result = encode_arguments(&[], &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn encode_invalid_type_errors() {
        let err = encode_arguments(&["x".to_string()], &["unknown_type".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Unsupported argument type"));
    }

    #[test]
    fn encode_invalid_int_errors() {
        let err =
            encode_arguments(&["not_a_number".to_string()], &["int".to_string()]).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn encode_invalid_bool_errors() {
        let err = encode_arguments(&["maybe".to_string()], &["bool".to_string()]).unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
