#![allow(clippy::result_large_err)]

use crate::utils::config;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::sync::OnceLock;
use std::time::Duration;

const HORIZON_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HORIZON_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HORIZON_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

static HORIZON_AGENT: OnceLock<ureq::Agent> = OnceLock::new();

fn horizon_agent() -> &'static ureq::Agent {
    HORIZON_AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(HORIZON_CONNECT_TIMEOUT)
            .timeout(HORIZON_REQUEST_TIMEOUT)
            .build()
    })
}

fn is_transient_horizon_error(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Status(status, _) => matches!(*status, 429 | 502 | 503 | 504),
        ureq::Error::Transport(_) => true,
    }
}

fn request_with_retries<F>(
    mut request: F,
    retry_delays: &[Duration],
) -> std::result::Result<ureq::Response, ureq::Error>
where
    F: FnMut() -> std::result::Result<ureq::Response, ureq::Error>,
{
    for attempt in 0..=retry_delays.len() {
        match request() {
            Ok(response) => return Ok(response),
            Err(error) if attempt < retry_delays.len() && is_transient_horizon_error(&error) => {
                std::thread::sleep(retry_delays[attempt]);
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("retry loop returns on success or final error");
}

fn horizon_request<F>(request: F) -> std::result::Result<ureq::Response, ureq::Error>
where
    F: FnMut() -> std::result::Result<ureq::Response, ureq::Error>,
{
    request_with_retries(request, &HORIZON_RETRY_DELAYS)
}

fn horizon_request_error(error: ureq::Error, context: &str) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => {
            let detail = response
                .into_string()
                .ok()
                .and_then(|body| format_horizon_error_body(&body))
                .unwrap_or_else(|| "No response body".to_string());
            anyhow!("{context}: HTTP {status}: {detail}")
        }
        ureq::Error::Transport(error) => anyhow!("{context}: {error}"),
    }
}

#[derive(Debug, Clone)]
pub struct HorizonClient {
    base_url: String,
}

impl HorizonClient {
    pub fn for_network(network: &str) -> Result<Self> {
        Ok(Self::new(horizon_url(network)?))
    }

    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        }
    }

    fn get_raw(&self, path: &str) -> std::result::Result<ureq::Response, ureq::Error> {
        let url = self.url(path);
        horizon_request(|| horizon_agent().get(&url).call())
    }

    fn post_form_raw(
        &self,
        path: &str,
        form_data: &str,
    ) -> std::result::Result<ureq::Response, ureq::Error> {
        let url = self.url(path);
        horizon_request(|| {
            horizon_agent()
                .post(&url)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(form_data)
        })
    }
}

pub fn network_config(network: &str) -> Result<config::NetworkConfig> {
    let cfg = config::load()?;
    config::get_network_config(&cfg, network)
}

pub fn horizon_url(network: &str) -> Result<String> {
    Ok(network_config(network)?.horizon_url)
}

pub fn friendbot_url(network: &str) -> Result<Option<String>> {
    Ok(network_config(network)?.friendbot_url)
}

#[derive(Debug, Deserialize)]
pub struct AccountResponse {
    #[allow(dead_code)]
    pub id: String,
    pub sequence: String,
    pub balances: Vec<Balance>,
    #[allow(dead_code)]
    pub subentry_count: u32,
}

#[derive(Debug, Deserialize)]
pub struct Balance {
    pub balance: String,
    pub asset_type: String,
    pub asset_code: Option<String>,
}

pub fn fund_account(public_key: &str, network: &str) -> Result<()> {
    let friendbot =
        friendbot_url(network)?.unwrap_or_else(|| "https://friendbot.stellar.org".to_string());
    let separator = if friendbot.contains('?') { '&' } else { '?' };
    let url = format!("{}{}addr={}", friendbot, separator, public_key);
    let res = match horizon_request(|| horizon_agent().get(&url).call()) {
        Ok(res) => res,
        Err(ureq::Error::Status(status, _)) => {
            anyhow::bail!("Friendbot returned status {}", status)
        }
        Err(error) => {
            return Err(horizon_request_error(
                error,
                &format!("Friendbot request failed for {}", network),
            ))
        }
    };
    if res.status() == 200 {
        Ok(())
    } else {
        anyhow::bail!("Friendbot returned status {}", res.status())
    }
}

pub fn fetch_account(public_key: &str, network: &str) -> Result<AccountResponse> {
    let client = HorizonClient::for_network(network)?;
    let res = match client.get_raw(&format!("/accounts/{public_key}")) {
        Ok(res) => res,
        Err(ureq::Error::Status(404, _)) => anyhow::bail!("Account not found on {}", network),
        Err(error) => {
            return Err(horizon_request_error(
                error,
                &format!("Failed to reach Horizon on {}", network),
            ))
        }
    };
    if res.status() == 200 {
        let account: AccountResponse = res
            .into_json()
            .with_context(|| "Failed to parse account response")?;
        Ok(account)
    } else {
        anyhow::bail!("Account not found on {}", network)
    }
}

pub fn fetch_account_sequence(public_key: &str, network: &str) -> Result<i64> {
    let account = fetch_account(public_key, network)?;
    account
        .sequence
        .parse::<i64>()
        .with_context(|| format!("Failed to parse sequence string '{}'", account.sequence))
}

pub fn check_network(network: &str) -> bool {
    if let Ok(client) = HorizonClient::for_network(network) {
        client
            .get_raw("/")
            .map(|r| r.status() == 200)
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn build_transaction_query_url(
    public_key: &str,
    network: &str,
    filter: &TxFilter,
) -> Result<String> {
    let horizon = horizon_url(network)?;
    let mut url = format!(
        "{}/accounts/{}/transactions?order={}&limit={}",
        horizon,
        public_key,
        filter.order.as_deref().unwrap_or("desc"),
        filter.limit.min(200)
    );

    if let Some(ref cursor) = filter.cursor {
        url.push_str(&format!("&cursor={}", cursor));
    }
    if let Some(ref type_filter) = filter.type_filter {
        url.push_str(&format!("&type={}", type_filter));
    }

    Ok(url)
}

#[derive(Debug, Deserialize, Clone)]
pub struct TransactionRecord {
    pub hash: String,
    pub successful: bool,
    pub operation_count: u32,
    pub fee_charged: String,
    pub created_at: String,
    pub memo_type: Option<String>,
    pub memo: Option<String>,
    pub source_account: Option<String>,
    #[serde(rename = "type")]
    pub transaction_type: Option<String>,
    pub paging_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FeeStats {
    #[serde(rename = "low_fee")]
    pub low_fee: String,
    #[serde(rename = "mode_fee")]
    pub mode_fee: String,
    #[serde(rename = "high_fee")]
    pub high_fee: String,
}

pub fn fetch_fee_stats(network: &str) -> Result<FeeStats> {
    let client = HorizonClient::for_network(network)?;
    let res = client.get_raw("/fee_stats").map_err(|error| {
        horizon_request_error(
            error,
            &format!("Failed to fetch fee stats from {}", network),
        )
    })?;
    if res.status() == 200 {
        let stats: FeeStats = res
            .into_json()
            .with_context(|| "Failed to parse fee stats response")?;
        Ok(stats)
    } else {
        anyhow::bail!("Failed to get fee stats: HTTP {}", res.status())
    }
}

#[derive(Debug, Deserialize)]
struct TransactionsResponse {
    #[serde(rename = "_embedded")]
    embedded: TransactionsEmbedded,
}

#[derive(Debug, Deserialize)]
struct TransactionsEmbedded {
    records: Vec<TransactionRecord>,
}

pub struct TxFilter {
    pub limit: u8,
    pub cursor: Option<String>,
    pub order: Option<String>,
    pub type_filter: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
    pub successful_only: Option<bool>,
}

#[allow(dead_code)]
pub fn fetch_transactions(
    public_key: &str,
    network: &str,
    limit: u8,
) -> Result<Vec<TransactionRecord>> {
    fetch_transactions_filtered(
        public_key,
        network,
        TxFilter {
            limit,
            cursor: None,
            order: None,
            type_filter: None,
            after: None,
            before: None,
            successful_only: None,
        },
    )
}

pub fn fetch_transactions_filtered(
    public_key: &str,
    network: &str,
    filter: TxFilter,
) -> Result<Vec<TransactionRecord>> {
    let client = HorizonClient::for_network(network)?;
    let url = build_transaction_query_url(public_key, network, &filter)?;
    let res = client.get_raw(&url).map_err(|error| {
        horizon_request_error(
            error,
            &format!(
                "Account '{}' not found on {}. Has it been funded?",
                public_key, network
            ),
        )
    })?;

    let parsed: TransactionsResponse = res.into_json().with_context(|| {
        format!(
            "Account '{}' not found on {}. Has it been funded?",
            public_key, network
        )
    })?;

    let mut records = parsed.embedded.records;

    // Client-side filtering for Horizon features not universally supported
    if let Some(ref type_filter) = filter.type_filter {
        records.retain(|tx| tx.transaction_type.as_deref() == Some(type_filter.as_str()));
    }
    if let Some(ref after) = filter.after {
        records.retain(|tx| tx.created_at.as_str() >= after.as_str());
    }
    if let Some(ref before) = filter.before {
        records.retain(|tx| tx.created_at.as_str() <= before.as_str());
    }
    if let Some(successful_only) = filter.successful_only {
        records.retain(|tx| tx.successful == successful_only);
    }

    Ok(records)
}

#[derive(Debug, Deserialize)]
pub struct TransactionSimulationResult {
    pub transaction_xdr: String,
    pub fee: u64,
}

#[derive(Debug, Deserialize)]
pub struct TransactionSubmitResult {
    pub hash: String,
    pub successful: bool,
}

#[derive(Debug, Deserialize)]
struct HorizonError {
    pub title: String,
    pub detail: Option<String>,
    pub extras: Option<HorizonErrorExtras>,
}

#[derive(Debug, Deserialize)]
struct HorizonErrorExtras {
    pub result_codes: Option<HorizonResultCodes>,
}

#[derive(Debug, Deserialize)]
struct HorizonResultCodes {
    pub transaction: Option<String>,
    pub operations: Option<Vec<String>>,
}

fn format_horizon_error_body(body: &str) -> Option<String> {
    let horizon_error = serde_json::from_str::<HorizonError>(body).ok()?;
    let mut parts = vec![horizon_error.title];

    if let Some(detail) = horizon_error.detail.filter(|detail| !detail.is_empty()) {
        parts.push(detail);
    }

    if let Some(result_codes) = horizon_error.extras.and_then(|extras| extras.result_codes) {
        let mut codes = Vec::new();
        if let Some(transaction) = result_codes.transaction {
            codes.push(format!("transaction={transaction}"));
        }
        if let Some(operations) = result_codes.operations {
            if !operations.is_empty() {
                codes.push(format!("operations={}", operations.join(",")));
            }
        }
        if !codes.is_empty() {
            parts.push(format!("result_codes: {}", codes.join("; ")));
        }
    }

    Some(parts.join(" - "))
}

#[derive(Debug, Clone)]
pub struct BatchPaymentOp {
    pub destination: String,
    pub amount: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
}

pub fn build_and_simulate_batch(
    source: &str,
    operations: &[BatchPaymentOp],
    sequence: &str,
    network: &str,
) -> Result<TransactionSimulationResult> {
    let tx_xdr = build_batch_transaction_xdr(source, operations, sequence, network)?;

    let base_fee_per_op = 100_000u64;
    let estimated_fee = base_fee_per_op.saturating_mul(operations.len() as u64);

    Ok(TransactionSimulationResult {
        transaction_xdr: tx_xdr,
        fee: estimated_fee,
    })
}

pub fn build_and_simulate_account_merge(
    source: &str,
    destination: &str,
    sequence: &str,
    network: &str,
) -> Result<TransactionSimulationResult> {
    let tx_xdr = build_account_merge_transaction_xdr(source, destination, sequence, network)?;

    Ok(TransactionSimulationResult {
        transaction_xdr: tx_xdr,
        fee: 100_000,
    })
}

pub fn build_and_simulate_payment(
    source: &str,
    destination: &str,
    amount: &str,
    asset_code: Option<&str>,
    asset_issuer: Option<&str>,
    sequence: &str,
    network: &str,
) -> Result<TransactionSimulationResult> {
    // For now, we'll use a simplified approach by calling the stellar CLI
    // In a production implementation, you'd use stellar-xdr to build the transaction properly

    // Build transaction XDR using stellar-sdk patterns
    let tx_xdr = build_payment_transaction_xdr(
        source,
        destination,
        amount,
        asset_code,
        asset_issuer,
        sequence,
        network,
    )?;

    // Simulate the transaction
    let horizon = horizon_url(network)?;
    let _url = format!("{}/transactions", horizon);
    let _form_data = format!("tx={}", urlencoding::encode(&tx_xdr));

    // For simulation, we'll estimate the fee
    let estimated_fee = 100000u64; // 0.00001 XLM in stroops

    Ok(TransactionSimulationResult {
        transaction_xdr: tx_xdr,
        fee: estimated_fee,
    })
}

pub fn submit_payment_transaction(
    transaction_xdr: &str,
    secret_key: &str,
    network: &str,
) -> Result<TransactionSubmitResult> {
    // Sign the transaction
    let signed_xdr = sign_transaction_xdr(transaction_xdr, secret_key, network)?;

    // Submit to Horizon
    let client = HorizonClient::for_network(network)?;
    let form_data = format!("tx={}", urlencoding::encode(&signed_xdr));

    let res = match client.post_form_raw("/transactions", &form_data) {
        Ok(res) => res,
        Err(error) => {
            return Err(horizon_request_error(
                error,
                "Failed to submit transaction to Horizon",
            ))
        }
    };

    let status = res.status();

    if status == 200 {
        let result: serde_json::Value = res
            .into_json()
            .with_context(|| "Failed to parse transaction response")?;

        let hash = result
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(TransactionSubmitResult {
            hash,
            successful: true,
        })
    } else {
        let error_text = res
            .into_string()
            .unwrap_or_else(|_| "Unknown error".to_string());

        if let Some(detail) = format_horizon_error_body(&error_text) {
            anyhow::bail!("Transaction failed: {}", detail);
        } else {
            anyhow::bail!("Transaction failed with status {}: {}", status, error_text);
        }
    }
}

pub fn submit_multisig_transaction(
    signed_transaction_xdr: &str,
    network: &str,
) -> Result<TransactionSubmitResult> {
    // Submit a pre-signed transaction (e.g. multisig envelope) to Horizon.
    let client = HorizonClient::for_network(network)?;
    let form_data = format!("tx={}", urlencoding::encode(signed_transaction_xdr));

    let res = match client.post_form_raw("/transactions", &form_data) {
        Ok(res) => res,
        Err(error) => {
            return Err(horizon_request_error(
                error,
                "Failed to submit transaction to Horizon",
            ))
        }
    };

    let status = res.status();
    if status == 200 {
        let result: serde_json::Value = res
            .into_json()
            .with_context(|| "Failed to parse transaction response")?;

        let hash = result
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(TransactionSubmitResult {
            hash,
            successful: true,
        })
    } else {
        let error_text = res
            .into_string()
            .unwrap_or_else(|_| "Unknown error".to_string());

        if let Some(detail) = format_horizon_error_body(&error_text) {
            anyhow::bail!("Transaction failed: {}", detail);
        } else {
            anyhow::bail!("Transaction failed with status {}: {}", status, error_text);
        }
    }
}

fn build_batch_transaction_xdr(
    source: &str,
    operations: &[BatchPaymentOp],
    sequence: &str,
    network: &str,
) -> Result<String> {
    if operations.is_empty() {
        anyhow::bail!("Batch transaction requires at least one operation");
    }

    let _network_passphrase = config::get_network_passphrase(network);

    let op_parts: Vec<String> = operations
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let asset_info = match (&op.asset_code, &op.asset_issuer) {
                (None, None) => "native".to_string(),
                (Some(code), Some(issuer)) => format!("{}:{}", code, issuer),
                _ => return Err(anyhow::anyhow!("Invalid asset in operation {}", i + 1)),
            };
            Ok(format!(
                "pay:{}:{}:{}",
                op.destination, op.amount, asset_info
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    let mock_xdr = format!(
        "mock_batch_tx_{}_{}_{}_{}",
        source,
        op_parts.join("|"),
        sequence,
        network
    );

    use base64::{engine::general_purpose, Engine as _};
    Ok(general_purpose::STANDARD.encode(mock_xdr))
}

fn build_account_merge_transaction_xdr(
    source: &str,
    destination: &str,
    sequence: &str,
    network: &str,
) -> Result<String> {
    let _network_passphrase = network_passphrase(network);

    let mock_xdr = format!(
        "mock_merge_tx_{}_{}_{}_{}",
        source, destination, sequence, network
    );

    use base64::{engine::general_purpose, Engine as _};
    Ok(general_purpose::STANDARD.encode(mock_xdr))
}

fn network_passphrase(network: &str) -> String {
    config::get_network_passphrase(network)
}

fn build_payment_transaction_xdr(
    source: &str,
    destination: &str,
    amount: &str,
    asset_code: Option<&str>,
    asset_issuer: Option<&str>,
    sequence: &str,
    network: &str,
) -> Result<String> {
    // This is a simplified mock implementation
    // In production, you'd use stellar-xdr crate to build proper transaction XDR

    let _network_passphrase = network_passphrase(network);

    // Mock XDR generation - in reality this would be much more complex
    let asset_info = match (asset_code, asset_issuer) {
        (None, None) => "native".to_string(),
        (Some(code), Some(issuer)) => format!("{}:{}", code, issuer),
        _ => return Err(anyhow::anyhow!("Invalid asset specification")),
    };

    // Generate a mock transaction XDR
    // In production, use stellar-xdr to build proper TransactionEnvelope
    let mock_xdr = format!(
        "mock_payment_tx_{}_{}_{}_{}_{}",
        source, destination, amount, asset_info, sequence
    );

    use base64::{engine::general_purpose, Engine as _};
    Ok(general_purpose::STANDARD.encode(mock_xdr))
}

fn sign_transaction_xdr(transaction_xdr: &str, secret_key: &str, network: &str) -> Result<String> {
    // This is a simplified mock implementation
    // In production, you'd use stellar-xdr and ed25519 signing

    let _network_passphrase = config::get_network_passphrase(network);

    // Mock signing - in reality this would involve:
    // 1. Decode the transaction XDR
    // 2. Hash the transaction with network passphrase
    // 3. Sign with ed25519 private key
    // 4. Create TransactionEnvelope with signature
    // 5. Re-encode to XDR

    let signed_mock = format!("signed_{}_with_{}", transaction_xdr, &secret_key[..8]);
    use base64::{engine::general_purpose, Engine as _};
    Ok(general_purpose::STANDARD.encode(signed_mock))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::{self, Config, NetworkConfig};
    use mockito::{Matcher, Server};
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestConfigGuard {
        _env_lock: MutexGuard<'static, ()>,
        _temp_dir: TempDir,
        original_home: Option<String>,
    }

    impl TestConfigGuard {
        fn new(horizon_url: &str, friendbot_url: Option<String>) -> Self {
            let env_lock = TEST_ENV_LOCK.lock().expect("test env lock");
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let original_home = std::env::var("HOME").ok();

            unsafe {
                std::env::set_var("HOME", temp_dir.path());
            }

            let mut networks = HashMap::new();
            networks.insert(
                "mocknet".to_string(),
                NetworkConfig {
                    horizon_url: horizon_url.to_string(),
                    soroban_rpc_url: None,
                    friendbot_url,
                    passphrase: Some("Test SDF Network ; September 2015".to_string()),
                },
            );

            config::save(&Config {
                network: "mocknet".to_string(),
                version: "1".to_string(),
                networks,
                wallets: Vec::new(),
                plugin_trust: Default::default(),
                telemetry_enabled: Some(false),
                wallet_encryption: None,
            })
            .expect("save config");

            Self {
                _env_lock: env_lock,
                _temp_dir: temp_dir,
                original_home,
            }
        }
    }

    impl Drop for TestConfigGuard {
        fn drop(&mut self) {
            if let Some(home) = &self.original_home {
                unsafe {
                    std::env::set_var("HOME", home);
                }
            } else {
                unsafe {
                    std::env::remove_var("HOME");
                }
            }
        }
    }

    #[test]
    fn fetch_account_returns_mocked_account() {
        let mut server = Server::new();
        let _guard = TestConfigGuard::new(&server.url(), None);
        let public_key = "GACCOUNT123";

        let _mock = server
            .mock("GET", format!("/accounts/{public_key}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "id":"GACCOUNT123",
                    "sequence":"123456789",
                    "balances":[{"balance":"42.0000000","asset_type":"native","asset_code":null}],
                    "subentry_count":1
                }"#,
            )
            .create();

        let account = fetch_account(public_key, "mocknet").expect("account");
        assert_eq!(account.sequence, "123456789");
        assert_eq!(account.balances.len(), 1);
        assert_eq!(account.balances[0].asset_type, "native");
    }

    #[test]
    fn fetch_account_reports_parse_error_for_invalid_json() {
        let mut server = Server::new();
        let _guard = TestConfigGuard::new(&server.url(), None);

        let _mock = server
            .mock("GET", "/accounts/GACCOUNT123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{\"sequence\":")
            .create();

        let err = fetch_account("GACCOUNT123", "mocknet").unwrap_err();
        assert!(err.to_string().contains("Failed to parse account response"));
    }

    #[test]
    fn fund_account_reports_friendbot_error_path() {
        let mut server = Server::new();
        let _guard = TestConfigGuard::new(&server.url(), Some(server.url()));

        let _mock = server
            .mock("GET", "/")
            .match_query(Matcher::UrlEncoded("addr".into(), "GACCOUNT123".into()))
            .with_status(500)
            .create();

        let err = fund_account("GACCOUNT123", "mocknet").unwrap_err();
        assert!(err.to_string().contains("Friendbot returned status 500"));
    }

    #[test]
    fn horizon_error_body_includes_result_codes() {
        let detail = format_horizon_error_body(
            r#"{
                "title":"Transaction Failed",
                "detail":"The transaction failed when submitted to Horizon.",
                "extras":{
                    "result_codes":{
                        "transaction":"tx_failed",
                        "operations":["op_no_trust","op_underfunded"]
                    }
                }
            }"#,
        )
        .expect("formatted error");

        assert!(detail.contains("Transaction Failed"));
        assert!(detail.contains("tx_failed"));
        assert!(detail.contains("op_no_trust"));
        assert!(detail.contains("op_underfunded"));
    }

    #[test]
    fn horizon_503_status_is_transient() {
        let mut server = Server::new();
        let _mock = server.mock("GET", "/fee_stats").with_status(503).create();
        let url = format!("{}/fee_stats", server.url());

        let err = horizon_agent().get(&url).call().unwrap_err();

        assert!(is_transient_horizon_error(&err));
    }

    #[test]
    fn build_transaction_query_url_includes_pagination_params() {
        let server = Server::new();
        let _guard = TestConfigGuard::new(&server.url(), None);

        let filter = TxFilter {
            limit: 250,
            cursor: Some("cursor-123".to_string()),
            order: Some("asc".to_string()),
            type_filter: Some("payment".to_string()),
            after: None,
            before: None,
            successful_only: None,
        };

        let url = build_transaction_query_url("GACCOUNT123", "mocknet", &filter).expect("url");
        assert!(url.contains("/accounts/GACCOUNT123/transactions?order=asc&limit=200"));
        assert!(url.contains("&cursor=cursor-123"));
        assert!(url.contains("&type=payment"));
    }

    #[test]
    fn fetch_transactions_filtered_uses_cursor_and_filters_records() {
        let mut server = Server::new();
        let _guard = TestConfigGuard::new(&server.url(), None);

        let _mock = server
            .mock("GET", "/accounts/GACCOUNT123/transactions")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".into(), "asc".into()),
                Matcher::UrlEncoded("limit".into(), "2".into()),
                Matcher::UrlEncoded("cursor".into(), "cursor-2".into()),
                Matcher::UrlEncoded("type".into(), "payment".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "_embedded": {
                        "records": [
                            {
                                "hash":"tx-1",
                                "successful":true,
                                "operation_count":1,
                                "fee_charged":"100",
                                "created_at":"2024-01-01T00:00:00Z",
                                "memo_type":"text",
                                "memo":"ok",
                                "source_account":"GACCOUNT123",
                                "type":"payment",
                                "paging_token":"cursor-1"
                            },
                            {
                                "hash":"tx-2",
                                "successful":false,
                                "operation_count":1,
                                "fee_charged":"100",
                                "created_at":"2024-01-02T00:00:00Z",
                                "memo_type":null,
                                "memo":null,
                                "source_account":"GACCOUNT123",
                                "type":"payment",
                                "paging_token":"cursor-2"
                            }
                        ]
                    }
                }"#,
            )
            .create();

        let records = fetch_transactions_filtered(
            "GACCOUNT123",
            "mocknet",
            TxFilter {
                limit: 2,
                cursor: Some("cursor-2".to_string()),
                order: Some("asc".to_string()),
                type_filter: Some("payment".to_string()),
                after: None,
                before: None,
                successful_only: Some(true),
            },
        )
        .expect("records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].hash, "tx-1");
        assert_eq!(records[0].paging_token.as_deref(), Some("cursor-1"));
    }
}
