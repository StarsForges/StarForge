use super::{
    redact_url, AccountPolicy, AccountSigner, MasterKeyPolicy, SignerAvailability, SignerType,
    Thresholds, POLICY_SCHEMA_VERSION,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_NETWORK_TIMEOUT_SECONDS: u64 = 15;
pub const MAX_NETWORK_TIMEOUT_SECONDS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionResult {
    pub transaction_hash: String,
    pub ledger: Option<u32>,
    pub successful: bool,
}

pub trait AccountTransport: Send + Sync {
    fn inspect_account(&self, account_id: &str) -> Result<AccountPolicy>;

    fn submit_envelope(
        &self,
        signed_envelope_xdr: &str,
        expected_after: &AccountPolicy,
    ) -> Result<SubmissionResult>;
}

#[derive(Clone)]
pub struct HorizonAccountTransport {
    endpoint: String,
    network_passphrase: String,
    agent: ureq::Agent,
}

impl HorizonAccountTransport {
    pub fn new(
        endpoint: impl Into<String>,
        network_passphrase: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        if !endpoint.starts_with("https://") && !is_loopback_http(&endpoint) {
            bail!("Horizon endpoint must use HTTPS (loopback HTTP is allowed for fixtures)");
        }
        if timeout.is_zero() || timeout > Duration::from_secs(MAX_NETWORK_TIMEOUT_SECONDS) {
            bail!(
                "network timeout must be between 1 and {} seconds",
                MAX_NETWORK_TIMEOUT_SECONDS
            );
        }
        let network_passphrase = network_passphrase.into();
        if network_passphrase.trim().is_empty() {
            bail!("network passphrase must not be empty");
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .build();
        Ok(Self {
            endpoint,
            network_passphrase,
            agent,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn verify_network_identity(&self) -> Result<()> {
        let response = self.agent.get(&self.endpoint).call().map_err(|error| {
            transport_error(
                error,
                &format!(
                    "failed to probe Horizon endpoint {}",
                    redact_url(&self.endpoint)
                ),
            )
        })?;
        let identity: HorizonRoot = response
            .into_json()
            .context("Horizon identity response was malformed JSON")?;
        if identity.network_passphrase != self.network_passphrase {
            bail!(
                "Horizon network identity mismatch at {} (expected passphrase sha256 {}, observed {})",
                redact_url(&self.endpoint),
                super::sha256_hex(self.network_passphrase.as_bytes()),
                super::sha256_hex(identity.network_passphrase.as_bytes())
            );
        }
        Ok(())
    }

    fn account_url(&self, account_id: &str) -> String {
        format!("{}/accounts/{account_id}", self.endpoint)
    }
}

impl AccountTransport for HorizonAccountTransport {
    fn inspect_account(&self, account_id: &str) -> Result<AccountPolicy> {
        self.verify_network_identity()?;
        let url = self.account_url(account_id);
        let response = self.agent.get(&url).call().map_err(|error| {
            transport_error(
                error,
                &format!("failed to inspect account at {}", redact_url(&url)),
            )
        })?;
        let account: HorizonAccount = response
            .into_json()
            .context("Horizon account response was malformed JSON")?;
        account.into_policy(&self.network_passphrase, account_id)
    }

    fn submit_envelope(
        &self,
        signed_envelope_xdr: &str,
        _expected_after: &AccountPolicy,
    ) -> Result<SubmissionResult> {
        if signed_envelope_xdr.trim().is_empty() {
            bail!("signed transaction envelope is empty");
        }
        self.verify_network_identity()?;
        let url = format!("{}/transactions", self.endpoint);
        let body = format!("tx={}", urlencoding::encode(signed_envelope_xdr.trim()));
        let response = self
            .agent
            .post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body)
            .map_err(|error| {
                transport_error(
                    error,
                    &format!("Horizon rejected transaction at {}", redact_url(&url)),
                )
            })?;
        let submitted: HorizonSubmission = response
            .into_json()
            .context("Horizon transaction response was malformed JSON")?;
        Ok(SubmissionResult {
            transaction_hash: submitted.hash,
            ledger: submitted.ledger,
            successful: submitted.successful,
        })
    }
}

#[derive(Debug, Deserialize)]
struct HorizonRoot {
    network_passphrase: String,
}

#[derive(Debug, Deserialize)]
struct HorizonAccount {
    #[serde(default)]
    id: String,
    #[serde(default)]
    account_id: String,
    sequence: String,
    #[serde(default)]
    last_modified_ledger: Option<u32>,
    thresholds: HorizonThresholds,
    signers: Vec<HorizonSigner>,
}

#[derive(Debug, Deserialize)]
struct HorizonThresholds {
    low_threshold: u32,
    med_threshold: u32,
    high_threshold: u32,
}

#[derive(Debug, Deserialize)]
struct HorizonSigner {
    key: String,
    weight: u32,
    #[serde(rename = "type")]
    signer_type: String,
    #[serde(default)]
    sponsor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HorizonSubmission {
    hash: String,
    #[serde(default)]
    ledger: Option<u32>,
    #[serde(default = "default_success")]
    successful: bool,
}

fn default_success() -> bool {
    true
}

impl HorizonAccount {
    fn into_policy(self, network: &str, requested_account: &str) -> Result<AccountPolicy> {
        let account_id = if !self.account_id.is_empty() {
            self.account_id
        } else {
            self.id
        };
        if account_id != requested_account {
            bail!("Horizon returned an inconsistent account identity");
        }
        let sequence = self
            .sequence
            .parse::<i64>()
            .context("Horizon account sequence was not a signed 64-bit integer")?;
        let low = u8::try_from(self.thresholds.low_threshold)
            .context("Horizon low threshold exceeds the Stellar u8 range")?;
        let medium = u8::try_from(self.thresholds.med_threshold)
            .context("Horizon medium threshold exceeds the Stellar u8 range")?;
        let high = u8::try_from(self.thresholds.high_threshold)
            .context("Horizon high threshold exceeds the Stellar u8 range")?;

        let mut master_weight = None;
        let mut signers = Vec::new();
        for signer in self.signers {
            let weight = u8::try_from(signer.weight)
                .context("Horizon signer weight exceeds the Stellar u8 range")?;
            if signer.key == account_id && signer.signer_type == "ed25519_public_key" {
                master_weight = Some(weight);
                continue;
            }
            if weight == 0 {
                continue;
            }
            signers.push(AccountSigner {
                key: signer.key,
                weight,
                signer_type: SignerType::from_horizon(&signer.signer_type)?,
                availability: SignerAvailability::Unavailable,
                sponsored_by: signer.sponsor,
                label: None,
            });
        }
        let policy = AccountPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            network: network.to_string(),
            account_id,
            sequence,
            observed_ledger: self.last_modified_ledger,
            master_key: MasterKeyPolicy {
                weight: master_weight.context("Horizon response omitted the master signer")?,
                availability: SignerAvailability::Unavailable,
            },
            thresholds: Thresholds { low, medium, high },
            signers,
        };
        policy.validate_structure()?;
        Ok(policy)
    }
}

fn is_loopback_http(endpoint: &str) -> bool {
    endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:")
        || endpoint.starts_with("http://[::1]:")
}

fn transport_error(error: ureq::Error, context: &str) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => {
            let code = response
                .into_json::<HorizonProblem>()
                .ok()
                .and_then(|problem| problem.extras)
                .and_then(|extras| extras.result_codes)
                .and_then(|codes| codes.transaction)
                .unwrap_or_else(|| "unavailable".to_string());
            anyhow::anyhow!("{context}: HTTP {status}, transaction result code {code}")
        }
        ureq::Error::Transport(_) => anyhow::anyhow!("{context}: bounded network transport error"),
    }
}

#[derive(Debug, Deserialize)]
struct HorizonProblem {
    #[serde(default)]
    extras: Option<HorizonProblemExtras>,
}

#[derive(Debug, Deserialize)]
struct HorizonProblemExtras {
    #[serde(default)]
    result_codes: Option<HorizonResultCodes>,
}

#[derive(Debug, Deserialize)]
struct HorizonResultCodes {
    #[serde(default)]
    transaction: Option<String>,
}

/// Deterministic, thread-safe transport used by tests and offline recovery
/// tools.  It never opens a socket and can inject concurrent policy changes.
#[derive(Clone)]
pub struct InMemoryAccountTransport {
    inner: Arc<Mutex<InMemoryState>>,
}

struct InMemoryState {
    policy: AccountPolicy,
    submissions: Vec<String>,
    fail_next_submission: Option<String>,
}

impl InMemoryAccountTransport {
    pub fn new(policy: AccountPolicy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryState {
                policy,
                submissions: Vec::new(),
                fail_next_submission: None,
            })),
        }
    }

    pub fn replace_policy(&self, policy: AccountPolicy) {
        self.inner.lock().expect("transport lock poisoned").policy = policy;
    }

    pub fn fail_next_submission(&self, message: impl Into<String>) {
        self.inner
            .lock()
            .expect("transport lock poisoned")
            .fail_next_submission = Some(message.into());
    }

    pub fn submitted_count(&self) -> usize {
        self.inner
            .lock()
            .expect("transport lock poisoned")
            .submissions
            .len()
    }
}

impl AccountTransport for InMemoryAccountTransport {
    fn inspect_account(&self, account_id: &str) -> Result<AccountPolicy> {
        let state = self.inner.lock().expect("transport lock poisoned");
        if state.policy.account_id != account_id {
            bail!("fixture transport account mismatch");
        }
        Ok(state.policy.clone())
    }

    fn submit_envelope(
        &self,
        signed_envelope_xdr: &str,
        expected_after: &AccountPolicy,
    ) -> Result<SubmissionResult> {
        let mut state = self.inner.lock().expect("transport lock poisoned");
        if let Some(message) = state.fail_next_submission.take() {
            bail!("fixture submission failed: {message}");
        }
        state
            .submissions
            .push(super::sha256_hex(signed_envelope_xdr.as_bytes()));
        state.policy = expected_after.clone();
        Ok(SubmissionResult {
            transaction_hash: format!("fixture-{:04}", state.submissions.len()),
            ledger: state.policy.observed_ledger,
            successful: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    #[test]
    fn horizon_probe_parses_sponsorship_and_network_identity() {
        let mut server = Server::new();
        let root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"network_passphrase":"fixture network"}"#)
            .expect(1)
            .create();
        let account = server
            .mock("GET", format!("/accounts/{ACCOUNT}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"id":"{ACCOUNT}","sequence":"22","last_modified_ledger":40,"thresholds":{{"low_threshold":1,"med_threshold":2,"high_threshold":2}},"signers":[{{"key":"{ACCOUNT}","weight":1,"type":"ed25519_public_key"}},{{"key":"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H","weight":2,"type":"ed25519_public_key","sponsor":"{ACCOUNT}"}}]}}"#
            ))
            .expect(1)
            .create();
        let transport =
            HorizonAccountTransport::new(server.url(), "fixture network", Duration::from_secs(2))
                .unwrap();
        let policy = transport.inspect_account(ACCOUNT).unwrap();
        assert_eq!(policy.sequence, 22);
        assert_eq!(policy.signers[0].sponsored_by.as_deref(), Some(ACCOUNT));
        root.assert();
        account.assert();
    }

    #[test]
    fn identity_mismatch_is_actionable_without_passphrase_disclosure() {
        let mut server = Server::new();
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"network_passphrase":"wrong secret passphrase"}"#)
            .create();
        let transport = HorizonAccountTransport::new(
            server.url(),
            "expected secret passphrase",
            Duration::from_secs(2),
        )
        .unwrap();
        let message = transport.inspect_account(ACCOUNT).unwrap_err().to_string();
        assert!(message.contains("identity mismatch"));
        assert!(!message.contains("secret passphrase"));
    }

    #[test]
    fn malformed_probe_is_contextual() {
        let mut server = Server::new();
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not-json")
            .create();
        let transport =
            HorizonAccountTransport::new(server.url(), "fixture", Duration::from_secs(2)).unwrap();
        assert!(transport
            .inspect_account(ACCOUNT)
            .unwrap_err()
            .to_string()
            .contains("malformed JSON"));
    }
}
