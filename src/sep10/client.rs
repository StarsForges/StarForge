use super::session::EncryptedTokenStore;
use super::types::{ChallengeValidationConfig, Sep10Error, SessionToken, ValidationReport};
use super::validation::Sep10Validator;
use anyhow::Result;
use serde_json::Value;

/// High-level client for executing authenticated SEP-10 sessions.
pub struct Sep10Client {
    store: EncryptedTokenStore,
}

impl Sep10Client {
    pub fn new() -> Result<Self, Sep10Error> {
        let store = EncryptedTokenStore::default_store()?;
        Ok(Self { store })
    }

    /// Authenticate against an anchor domain using a local wallet key.
    /// Checks the encrypted cache first; if expired or missing, performs a full handshake.
    pub fn authenticate(
        &self,
        anchor_domain: &str,
        wallet_public_key: &str,
        wallet_secret_key: &str,
        client_domain: Option<&str>,
        force_refresh: bool,
    ) -> Result<SessionToken, Sep10Error> {
        // Step 1: Check cached token if not forced
        if !force_refresh {
            if let Ok(Some(cached)) = self.store.get_session(anchor_domain, wallet_public_key) {
                if !cached.is_expired() {
                    return Ok(cached);
                }
            }
        }

        // Step 2: Fetch stellar.toml
        let toml_url = format!("https://{}/.well-known/stellar.toml", anchor_domain);
        let toml_resp = ureq::get(&toml_url)
            .timeout(std::time::Duration::from_secs(10))
            .call()
            .map_err(|e| {
                Sep10Error::NetworkError(format!(
                    "Failed to fetch stellar.toml from {toml_url}: {e}"
                ))
            })?;

        let toml_body = toml_resp
            .into_string()
            .map_err(|e| Sep10Error::SerializationError(format!("Read toml body error: {e}")))?;

        let toml_val: toml::Value = toml::from_str(&toml_body)
            .map_err(|e| Sep10Error::StellarTomlError(anchor_domain.to_string(), e.to_string()))?;

        let web_auth_endpoint = toml_val
            .get("WEB_AUTH_ENDPOINT")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Sep10Error::StellarTomlError(
                    anchor_domain.to_string(),
                    "Missing WEB_AUTH_ENDPOINT in stellar.toml".to_string(),
                )
            })?;

        let signing_key = toml_val
            .get("SIGNING_KEY")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Sep10Error::StellarTomlError(
                    anchor_domain.to_string(),
                    "Missing SIGNING_KEY in stellar.toml".to_string(),
                )
            })?;

        let network_passphrase = toml_val
            .get("NETWORK_PASSPHRASE")
            .and_then(|v| v.as_str())
            .unwrap_or("Test SDF Network ; September 2015");

        // Step 3: Request challenge transaction
        let mut challenge_url = format!("{web_auth_endpoint}?account={wallet_public_key}");
        if let Some(cd) = client_domain {
            challenge_url.push_str(&format!("&client_domain={cd}"));
        }

        let resp = ureq::get(&challenge_url)
            .timeout(std::time::Duration::from_secs(10))
            .call()
            .map_err(|e| {
                Sep10Error::NetworkError(format!(
                    "Failed to request challenge from {challenge_url}: {e}"
                ))
            })?;

        let resp_json: Value = resp.into_json().map_err(|e| {
            Sep10Error::SerializationError(format!("Failed to parse challenge JSON: {e}"))
        })?;

        let challenge_xdr = resp_json["transaction"].as_str().ok_or_else(|| {
            Sep10Error::InvalidEnvelope(
                "Missing 'transaction' field in challenge response".to_string(),
            )
        })?;

        let resp_network = resp_json["network_passphrase"]
            .as_str()
            .unwrap_or(network_passphrase);

        // Step 4: Full challenge validation
        let config = ChallengeValidationConfig {
            allowed_clock_skew_secs: 300,
            max_challenge_duration_secs: 3600,
            expected_home_domain: Some(anchor_domain.to_string()),
            expected_web_auth_domain: None,
            expected_client_domain: client_domain.map(|s| s.to_string()),
            network_passphrase: resp_network.to_string(),
            require_web_auth_domain: false,
            require_client_domain: client_domain.is_some(),
        };

        let _report =
            Sep10Validator::validate(challenge_xdr, signing_key, wallet_public_key, &config)?;

        // Step 5: Sign the challenge transaction
        let signed_xdr =
            Sep10Validator::sign_challenge(challenge_xdr, wallet_secret_key, resp_network)?;

        // Step 6: Submit signed transaction back to anchor
        let token_resp = ureq::post(web_auth_endpoint)
            .timeout(std::time::Duration::from_secs(10))
            .send_json(serde_json::json!({
                "transaction": signed_xdr
            }))
            .map_err(|e| {
                Sep10Error::NetworkError(format!("Failed to POST signed challenge: {e}"))
            })?;

        let token_json: Value = token_resp.into_json().map_err(|e| {
            Sep10Error::SerializationError(format!("Failed to parse token JSON: {e}"))
        })?;

        let jwt = token_json["token"].as_str().ok_or_else(|| {
            Sep10Error::SerializationError("Anchor response missing 'token' field".to_string())
        })?;

        // Step 7: Parse JWT claims and save to encrypted vault
        let mut session = EncryptedTokenStore::parse_jwt_claims(jwt)?;
        session.anchor_domain = anchor_domain.to_string();
        session.account = wallet_public_key.to_string();

        self.store.store_session(&session)?;

        Ok(session)
    }

    /// Inspect a challenge XDR without signing or submitting
    pub fn inspect_challenge(
        challenge_xdr: &str,
        server_signing_key: &str,
        client_account: &str,
        network_passphrase: &str,
    ) -> Result<ValidationReport, Sep10Error> {
        let config = ChallengeValidationConfig {
            network_passphrase: network_passphrase.to_string(),
            ..Default::default()
        };
        Sep10Validator::validate(challenge_xdr, server_signing_key, client_account, &config)
    }

    /// Access the underlying encrypted store
    pub fn store(&self) -> &EncryptedTokenStore {
        &self.store
    }
}
