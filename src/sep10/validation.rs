use super::types::{ChallengeDetails, ChallengeValidationConfig, Sep10Error, ValidationReport};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
use stellar_xdr::curr::{
    DecoratedSignature, Limits, OperationBody, Preconditions, ReadXdr, Signature as XdrSignature,
    SignatureHint, Transaction, TransactionEnvelope, TransactionV1Envelope, WriteXdr,
};

/// Core validation engine implementing complete SEP-10 challenge validation rules.
pub struct Sep10Validator;

impl Sep10Validator {
    /// Decode, inspect, and strictly validate a SEP-10 challenge transaction against server signing key
    /// and expected client public key.
    pub fn validate(
        challenge_xdr: &str,
        server_signing_key: &str,
        expected_client_account: &str,
        config: &ChallengeValidationConfig,
    ) -> Result<ValidationReport, Sep10Error> {
        let xdr_bytes = base64::engine::general_purpose::STANDARD
            .decode(challenge_xdr)
            .map_err(|e| Sep10Error::InvalidEnvelope(format!("Base64 decode failed: {e}")))?;

        let envelope = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
            .map_err(|e| Sep10Error::InvalidEnvelope(format!("XDR envelope parse failed: {e}")))?;

        let mut checks_passed = Vec::new();
        let mut warnings = Vec::new();

        let tx_v1 = match envelope {
            TransactionEnvelope::Tx(ref v1) => v1,
            _ => {
                return Err(Sep10Error::InvalidEnvelope(
                    "SEP-10 challenge must use TransactionEnvelope::Tx (V1)".to_string(),
                ));
            }
        };

        let tx = &tx_v1.tx;

        // Check 1: Sequence number must be exactly 0
        if tx.seq_num.0 != 0 {
            return Err(Sep10Error::InvalidSequenceNumber(tx.seq_num.0));
        }
        checks_passed.push("Sequence number is strictly 0".to_string());

        // Check 2: Server source account verification
        let server_source_pk = Self::extract_source_account_pk(&tx.source_account)?;
        if server_source_pk != server_signing_key {
            return Err(Sep10Error::SourceAccountMismatch {
                expected: server_signing_key.to_string(),
                actual: server_source_pk,
            });
        }
        checks_passed.push(format!(
            "Source account matches anchor server key ({server_signing_key})"
        ));

        // Check 3: Timebounds precondition verification
        let (min_time, max_time) = Self::extract_time_bounds(tx)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let skew = config.allowed_clock_skew_secs;
        if now + skew < min_time {
            return Err(Sep10Error::ChallengePremature {
                min_time,
                current_time: now,
            });
        }
        if now > max_time + skew {
            return Err(Sep10Error::ChallengeExpired {
                max_time,
                current_time: now,
            });
        }

        let duration = max_time.saturating_sub(min_time);
        if duration > config.max_challenge_duration_secs {
            return Err(Sep10Error::ExcessiveDuration {
                duration_secs: duration,
                max_allowed: config.max_challenge_duration_secs,
            });
        }
        checks_passed.push(format!(
            "Time bounds valid [min: {min_time}, max: {max_time}, duration: {duration}s, skew tolerance: {skew}s]"
        ));

        // Check 4: Operations validation
        if tx.operations.is_empty() {
            return Err(Sep10Error::EmptyOperations);
        }

        // Operation 0: Must be ManageData with client account as source and valid nonce
        let first_op = &tx.operations[0];
        let op0_source = first_op.source_account.as_ref().ok_or_else(|| {
            Sep10Error::InvalidFirstOperation(
                "Operation 0 must specify a source account".to_string(),
            )
        })?;
        let client_source_pk = Self::extract_source_account_pk(op0_source)?;

        if client_source_pk != expected_client_account {
            return Err(Sep10Error::SourceAccountMismatch {
                expected: expected_client_account.to_string(),
                actual: client_source_pk.clone(),
            });
        }

        let (home_domain, nonce_len) = match &first_op.body {
            OperationBody::ManageData(ref md) => {
                let key_str = md.data_name.0.to_utf8_string_lossy();
                let domain = if let Some(stripped) = key_str.strip_suffix(" auth") {
                    stripped.to_string()
                } else {
                    key_str.clone()
                };

                if let Some(ref expected_home) = config.expected_home_domain {
                    if domain != *expected_home {
                        return Err(Sep10Error::HomeDomainMismatch {
                            expected: expected_home.clone(),
                            actual: domain,
                        });
                    }
                }

                let len = match &md.data_value {
                    Some(dv) if dv.0.len() == 48 || dv.0.len() == 64 => dv.0.len(),
                    Some(dv) => {
                        return Err(Sep10Error::InvalidNonce(format!(
                            "Nonce must be 48 or 64 bytes cryptographic random bytes, got {}",
                            dv.0.len()
                        )));
                    }
                    None => {
                        return Err(Sep10Error::InvalidNonce(
                            "ManageData operation missing value".to_string(),
                        ))
                    }
                };

                (domain, len)
            }
            _ => {
                return Err(Sep10Error::InvalidFirstOperation(
                    "First operation must be ManageData".to_string(),
                ));
            }
        };
        checks_passed.push(format!(
            "First operation is valid ManageData (client: {client_source_pk}, domain: {home_domain}, nonce: {nonce_len}B)"
        ));

        // Inspect subsequent operations (web_auth_domain, client_domain)
        let mut web_auth_domain = None;
        let mut client_domain = None;

        for (idx, op) in tx.operations.iter().enumerate().skip(1) {
            match &op.body {
                OperationBody::ManageData(ref md) => {
                    let key = md.data_name.0.to_utf8_string_lossy();
                    if key == "web_auth_domain" {
                        if let Some(ref val) = md.data_value {
                            let val_str = String::from_utf8_lossy(&val.0).to_string();
                            web_auth_domain = Some(val_str);
                        }
                    } else if key == "client_domain" {
                        if let Some(ref val) = md.data_value {
                            let val_str = String::from_utf8_lossy(&val.0).to_string();
                            client_domain = Some(val_str);
                        }
                    } else {
                        warnings.push(format!(
                            "Additional unknown ManageData key '{key}' at operation index {idx}"
                        ));
                    }
                }
                _ => {
                    return Err(Sep10Error::InvalidEnvelope(format!(
                        "Operation at index {idx} is not ManageData (forbidden in SEP-10)"
                    )));
                }
            }
        }

        if let Some(ref exp_web) = config.expected_web_auth_domain {
            if let Some(ref actual_web) = web_auth_domain {
                if exp_web != actual_web {
                    return Err(Sep10Error::WebAuthDomainMismatch {
                        expected: exp_web.clone(),
                        actual: actual_web.clone(),
                    });
                }
                checks_passed.push(format!("web_auth_domain matched expected '{exp_web}'"));
            } else if config.require_web_auth_domain {
                return Err(Sep10Error::WebAuthDomainMismatch {
                    expected: exp_web.clone(),
                    actual: "[missing]".to_string(),
                });
            }
        }

        if let Some(ref exp_client) = config.expected_client_domain {
            if let Some(ref actual_client) = client_domain {
                if exp_client != actual_client {
                    return Err(Sep10Error::ClientDomainMismatch {
                        expected: exp_client.clone(),
                        actual: actual_client.clone(),
                    });
                }
                checks_passed.push(format!("client_domain matched expected '{exp_client}'"));
            } else if config.require_client_domain {
                return Err(Sep10Error::ClientDomainMismatch {
                    expected: exp_client.clone(),
                    actual: "[missing]".to_string(),
                });
            }
        }

        // Check 5: Server signature verification
        let tx_hash = Self::compute_transaction_hash(tx, &config.network_passphrase)?;
        let server_sig_valid = Self::verify_server_signature(tx_v1, server_signing_key, &tx_hash)?;

        if !server_sig_valid {
            return Err(Sep10Error::InvalidServerSignature(
                "No valid cryptographic signature found for server signing key".to_string(),
            ));
        }
        checks_passed.push("Server cryptographic Ed25519 signature verified strictly".to_string());

        let details = ChallengeDetails {
            server_account: server_source_pk,
            client_account: client_source_pk,
            sequence_number: tx.seq_num.0,
            min_time,
            max_time,
            duration_secs: duration,
            time_to_expiry_secs: (max_time as i64) - (now as i64),
            home_domain,
            web_auth_domain,
            client_domain,
            nonce_length_bytes: nonce_len,
            server_signature_valid: true,
            existing_signatures_count: tx_v1.signatures.len(),
        };

        Ok(ValidationReport {
            is_valid: true,
            checks_passed,
            warnings,
            details,
        })
    }

    /// Extract public key string from a Stellar MuxedAccount
    pub fn extract_source_account_pk(
        acc: &stellar_xdr::curr::MuxedAccount,
    ) -> Result<String, Sep10Error> {
        match acc {
            stellar_xdr::curr::MuxedAccount::Ed25519(uint256) => {
                let pk = StellarPublicKey(uint256.0);
                Ok(pk.to_string())
            }
            stellar_xdr::curr::MuxedAccount::MuxedEd25519(med) => {
                let pk = StellarPublicKey(med.ed25519.0);
                Ok(pk.to_string())
            }
        }
    }

    /// Extract time bounds from transaction preconditions
    fn extract_time_bounds(tx: &Transaction) -> Result<(u64, u64), Sep10Error> {
        match &tx.cond {
            Preconditions::Time(tb) => Ok((tb.min_time.0, tb.max_time.0)),
            Preconditions::V2(v2) => {
                let tb = v2
                    .time_bounds
                    .as_ref()
                    .ok_or(Sep10Error::MissingTimeBounds)?;
                Ok((tb.min_time.0, tb.max_time.0))
            }
            Preconditions::None => Err(Sep10Error::MissingTimeBounds),
        }
    }

    /// Compute transaction signature payload hash
    pub fn compute_transaction_hash(
        tx: &Transaction,
        network_passphrase: &str,
    ) -> Result<[u8; 32], Sep10Error> {
        let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
        let tx_body = tx.to_xdr(Limits::none()).map_err(|e| {
            Sep10Error::SerializationError(format!("Failed to serialize tx body: {e}"))
        })?;

        let mut payload = Vec::with_capacity(36 + tx_body.len());
        payload.extend_from_slice(&network_id);
        payload.extend_from_slice(&[0u8, 0, 0, 2]); // ENVELOPE_TYPE_TX = 2
        payload.extend_from_slice(&tx_body);

        let hash: [u8; 32] = Sha256::digest(&payload).into();
        Ok(hash)
    }

    /// Verify that the transaction envelope contains a valid signature from server_pubkey_str
    fn verify_server_signature(
        v1: &TransactionV1Envelope,
        server_pubkey_str: &str,
        tx_hash: &[u8; 32],
    ) -> Result<bool, Sep10Error> {
        let server_pk = StellarPublicKey::from_string(server_pubkey_str).map_err(|e| {
            Sep10Error::CryptoError(format!("Invalid server public key strkey: {e}"))
        })?;

        let pk_bytes = server_pk.0;
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
            Sep10Error::CryptoError(format!("Failed to parse ed25519 verifying key: {e}"))
        })?;

        let expected_hint = SignatureHint(pk_bytes[28..32].try_into().unwrap());

        for dec_sig in v1.signatures.iter() {
            if dec_sig.hint == expected_hint {
                if let Ok(sig_bytes) = <[u8; 64]>::try_from(dec_sig.signature.0.as_slice()) {
                    let sig = Signature::from_bytes(&sig_bytes);
                    if verifying_key.verify_strict(tx_hash, &sig).is_ok() {
                        return Ok(true);
                    }
                }
            }
        }

        // Also fallback to checking all signatures regardless of hint
        for dec_sig in v1.signatures.iter() {
            if let Ok(sig_bytes) = <[u8; 64]>::try_from(dec_sig.signature.0.as_slice()) {
                let sig = Signature::from_bytes(&sig_bytes);
                if verifying_key.verify_strict(tx_hash, &sig).is_ok() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Signs the challenge transaction with the client's secret key and returns base64 encoded XDR.
    pub fn sign_challenge(
        challenge_xdr: &str,
        client_secret_key: &str,
        network_passphrase: &str,
    ) -> Result<String, Sep10Error> {
        let xdr_bytes = base64::engine::general_purpose::STANDARD
            .decode(challenge_xdr)
            .map_err(|e| Sep10Error::InvalidEnvelope(format!("Base64 decode failed: {e}")))?;

        let envelope = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
            .map_err(|e| Sep10Error::InvalidEnvelope(format!("XDR envelope parse failed: {e}")))?;

        let TransactionEnvelope::Tx(mut v1) = envelope else {
            return Err(Sep10Error::InvalidEnvelope(
                "Must be TransactionEnvelope::Tx".to_string(),
            ));
        };

        let tx_hash = Self::compute_transaction_hash(&v1.tx, network_passphrase)?;

        let priv_key = stellar_strkey::ed25519::PrivateKey::from_string(client_secret_key)
            .map_err(|e| Sep10Error::CryptoError(format!("Invalid client private key: {e}")))?;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_key.0);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let sig = ed25519_dalek::Signer::sign(&signing_key, &tx_hash);
        let hint = SignatureHint(pubkey_bytes[28..32].try_into().unwrap());

        let dec_sig = DecoratedSignature {
            hint,
            signature: XdrSignature(sig.to_bytes().to_vec().try_into().unwrap()),
        };

        let mut sigs = v1.signatures.to_vec();
        sigs.push(dec_sig);
        v1.signatures = sigs
            .try_into()
            .map_err(|_| Sep10Error::SerializationError("Too many signatures".to_string()))?;

        let updated_env = TransactionEnvelope::Tx(v1);
        let updated_bytes = updated_env.to_xdr(Limits::none()).map_err(|e| {
            Sep10Error::SerializationError(format!("Failed to serialize signed tx: {e}"))
        })?;

        Ok(base64::engine::general_purpose::STANDARD.encode(&updated_bytes))
    }
}
