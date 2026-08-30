use super::{ensure_private_input, sha256_hex, AccountPolicy, PolicyMutation, Thresholds};
use crate::utils::hardware_wallet::{self, HardwareWalletKind};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};
use stellar_xdr::curr::{
    AccountId, BeginSponsoringFutureReservesOp, BytesM, DecoratedSignature, Hash, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, RevokeSponsorshipOp,
    RevokeSponsorshipOpSigner, SequenceNumber, SetOptionsOp, Signature as XdrSignature,
    SignatureHint, Signer as XdrSigner, SignerKey, Transaction, TransactionEnvelope,
    TransactionExt, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    WriteXdr,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedEnvelope {
    pub envelope_xdr: String,
    pub transaction_body_sha256: String,
    pub signature_payload_sha256: String,
    pub source_account: String,
    pub sequence: i64,
    pub operation_count: u32,
    pub fee_stroops: u32,
    pub operation_summaries: Vec<String>,
}

pub fn build_mutation_envelope(
    policy_before: &AccountPolicy,
    mutation: &PolicyMutation,
    base_fee_stroops: u32,
) -> Result<UnsignedEnvelope> {
    policy_before.require_operable("envelope source policy")?;
    if base_fee_stroops < 100 {
        bail!("base fee must be at least 100 stroops");
    }
    let source = MuxedAccount::from_str(&policy_before.account_id)
        .map_err(|_| anyhow::anyhow!("invalid source account for rotation envelope"))?;
    let sequence = policy_before
        .sequence
        .checked_add(1)
        .context("account sequence overflow")?;
    let (operations, summaries) = mutation_operations(policy_before, mutation)?;
    let operation_count = u32::try_from(operations.len()).context("operation count overflow")?;
    let fee_stroops = base_fee_stroops
        .checked_mul(operation_count)
        .context("transaction fee overflow")?;
    let transaction = Transaction {
        source_account: source,
        fee: fee_stroops,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: operations
            .try_into()
            .map_err(|_| anyhow::anyhow!("rotation operation count exceeds the Stellar limit"))?,
        ext: TransactionExt::V0,
    };
    let envelope = TransactionEnvelope::from(transaction);
    let body = transaction_body_bytes(&envelope)?;
    let signature_hash = transaction_signature_hash(&envelope, &policy_before.network)?;
    let envelope_xdr = encode_envelope(&envelope)?;
    Ok(UnsignedEnvelope {
        envelope_xdr,
        transaction_body_sha256: sha256_hex(&body),
        signature_payload_sha256: hex::encode(signature_hash),
        source_account: policy_before.account_id.clone(),
        sequence,
        operation_count,
        fee_stroops,
        operation_summaries: summaries,
    })
}

fn mutation_operations(
    policy: &AccountPolicy,
    mutation: &PolicyMutation,
) -> Result<(Vec<Operation>, Vec<String>)> {
    let source_account = AccountId::from_str(&policy.account_id)
        .map_err(|_| anyhow::anyhow!("invalid account ID for rotation operation"))?;
    let mut operations = Vec::new();
    let mut summaries = Vec::new();
    match mutation {
        PolicyMutation::AddSigner { signer } => {
            if let Some(sponsor) = &signer.sponsored_by {
                append_sponsored_signer_add(
                    &mut operations,
                    &mut summaries,
                    &source_account,
                    sponsor,
                    &signer.key,
                    signer.weight,
                )?;
            } else {
                operations.push(set_signer_operation(&signer.key, signer.weight, None)?);
                summaries.push(format!(
                    "set signer {} weight {}",
                    super::redact_key(&signer.key),
                    signer.weight
                ));
            }
        }
        PolicyMutation::UpdateSigner { after, .. } => {
            operations.push(set_signer_operation(&after.key, after.weight, None)?);
            summaries.push(format!(
                "set signer {} weight {}",
                super::redact_key(&after.key),
                after.weight
            ));
        }
        PolicyMutation::RemoveSigner { signer } => {
            operations.push(set_signer_operation(&signer.key, 0, None)?);
            summaries.push(format!("remove signer {}", super::redact_key(&signer.key)));
        }
        PolicyMutation::SetMasterWeight { to, .. } => {
            operations.push(set_options_operation(
                None,
                SetOptionsOp {
                    inflation_dest: None,
                    clear_flags: None,
                    set_flags: None,
                    master_weight: Some(u32::from(*to)),
                    low_threshold: None,
                    med_threshold: None,
                    high_threshold: None,
                    home_domain: None,
                    signer: None,
                },
            ));
            summaries.push(format!("set master weight {to}"));
        }
        PolicyMutation::SetThresholds { to, .. } => {
            operations.push(set_threshold_operation(*to));
            summaries.push(format!(
                "set thresholds {}/{}/{}",
                to.low, to.medium, to.high
            ));
        }
        PolicyMutation::SetSignerSponsorship {
            key,
            from_sponsor,
            to_sponsor,
        } => match (from_sponsor, to_sponsor) {
            (Some(_), None) => {
                let signer_key = SignerKey::from_str(key)
                    .map_err(|_| anyhow::anyhow!("invalid signer key for sponsorship release"))?;
                operations.push(Operation {
                    source_account: None,
                    body: OperationBody::RevokeSponsorship(RevokeSponsorshipOp::Signer(
                        RevokeSponsorshipOpSigner {
                            account_id: source_account,
                            signer_key,
                        },
                    )),
                });
                summaries.push(format!(
                    "release sponsorship for signer {}",
                    super::redact_key(key)
                ));
            }
            (_, Some(sponsor)) => {
                let signer = policy
                    .signer(key)
                    .context("sponsorship mutation refers to a missing signer")?;
                operations.push(set_signer_operation(key, 0, None)?);
                summaries.push(format!(
                    "remove signer {} before sponsorship replacement",
                    super::redact_key(key)
                ));
                append_sponsored_signer_add(
                    &mut operations,
                    &mut summaries,
                    &source_account,
                    sponsor,
                    key,
                    signer.weight,
                )?;
            }
            (None, None) => bail!("sponsorship mutation has no effect"),
        },
    }
    Ok((operations, summaries))
}

fn append_sponsored_signer_add(
    operations: &mut Vec<Operation>,
    summaries: &mut Vec<String>,
    sponsored_account: &AccountId,
    sponsor: &str,
    signer_key: &str,
    weight: u8,
) -> Result<()> {
    let sponsor_source = MuxedAccount::from_str(sponsor)
        .map_err(|_| anyhow::anyhow!("invalid sponsor account for signer operation"))?;
    operations.push(Operation {
        source_account: Some(sponsor_source),
        body: OperationBody::BeginSponsoringFutureReserves(BeginSponsoringFutureReservesOp {
            sponsored_id: sponsored_account.clone(),
        }),
    });
    operations.push(set_signer_operation(signer_key, weight, None)?);
    operations.push(Operation {
        source_account: None,
        body: OperationBody::EndSponsoringFutureReserves,
    });
    summaries.push(format!(
        "begin sponsorship from {}",
        super::redact_key(sponsor)
    ));
    summaries.push(format!(
        "set sponsored signer {} weight {}",
        super::redact_key(signer_key),
        weight
    ));
    summaries.push("end sponsorship scope".to_string());
    Ok(())
}

fn set_signer_operation(
    key: &str,
    weight: u8,
    source_account: Option<MuxedAccount>,
) -> Result<Operation> {
    let signer_key = SignerKey::from_str(key)
        .map_err(|_| anyhow::anyhow!("invalid Stellar signer key {}", super::redact_key(key)))?;
    Ok(set_options_operation(
        source_account,
        SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(XdrSigner {
                key: signer_key,
                weight: u32::from(weight),
            }),
        },
    ))
}

fn set_threshold_operation(thresholds: Thresholds) -> Operation {
    set_options_operation(
        None,
        SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: Some(u32::from(thresholds.low)),
            med_threshold: Some(u32::from(thresholds.medium)),
            high_threshold: Some(u32::from(thresholds.high)),
            home_domain: None,
            signer: None,
        },
    )
}

fn set_options_operation(source_account: Option<MuxedAccount>, options: SetOptionsOp) -> Operation {
    Operation {
        source_account,
        body: OperationBody::SetOptions(options),
    }
}

pub fn sign_envelope_with_secret(
    envelope_xdr: &str,
    secret_key: &str,
    network_passphrase: &str,
) -> Result<(String, String, bool)> {
    let mut envelope = decode_envelope(envelope_xdr)?;
    let decoded = StellarPrivateKey::from_string(secret_key)
        .context("failed to parse Stellar secret key from protected input")?;
    let signing_key = SigningKey::from_bytes(&decoded.0);
    let public_bytes = signing_key.verifying_key().to_bytes();
    let public_key = StellarPublicKey(public_bytes).to_string();
    let hint = signature_hint(&public_bytes);
    if envelope_has_hint(&envelope, &hint) {
        return Ok((envelope_xdr.trim().to_string(), public_key, false));
    }
    let hash = transaction_signature_hash(&envelope, network_passphrase)?;
    let signature = signing_key.sign(&hash).to_bytes().to_vec();
    append_signature(&mut envelope, hint, signature)?;
    Ok((encode_envelope(&envelope)?, public_key, true))
}

pub fn sign_envelope_with_secret_file(
    envelope_xdr: &str,
    secret_file: &Path,
    network_passphrase: &str,
) -> Result<(String, String, bool)> {
    ensure_private_input(secret_file)?;
    let secret = Zeroizing::new(fs::read_to_string(secret_file).with_context(|| {
        format!(
            "failed to read protected key file {}",
            secret_file.display()
        )
    })?);
    sign_envelope_with_secret(envelope_xdr, secret.trim(), network_passphrase)
}

pub fn sign_envelope_with_hardware(
    envelope_xdr: &str,
    kind: HardwareWalletKind,
    network_passphrase: &str,
) -> Result<(String, String, bool)> {
    let mut envelope = decode_envelope(envelope_xdr)?;
    let public_key = hardware_wallet::get_stellar_address(kind, hardware_wallet::STELLAR_HD_PATH)
        .context("failed to obtain hardware signer address")?;
    let parsed = StellarPublicKey::from_string(&public_key)
        .context("hardware wallet returned an invalid Stellar public key")?;
    let hint = signature_hint(&parsed.0);
    if envelope_has_hint(&envelope, &hint) {
        return Ok((envelope_xdr.trim().to_string(), public_key, false));
    }
    let hash = transaction_signature_hash(&envelope, network_passphrase)?;
    let signature = hardware_wallet::sign(kind, &hash).context("hardware signing failed")?;
    append_signature(&mut envelope, hint, signature)?;
    Ok((encode_envelope(&envelope)?, public_key, true))
}

pub fn verify_signed_envelope_body(
    signed_envelope_xdr: &str,
    expected_body_sha256: &str,
) -> Result<usize> {
    let envelope = decode_envelope(signed_envelope_xdr)?;
    let actual = sha256_hex(&transaction_body_bytes(&envelope)?);
    if actual != expected_body_sha256 {
        bail!("signed envelope transaction body does not match the planned mutation");
    }
    Ok(signature_count(&envelope))
}

pub fn envelope_signature_payload(
    envelope_xdr: &str,
    network_passphrase: &str,
) -> Result<[u8; 32]> {
    transaction_signature_hash(&decode_envelope(envelope_xdr)?, network_passphrase)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedEnvelopeApproval {
    pub signer_key: String,
    pub weight: u8,
    pub master_key: bool,
}

/// Cryptographically verify each candidate signer against an envelope.  The
/// returned weight is safe to use for threshold checks; signature hints alone
/// are never treated as evidence because hints can collide.
pub fn verified_envelope_approvals(
    envelope_xdr: &str,
    policy: &AccountPolicy,
) -> Result<Vec<VerifiedEnvelopeApproval>> {
    use stellar_xdr::curr::Uint256;

    let envelope = decode_envelope(envelope_xdr)?;
    let transaction_hash = transaction_signature_hash(&envelope, &policy.network)?;
    let signatures = envelope_signatures(&envelope);
    let mut verified = Vec::new();

    for candidate in policy.approval_candidates() {
        let approved = if candidate.master_key {
            verify_ed25519_candidate(&candidate.key, &transaction_hash, &signatures)?
        } else if let Some(signer) = policy.signer(&candidate.key) {
            match SignerKey::from_str(&signer.key)
                .map_err(|_| anyhow::anyhow!("invalid signer key in approval policy"))?
            {
                SignerKey::Ed25519(_) => {
                    verify_ed25519_candidate(&signer.key, &transaction_hash, &signatures)?
                }
                SignerKey::PreAuthTx(Uint256(expected)) => expected == transaction_hash,
                SignerKey::HashX(Uint256(expected)) => signatures.iter().any(|signature| {
                    Sha256::digest(&signature.signature.0[..]).as_slice() == expected
                }),
                SignerKey::Ed25519SignedPayload(payload) => {
                    let mut signed = Vec::with_capacity(32 + payload.payload.len());
                    signed.extend_from_slice(&transaction_hash);
                    signed.extend_from_slice(&payload.payload);
                    let key = StellarPublicKey(payload.ed25519.0).to_string();
                    verify_ed25519_candidate(&key, &signed, &signatures)?
                }
            }
        } else {
            false
        };
        if approved {
            verified.push(VerifiedEnvelopeApproval {
                signer_key: candidate.key,
                weight: candidate.weight,
                master_key: candidate.master_key,
            });
        }
    }
    Ok(verified)
}

pub fn verify_external_account_signature(
    envelope_xdr: &str,
    network_passphrase: &str,
    account_id: &str,
) -> Result<bool> {
    let envelope = decode_envelope(envelope_xdr)?;
    let hash = transaction_signature_hash(&envelope, network_passphrase)?;
    verify_ed25519_candidate(account_id, &hash, &envelope_signatures(&envelope))
}

fn verify_ed25519_candidate(
    public_key: &str,
    message: &[u8],
    signatures: &[DecoratedSignature],
) -> Result<bool> {
    let parsed = StellarPublicKey::from_string(public_key)
        .map_err(|_| anyhow::anyhow!("invalid ed25519 approval key"))?;
    let verifying = VerifyingKey::from_bytes(&parsed.0)
        .map_err(|_| anyhow::anyhow!("invalid ed25519 approval key bytes"))?;
    let hint = signature_hint(&parsed.0);
    for decorated in signatures.iter().filter(|decorated| decorated.hint == hint) {
        let Ok(bytes) = <[u8; 64]>::try_from(&decorated.signature.0[..]) else {
            continue;
        };
        let signature = DalekSignature::from_bytes(&bytes);
        if verifying.verify(message, &signature).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn envelope_signatures(envelope: &TransactionEnvelope) -> Vec<DecoratedSignature> {
    match envelope {
        TransactionEnvelope::Tx(transaction) => transaction.signatures.to_vec(),
        TransactionEnvelope::TxFeeBump(transaction) => transaction.signatures.to_vec(),
        TransactionEnvelope::TxV0(transaction) => transaction.signatures.to_vec(),
    }
}

fn decode_envelope(value: &str) -> Result<TransactionEnvelope> {
    use stellar_xdr::curr::ReadXdr;
    let bytes = BASE64
        .decode(value.trim())
        .context("transaction envelope is not valid base64")?;
    TransactionEnvelope::from_xdr(&bytes, Limits::none())
        .context("transaction envelope contains malformed XDR")
}

fn encode_envelope(envelope: &TransactionEnvelope) -> Result<String> {
    Ok(BASE64.encode(
        envelope
            .to_xdr(Limits::none())
            .context("failed to encode transaction envelope XDR")?,
    ))
}

fn transaction_body_bytes(envelope: &TransactionEnvelope) -> Result<Vec<u8>> {
    match envelope {
        TransactionEnvelope::Tx(transaction) => transaction
            .tx
            .to_xdr(Limits::none())
            .context("failed to encode transaction body"),
        TransactionEnvelope::TxFeeBump(transaction) => transaction
            .tx
            .to_xdr(Limits::none())
            .context("failed to encode fee-bump transaction body"),
        TransactionEnvelope::TxV0(_) => bail!("legacy V0 transaction envelopes are unsupported"),
    }
}

fn transaction_signature_hash(
    envelope: &TransactionEnvelope,
    network_passphrase: &str,
) -> Result<[u8; 32]> {
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
    let tagged_transaction = match envelope {
        TransactionEnvelope::Tx(transaction) => {
            TransactionSignaturePayloadTaggedTransaction::Tx(transaction.tx.clone())
        }
        TransactionEnvelope::TxFeeBump(transaction) => {
            TransactionSignaturePayloadTaggedTransaction::TxFeeBump(transaction.tx.clone())
        }
        TransactionEnvelope::TxV0(_) => bail!("legacy V0 transaction envelopes are unsupported"),
    };
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id),
        tagged_transaction,
    };
    let bytes = payload
        .to_xdr(Limits::none())
        .context("failed to encode transaction signature payload")?;
    Ok(Sha256::digest(bytes).into())
}

fn append_signature(
    envelope: &mut TransactionEnvelope,
    hint: SignatureHint,
    signature: Vec<u8>,
) -> Result<()> {
    let decorated = DecoratedSignature {
        hint,
        signature: XdrSignature(
            BytesM::try_from(signature)
                .map_err(|_| anyhow::anyhow!("signature exceeds the Stellar XDR limit"))?,
        ),
    };
    match envelope {
        TransactionEnvelope::Tx(transaction) => {
            let mut signatures = transaction.signatures.to_vec();
            signatures.push(decorated);
            transaction.signatures = signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("transaction signature count exceeds the limit"))?;
        }
        TransactionEnvelope::TxFeeBump(transaction) => {
            let mut signatures = transaction.signatures.to_vec();
            signatures.push(decorated);
            transaction.signatures = signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("transaction signature count exceeds the limit"))?;
        }
        TransactionEnvelope::TxV0(_) => bail!("legacy V0 transaction envelopes are unsupported"),
    }
    Ok(())
}

fn envelope_has_hint(envelope: &TransactionEnvelope, hint: &SignatureHint) -> bool {
    match envelope {
        TransactionEnvelope::Tx(transaction) => transaction
            .signatures
            .iter()
            .any(|signature| signature.hint == *hint),
        TransactionEnvelope::TxFeeBump(transaction) => transaction
            .signatures
            .iter()
            .any(|signature| signature.hint == *hint),
        TransactionEnvelope::TxV0(transaction) => transaction
            .signatures
            .iter()
            .any(|signature| signature.hint == *hint),
    }
}

fn signature_count(envelope: &TransactionEnvelope) -> usize {
    match envelope {
        TransactionEnvelope::Tx(transaction) => transaction.signatures.len(),
        TransactionEnvelope::TxFeeBump(transaction) => transaction.signatures.len(),
        TransactionEnvelope::TxV0(transaction) => transaction.signatures.len(),
    }
}

fn signature_hint(public_key: &[u8; 32]) -> SignatureHint {
    SignatureHint([
        public_key[28],
        public_key[29],
        public_key[30],
        public_key[31],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_rotation::{AccountSigner, MasterKeyPolicy, SignerAvailability, SignerType};
    use rand::RngCore;

    fn keys() -> (String, String) {
        let mut seed = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        (
            StellarPublicKey(signing.verifying_key().to_bytes()).to_string(),
            StellarPrivateKey(seed).to_string(),
        )
    }

    fn policy(account: String) -> AccountPolicy {
        AccountPolicy {
            schema_version: 1,
            network: "Test SDF Network ; September 2015".to_string(),
            account_id: account,
            sequence: 100,
            observed_ledger: Some(200),
            master_key: MasterKeyPolicy {
                weight: 1,
                availability: SignerAvailability::Software,
            },
            thresholds: Thresholds {
                low: 1,
                medium: 1,
                high: 1,
            },
            signers: Vec::new(),
        }
    }

    #[test]
    fn set_options_envelope_round_trips_and_signs() {
        let (account, secret) = keys();
        let (signer, _) = keys();
        let policy = policy(account);
        let mutation = PolicyMutation::AddSigner {
            signer: AccountSigner {
                key: signer,
                weight: 2,
                signer_type: SignerType::Ed25519PublicKey,
                availability: SignerAvailability::Hardware,
                sponsored_by: None,
                label: None,
            },
        };
        let artifact = build_mutation_envelope(&policy, &mutation, 100).unwrap();
        assert_eq!(artifact.operation_count, 1);
        let (signed, signer, added) =
            sign_envelope_with_secret(&artifact.envelope_xdr, &secret, &policy.network).unwrap();
        assert_eq!(signer, policy.account_id);
        assert!(added);
        assert_eq!(
            verify_signed_envelope_body(&signed, &artifact.transaction_body_sha256).unwrap(),
            1
        );
    }

    #[test]
    fn sponsored_add_has_begin_set_end_operations() {
        let (account, _) = keys();
        let (sponsor, _) = keys();
        let (signer, _) = keys();
        let policy = policy(account);
        let mutation = PolicyMutation::AddSigner {
            signer: AccountSigner {
                key: signer,
                weight: 1,
                signer_type: SignerType::Ed25519PublicKey,
                availability: SignerAvailability::Offline,
                sponsored_by: Some(sponsor),
                label: None,
            },
        };
        let artifact = build_mutation_envelope(&policy, &mutation, 100).unwrap();
        assert_eq!(artifact.operation_count, 3);
        assert_eq!(artifact.fee_stroops, 300);
    }

    #[cfg(unix)]
    #[test]
    fn permissive_secret_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let (account, secret) = keys();
        let policy = policy(account);
        let mutation = PolicyMutation::SetMasterWeight { from: 1, to: 2 };
        let artifact = build_mutation_envelope(&policy, &mutation, 100).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret");
        fs::write(&path, secret).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            sign_envelope_with_secret_file(&artifact.envelope_xdr, &path, &policy.network)
                .unwrap_err()
                .to_string()
                .contains("restrict it to 600")
        );
    }
}
