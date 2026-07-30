//! Multisig ceremony: a portable, self-describing file that carries an
//! unsigned transaction through an M-of-N signing process across
//! independent (potentially air-gapped) machines.
//!
//! A ceremony file bundles:
//!   - a `manifest` describing the source account, required signers,
//!     threshold, expiry, and integrity hashes
//!   - the transaction envelope XDR, which accumulates signatures as each
//!     signer runs `ceremony sign` against the file
//!   - a `signature_log` recording who signed and when (and whether via a
//!     hardware wallet), independent of what the raw XDR signature hints
//!     reveal
//!
//! Every operation that reads a ceremony file first re-derives its integrity
//! hashes from the current contents and compares them against the stored
//! values, so a file edited (accidentally or otherwise) after the first
//! signature is rejected rather than silently signed or submitted.

use crate::utils::config;
use crate::utils::hardware_wallet::{self, HardwareWalletKind};
use crate::utils::multisig;
use crate::utils::tx_batch::BatchOperation;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
use stellar_xdr::curr::{
    AccountId, AlphaNum12, AlphaNum4, Asset, AssetCode12, AssetCode4, BytesM, DecoratedSignature,
    Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions, SequenceNumber,
    Signature as XdrSignature, SignatureHint, TimeBounds, TimePoint, Transaction,
    TransactionEnvelope, TransactionExt,
};

/// Ceremony file format version. Bump when the on-disk schema changes in a
/// way that isn't backwards compatible.
pub const CEREMONY_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyManifest {
    pub source_account: String,
    pub network: String,
    pub threshold: u8,
    pub required_signers: Vec<String>,
    pub operation_summary: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    /// sha256 hex of the unsigned transaction body (no signatures).
    pub tx_body_hash: String,
    /// sha256 hex of the manifest fields above, used to detect tampering
    /// with the ceremony parameters themselves (threshold, signer set,
    /// expiry) independent of the transaction body.
    pub manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningMethod {
    Local,
    Hardware { device: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonySignatureRecord {
    pub signer: String,
    pub signed_at: String,
    pub method: SigningMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyFile {
    pub version: u32,
    pub manifest: CeremonyManifest,
    pub transaction_envelope_xdr: String,
    pub signature_log: Vec<CeremonySignatureRecord>,
}

#[derive(Debug, Clone)]
pub struct SignOutcome {
    pub signer: String,
    pub already_signed: bool,
}

#[derive(Debug, Clone)]
pub struct CeremonyStatusReport {
    pub required_threshold: u8,
    pub collected: usize,
    pub required_total: usize,
    pub threshold_met: bool,
    pub signed_signers: Vec<String>,
    pub outstanding_signers: Vec<String>,
    pub expires_at: Option<String>,
    pub expired: bool,
    pub seconds_remaining: Option<i64>,
}

/// Build a new ceremony: an unsigned transaction envelope for `operation`
/// plus a manifest recording the signers/threshold/expiry that must hold
/// for the lifetime of the ceremony.
#[allow(clippy::too_many_arguments)]
pub fn build_ceremony(
    source_account: &str,
    operation: &BatchOperation,
    sequence: &str,
    threshold: u8,
    mut required_signers: Vec<String>,
    network: &str,
    expires_in_minutes: Option<i64>,
) -> Result<CeremonyFile> {
    if required_signers.is_empty() {
        anyhow::bail!("A ceremony requires at least one signer");
    }
    if threshold == 0 {
        anyhow::bail!("Threshold must be greater than 0");
    }

    required_signers.sort();
    required_signers.dedup();

    if (threshold as usize) > required_signers.len() {
        anyhow::bail!(
            "Threshold ({}) exceeds the number of distinct signers provided ({})",
            threshold,
            required_signers.len()
        );
    }
    for signer in &required_signers {
        config::validate_public_key(signer)
            .with_context(|| format!("Invalid signer public key: {}", signer))?;
    }

    let expires_at_unix = match expires_in_minutes {
        Some(minutes) if minutes > 0 => Some(Utc::now().timestamp() + minutes * 60),
        Some(_) => anyhow::bail!("Expiry window must be a positive number of minutes"),
        None => None,
    };

    let envelope =
        build_transaction_envelope(source_account, operation, sequence, expires_at_unix)?;
    let tx_body_hash = hash_tx_body(&envelope)?;
    let expires_at = expires_at_unix.map(format_unix_timestamp);

    let mut manifest = CeremonyManifest {
        source_account: source_account.to_string(),
        network: network.to_string(),
        threshold,
        required_signers,
        operation_summary: describe_operation(operation),
        created_at: Utc::now().to_rfc3339(),
        expires_at,
        tx_body_hash,
        manifest_hash: String::new(),
    };
    manifest.manifest_hash = manifest_fingerprint(&manifest);

    Ok(CeremonyFile {
        version: CEREMONY_FORMAT_VERSION,
        manifest,
        transaction_envelope_xdr: multisig::encode_transaction_envelope(&envelope)?,
        signature_log: Vec::new(),
    })
}

/// Re-derive the manifest and transaction-body hashes from the current file
/// contents and compare them against the stored values. Any edit to the
/// signer set, threshold, expiry, or transaction body after ceremony start
/// is rejected here.
pub fn verify_integrity(file: &CeremonyFile) -> Result<()> {
    if file.version != CEREMONY_FORMAT_VERSION {
        anyhow::bail!(
            "Unsupported ceremony file version {} (expected {})",
            file.version,
            CEREMONY_FORMAT_VERSION
        );
    }

    let expected_manifest_hash = manifest_fingerprint(&file.manifest);
    if expected_manifest_hash != file.manifest.manifest_hash {
        anyhow::bail!(
            "Ceremony manifest integrity check failed: the required signers, threshold, \
             network, or expiry was modified after the ceremony started. Refusing to sign \
             or submit a tampered ceremony file."
        );
    }

    let envelope = multisig::decode_transaction_envelope(&file.transaction_envelope_xdr)?;
    let current_tx_body_hash = hash_tx_body(&envelope)?;
    if current_tx_body_hash != file.manifest.tx_body_hash {
        anyhow::bail!(
            "Transaction integrity check failed: the unsigned transaction body (source, \
             sequence, operations, or preconditions) was altered after the ceremony started. \
             Refusing to sign or submit a tampered ceremony file."
        );
    }

    Ok(())
}

/// Add this signer's signature to the ceremony file. Stateless: everything
/// needed is re-derived from `file` itself, so independent invocations
/// against the same file (e.g. on separate air-gapped machines, merged
/// later) behave identically to sequential invocations on one machine.
pub fn add_signature(
    file: &mut CeremonyFile,
    secret_key: Option<&str>,
    hardware: Option<HardwareWalletKind>,
) -> Result<SignOutcome> {
    verify_integrity(file)?;
    let network = file.manifest.network.clone();

    let signer_public_key = if let Some(kind) = hardware {
        hardware_wallet::get_stellar_address(kind, hardware_wallet::STELLAR_HD_PATH)
            .context("Failed to read Stellar address from hardware wallet")?
    } else {
        let secret_key = secret_key
            .ok_or_else(|| anyhow::anyhow!("A secret key or --hardware is required to sign"))?;
        let signing_key = multisig::signing_key_from_secret(secret_key)?;
        StellarPublicKey(signing_key.verifying_key().to_bytes()).to_string()
    };

    if !file
        .manifest
        .required_signers
        .iter()
        .any(|s| s == &signer_public_key)
    {
        anyhow::bail!(
            "Signer '{}' is not among the required signers for this ceremony ({})",
            signer_public_key,
            file.manifest.required_signers.join(", ")
        );
    }

    let (added, method) = if let Some(kind) = hardware {
        let mut envelope = multisig::decode_transaction_envelope(&file.transaction_envelope_xdr)?;
        let raw_pk = StellarPublicKey::from_string(&signer_public_key)
            .map_err(|_| anyhow::anyhow!("Invalid hardware wallet public key"))?
            .0;
        let hint = SignatureHint([raw_pk[28], raw_pk[29], raw_pk[30], raw_pk[31]]);
        let method = SigningMethod::Hardware {
            device: kind.to_string(),
        };

        if multisig::envelope_has_signature_hint(&envelope, &hint) {
            (false, method)
        } else {
            let hash = multisig::transaction_signature_hash(&envelope, &network)?;
            let raw_sig =
                hardware_wallet::sign(kind, &hash).context("Hardware wallet signing failed")?;
            let decorated = DecoratedSignature {
                hint,
                signature: XdrSignature(BytesM::try_from(raw_sig).map_err(|_| {
                    anyhow::anyhow!("Failed to encode hardware signature as XDR bytes")
                })?),
            };
            multisig::append_decorated_signature(&mut envelope, decorated)?;
            file.transaction_envelope_xdr = multisig::encode_transaction_envelope(&envelope)?;
            (true, method)
        }
    } else {
        let secret_key = secret_key.expect("checked above");
        let (signed_xdr, _pk, added) = multisig::sign_transaction_envelope(
            &file.transaction_envelope_xdr,
            secret_key,
            &network,
        )?;
        file.transaction_envelope_xdr = signed_xdr;
        (added, SigningMethod::Local)
    };

    if added {
        file.signature_log.push(CeremonySignatureRecord {
            signer: signer_public_key.clone(),
            signed_at: Utc::now().to_rfc3339(),
            method,
        });
    }

    Ok(SignOutcome {
        signer: signer_public_key,
        already_signed: !added,
    })
}

/// Collected-vs-required signature status, outstanding signers, and expiry
/// countdown for this ceremony file.
pub fn status(file: &CeremonyFile) -> Result<CeremonyStatusReport> {
    verify_integrity(file)?;

    let mut signed_signers: Vec<String> = file
        .signature_log
        .iter()
        .map(|record| record.signer.clone())
        .collect();
    signed_signers.sort();
    signed_signers.dedup();

    let outstanding_signers: Vec<String> = file
        .manifest
        .required_signers
        .iter()
        .filter(|signer| !signed_signers.contains(signer))
        .cloned()
        .collect();

    let (expired, seconds_remaining) = match &file.manifest.expires_at {
        Some(timestamp) => {
            let expiry = DateTime::parse_from_rfc3339(timestamp)
                .context("Failed to parse ceremony expiry timestamp")?
                .with_timezone(&Utc);
            let remaining = (expiry - Utc::now()).num_seconds();
            (remaining <= 0, Some(remaining))
        }
        None => (false, None),
    };

    Ok(CeremonyStatusReport {
        required_threshold: file.manifest.threshold,
        collected: signed_signers.len(),
        required_total: file.manifest.required_signers.len(),
        threshold_met: signed_signers.len() >= file.manifest.threshold as usize,
        signed_signers,
        outstanding_signers,
        expires_at: file.manifest.expires_at.clone(),
        expired,
        seconds_remaining,
    })
}

/// Verify the ceremony is ready to submit and return the final signed
/// envelope XDR. Refuses when signatures are insufficient, when the
/// envelope carries a signature from a signer outside the manifest, when
/// the ceremony has expired, or when integrity checks fail.
pub fn assemble_for_submit(file: &CeremonyFile) -> Result<String> {
    let report = status(file)?;

    if report.expired {
        anyhow::bail!(
            "Ceremony expired at {} — the transaction's time bounds have passed. Start a new ceremony.",
            report.expires_at.as_deref().unwrap_or("unknown")
        );
    }

    for record in &file.signature_log {
        if !file
            .manifest
            .required_signers
            .iter()
            .any(|s| s == &record.signer)
        {
            anyhow::bail!(
                "Ceremony file contains a signature from '{}', who is not an authorized signer \
                 for this ceremony",
                record.signer
            );
        }
    }

    if !report.threshold_met {
        let outstanding = if report.outstanding_signers.is_empty() {
            "none".to_string()
        } else {
            report.outstanding_signers.join(", ")
        };
        anyhow::bail!(
            "Not enough signatures to submit: {} of {} required signatures collected \
             (threshold {}). Outstanding signers: {}",
            report.collected,
            report.required_total,
            report.required_threshold,
            outstanding
        );
    }

    // Defense in depth: an edited signature_log claiming a threshold isn't
    // enough on its own — the raw envelope must actually carry that many
    // decoded signatures.
    let envelope_signatures = multisig::signature_count(&file.transaction_envelope_xdr)?;
    if envelope_signatures < file.manifest.threshold as usize {
        anyhow::bail!(
            "Transaction envelope carries {} signature(s), fewer than the required threshold \
             of {}. The signature log does not match the signed envelope.",
            envelope_signatures,
            file.manifest.threshold
        );
    }

    Ok(file.transaction_envelope_xdr.clone())
}

pub fn load_ceremony_file(path: &Path) -> Result<CeremonyFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read ceremony file {}", path.display()))?;
    let file: CeremonyFile = serde_json::from_str(&raw)
        .with_context(|| format!("Failed to parse ceremony file {}", path.display()))?;
    Ok(file)
}

pub fn save_ceremony_file(path: &Path, file: &CeremonyFile) -> Result<()> {
    let json = serde_json::to_string_pretty(file).context("Failed to serialize ceremony file")?;
    fs::write(path, format!("{}\n", json))
        .with_context(|| format!("Failed to write ceremony file {}", path.display()))?;
    Ok(())
}

fn manifest_fingerprint(manifest: &CeremonyManifest) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        manifest.source_account,
        manifest.network,
        manifest.threshold,
        manifest.required_signers.join(","),
        manifest.operation_summary,
        manifest.expires_at.as_deref().unwrap_or(""),
        manifest.tx_body_hash,
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn hash_tx_body(envelope: &TransactionEnvelope) -> Result<String> {
    let bytes = multisig::transaction_body_bytes(envelope)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn format_unix_timestamp(unix_seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix_seconds, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| unix_seconds.to_string())
}

fn describe_operation(operation: &BatchOperation) -> String {
    match operation {
        BatchOperation::Payment { to, amount, asset } => {
            format!("payment {} {} → {}", amount, asset, to)
        }
    }
}

fn build_transaction_envelope(
    source_account: &str,
    operation: &BatchOperation,
    sequence: &str,
    expires_at_unix: Option<i64>,
) -> Result<TransactionEnvelope> {
    let source = MuxedAccount::from_str(source_account)
        .map_err(|_| anyhow::anyhow!("Invalid source account: {}", source_account))?;
    let seq = sequence
        .parse::<i64>()
        .with_context(|| format!("Invalid sequence number: {}", sequence))?
        .checked_add(1)
        .context("Source account sequence overflow")?;

    let op = build_operation(operation)?;
    let cond = match expires_at_unix {
        Some(t) => Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(t.max(0) as u64),
        }),
        None => Preconditions::None,
    };

    let tx = Transaction {
        source_account: source,
        fee: 100,
        seq_num: SequenceNumber(seq),
        cond,
        memo: Memo::None,
        operations: vec![op]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to build operation list"))?,
        ext: TransactionExt::V0,
    };

    Ok(TransactionEnvelope::from(tx))
}

fn build_operation(operation: &BatchOperation) -> Result<Operation> {
    match operation {
        BatchOperation::Payment { to, amount, asset } => {
            let destination = MuxedAccount::from_str(to)
                .map_err(|_| anyhow::anyhow!("Invalid destination account: {}", to))?;
            let (code, issuer) = parse_asset_spec(asset)?;
            let asset = build_asset(code.as_deref(), issuer.as_deref())?;
            let amount = parse_amount_to_stroops(amount)?;
            Ok(Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination,
                    asset,
                    amount,
                }),
            })
        }
    }
}

fn parse_asset_spec(asset: &str) -> Result<(Option<String>, Option<String>)> {
    if asset.eq_ignore_ascii_case("xlm") {
        return Ok((None, None));
    }
    let parts: Vec<&str> = asset.split(':').collect();
    if parts.len() == 2 && !parts[0].is_empty() {
        return Ok((Some(parts[0].to_string()), Some(parts[1].to_string())));
    }
    anyhow::bail!("Invalid asset format '{}'. Use XLM or CODE:ISSUER", asset)
}

fn build_asset(code: Option<&str>, issuer: Option<&str>) -> Result<Asset> {
    match (code, issuer) {
        (None, None) => Ok(Asset::Native),
        (Some(code), Some(issuer)) => {
            let issuer_id = AccountId::from_str(issuer)
                .map_err(|_| anyhow::anyhow!("Invalid asset issuer: {}", issuer))?;
            if code.is_empty() || code.len() > 12 {
                anyhow::bail!("Asset code must be 1-12 characters");
            }
            if code.len() <= 4 {
                Ok(Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4::from_str(code)
                        .map_err(|_| anyhow::anyhow!("Invalid asset code: {}", code))?,
                    issuer: issuer_id,
                }))
            } else {
                Ok(Asset::CreditAlphanum12(AlphaNum12 {
                    asset_code: AssetCode12::from_str(code)
                        .map_err(|_| anyhow::anyhow!("Invalid asset code: {}", code))?,
                    issuer: issuer_id,
                }))
            }
        }
        _ => anyhow::bail!("Invalid asset specification"),
    }
}

fn parse_amount_to_stroops(amount: &str) -> Result<i64> {
    let amount = amount.trim();
    if amount.starts_with('-') {
        anyhow::bail!("Amount '{}' must not be negative", amount);
    }
    let (whole, frac) = match amount.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (amount, ""),
    };
    if frac.len() > 7 {
        anyhow::bail!("Amount '{}' has more than 7 decimal places", amount);
    }

    let whole_val: i64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .with_context(|| format!("Invalid amount: {}", amount))?
    };

    let mut frac_digits = frac.to_string();
    while frac_digits.len() < 7 {
        frac_digits.push('0');
    }
    let frac_val: i64 = if frac_digits.is_empty() {
        0
    } else {
        frac_digits
            .parse()
            .with_context(|| format!("Invalid amount: {}", amount))?
    };

    whole_val
        .checked_mul(10_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .ok_or_else(|| anyhow::anyhow!("Amount '{}' overflows i64 stroops", amount))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use stellar_strkey::ed25519::PrivateKey as StellarPrivateKey;

    fn test_keypair() -> (String, String) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = StellarPublicKey(signing_key.verifying_key().to_bytes()).to_string();
        let secret_key = StellarPrivateKey(seed).to_string();
        (public_key, secret_key)
    }

    fn sample_ceremony(signers: &[(String, String)], threshold: u8) -> CeremonyFile {
        let (source_public, _source_secret) = test_keypair();
        let (dest_public, _) = test_keypair();
        let op = BatchOperation::Payment {
            to: dest_public,
            amount: "100".to_string(),
            asset: "XLM".to_string(),
        };
        let required: Vec<String> = signers.iter().map(|(pk, _)| pk.clone()).collect();
        build_ceremony(
            &source_public,
            &op,
            "100",
            threshold,
            required,
            "testnet",
            Some(60),
        )
        .unwrap()
    }

    #[test]
    fn round_trips_through_json() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let file = sample_ceremony(&signers, 2);

        let json = serde_json::to_string_pretty(&file).unwrap();
        let reloaded: CeremonyFile = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.manifest, file.manifest);
        assert_eq!(
            reloaded.transaction_envelope_xdr,
            file.transaction_envelope_xdr
        );
        verify_integrity(&reloaded).unwrap();
    }

    #[test]
    fn threshold_exactly_met_marks_ready() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 3);

        for (_, secret) in &signers {
            add_signature(&mut file, Some(secret), None).unwrap();
        }

        let report = status(&file).unwrap();
        assert_eq!(report.collected, 3);
        assert!(report.threshold_met);
        assert!(report.outstanding_signers.is_empty());
        assert!(assemble_for_submit(&file).is_ok());
    }

    #[test]
    fn below_threshold_is_rejected_at_submit() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 3);

        // Only two of the required three signers sign.
        add_signature(&mut file, Some(&signers[0].1), None).unwrap();
        add_signature(&mut file, Some(&signers[1].1), None).unwrap();

        let report = status(&file).unwrap();
        assert_eq!(report.collected, 2);
        assert!(!report.threshold_met);
        assert_eq!(report.outstanding_signers, vec![signers[2].0.clone()]);

        let err = assemble_for_submit(&file).unwrap_err();
        assert!(err.to_string().contains("Not enough signatures"));
    }

    #[test]
    fn independent_sign_invocations_reach_threshold_like_sequential_ones() {
        // Simulate three separate machines each loading the same on-disk
        // ceremony file independently and signing once, with no shared
        // process state between invocations.
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let file = sample_ceremony(&signers, 3);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tx.ceremony");
        save_ceremony_file(&path, &file).unwrap();

        for (_, secret) in &signers {
            let mut loaded = load_ceremony_file(&path).unwrap();
            add_signature(&mut loaded, Some(secret), None).unwrap();
            save_ceremony_file(&path, &loaded).unwrap();
        }

        let final_file = load_ceremony_file(&path).unwrap();
        let report = status(&final_file).unwrap();
        assert!(report.threshold_met);
        assert_eq!(report.collected, 3);
        assemble_for_submit(&final_file).unwrap();
    }

    #[test]
    fn duplicate_signer_does_not_double_count() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 2);

        let first = add_signature(&mut file, Some(&signers[0].1), None).unwrap();
        assert!(!first.already_signed);

        let second = add_signature(&mut file, Some(&signers[0].1), None).unwrap();
        assert!(second.already_signed);

        let report = status(&file).unwrap();
        assert_eq!(report.collected, 1);
        assert_eq!(file.signature_log.len(), 1);
    }

    #[test]
    fn unauthorized_signer_is_rejected() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 2);
        let (_outsider_public, outsider_secret) = test_keypair();

        let err = add_signature(&mut file, Some(&outsider_secret), None).unwrap_err();
        assert!(err.to_string().contains("not among the required signers"));
    }

    #[test]
    fn tampered_transaction_body_is_rejected() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 2);
        add_signature(&mut file, Some(&signers[0].1), None).unwrap();

        // Hand-edit the envelope to point at a different destination without
        // updating the stored tx_body_hash — simulates tampering after the
        // first signature was collected.
        let (other_dest, _) = test_keypair();
        let other_op = BatchOperation::Payment {
            to: other_dest,
            amount: "100".to_string(),
            asset: "XLM".to_string(),
        };
        let tampered_envelope =
            build_transaction_envelope(&file.manifest.source_account, &other_op, "100", Some(60))
                .unwrap();
        file.transaction_envelope_xdr =
            multisig::encode_transaction_envelope(&tampered_envelope).unwrap();

        let err = verify_integrity(&file).unwrap_err();
        assert!(err
            .to_string()
            .contains("Transaction integrity check failed"));

        let sign_err = add_signature(&mut file, Some(&signers[1].1), None).unwrap_err();
        assert!(sign_err
            .to_string()
            .contains("Transaction integrity check failed"));

        let submit_err = assemble_for_submit(&file).unwrap_err();
        assert!(submit_err
            .to_string()
            .contains("Transaction integrity check failed"));
    }

    #[test]
    fn tampered_manifest_threshold_is_rejected() {
        let signers = vec![test_keypair(), test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 3);
        add_signature(&mut file, Some(&signers[0].1), None).unwrap();

        // Lower the threshold after the fact without recomputing the hash —
        // simulates someone hand-editing the JSON to force an early submit.
        file.manifest.threshold = 1;

        let err = verify_integrity(&file).unwrap_err();
        assert!(err
            .to_string()
            .contains("Ceremony manifest integrity check failed"));
        assert!(assemble_for_submit(&file).is_err());
    }

    #[test]
    fn expired_ceremony_is_rejected_at_submit() {
        let signers = vec![test_keypair(), test_keypair()];
        let mut file = sample_ceremony(&signers, 2);
        for (_, secret) in &signers {
            add_signature(&mut file, Some(secret), None).unwrap();
        }

        // Force expiry into the past and re-sign the manifest hash so this
        // exercises the expiry check specifically, not tamper detection.
        file.manifest.expires_at = Some("2000-01-01T00:00:00+00:00".to_string());
        file.manifest.manifest_hash = manifest_fingerprint(&file.manifest);

        let report = status(&file).unwrap();
        assert!(report.expired);

        let err = assemble_for_submit(&file).unwrap_err();
        assert!(err.to_string().contains("Ceremony expired"));
    }

    #[test]
    fn threshold_cannot_exceed_signer_count() {
        let (source_public, _) = test_keypair();
        let (dest_public, _) = test_keypair();
        let op = BatchOperation::Payment {
            to: dest_public,
            amount: "10".to_string(),
            asset: "XLM".to_string(),
        };
        let (only_signer, _) = test_keypair();

        let err = build_ceremony(
            &source_public,
            &op,
            "1",
            2,
            vec![only_signer],
            "testnet",
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds the number"));
    }

    #[test]
    fn parses_and_rejects_amounts() {
        assert_eq!(parse_amount_to_stroops("100").unwrap(), 1_000_000_000);
        assert_eq!(parse_amount_to_stroops("1.5").unwrap(), 15_000_000);
        assert_eq!(parse_amount_to_stroops("0.0000001").unwrap(), 1);
        assert!(parse_amount_to_stroops("-1").is_err());
        assert!(parse_amount_to_stroops("1.00000001").is_err());
    }
}
