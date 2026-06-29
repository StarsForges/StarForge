use crate::utils::config;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use stellar_strkey::ed25519::{
    PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey,
};
use stellar_xdr::curr::{
    BytesM, DecoratedSignature, Hash, Limits, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, ReadXdr, SequenceNumber, SetOptionsOp, Signature as XdrSignature,
    SignatureHint, Signer as XdrSigner, SignerKey, Transaction, TransactionEnvelope,
    TransactionExt, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    WriteXdr,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiSigAccount {
    pub name: String,
    pub account_id: String,
    pub signers: Vec<Signer>,
    pub thresholds: Thresholds,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signer {
    pub public_key: String,
    pub weight: u8,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Thresholds {
    pub low: u8,
    pub medium: u8,
    pub high: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            low: 1,
            medium: 1,
            high: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigTransaction {
    pub id: String,
    pub account_id: String,
    pub transaction_xdr: String,
    pub signatures: Vec<Signature>,
    pub threshold_required: u8,
    pub current_weight: u8,
    pub status: TransactionStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    pub signer_key: String,
    pub signature: String,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    ReadyToSubmit,
    Submitted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigSetupStep {
    pub title: String,
    pub command: String,
}

fn multisig_dir() -> Result<PathBuf> {
    let dir = crate::utils::config::get_data_dir()?.join("multisig");
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn account_path(name: &str) -> Result<PathBuf> {
    Ok(multisig_dir()?.join(format!("{}.json", name)))
}

pub fn save_account(account: &MultiSigAccount) -> Result<()> {
    let path = account_path(&account.name)?;
    fs::write(&path, serde_json::to_string_pretty(account)?)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

pub fn load_account(name: &str) -> Result<MultiSigAccount> {
    let path = account_path(name)?;
    let s =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let acct: MultiSigAccount =
        serde_json::from_str(&s).with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(acct)
}

pub fn list_accounts() -> Result<Vec<MultiSigAccount>> {
    let dir = multisig_dir()?;
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(s) = fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(acct) = serde_json::from_str::<MultiSigAccount>(&s) {
            out.push(acct);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn load_transaction(path: &Path) -> Result<MultiSigTransaction> {
    let s =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let tx: MultiSigTransaction =
        serde_json::from_str(&s).with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(tx)
}

pub fn save_transaction(path: &Path, tx: &MultiSigTransaction) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(tx)?)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

#[allow(dead_code)]
pub fn validate_signer(public_key: &str) -> Result<()> {
    StellarPublicKey::from_string(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Stellar public key: {}", public_key))?;
    Ok(())
}

#[allow(dead_code)]
pub fn validate_weight(weight: u8) -> Result<()> {
    if weight == 0 {
        anyhow::bail!("Signer weight must be greater than 0");
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_threshold(threshold: u8) -> Result<()> {
    if threshold == 0 {
        anyhow::bail!("Threshold must be greater than 0");
    }
    Ok(())
}

pub fn validate_thresholds(thresholds: &Thresholds, total_weight: u8) -> Result<()> {
    validate_threshold(thresholds.low)?;
    validate_threshold(thresholds.medium)?;
    validate_threshold(thresholds.high)?;

    if thresholds.low > total_weight {
        anyhow::bail!(
            "Low threshold ({}) exceeds total signer weight ({})",
            thresholds.low,
            total_weight
        );
    }
    if thresholds.medium > total_weight {
        anyhow::bail!(
            "Medium threshold ({}) exceeds total signer weight ({})",
            thresholds.medium,
            total_weight
        );
    }
    if thresholds.high > total_weight {
        anyhow::bail!(
            "High threshold ({}) exceeds total signer weight ({})",
            thresholds.high,
            total_weight
        );
    }

    Ok(())
}

pub fn calculate_total_weight(signers: &[Signer]) -> u8 {
    signers.iter().map(|s| s.weight).sum()
}

pub fn check_transaction_ready(tx: &MultiSigTransaction) -> bool {
    tx.current_weight >= tx.threshold_required
}

pub fn add_signature_to_transaction(
    tx: &mut MultiSigTransaction,
    signer_key: &str,
    signature: String,
) -> Result<()> {
    // Check if already signed
    if tx.signatures.iter().any(|s| s.signer_key == signer_key) {
        anyhow::bail!(
            "Signer '{}' has already signed this transaction",
            signer_key
        );
    }

    let sig = Signature {
        signer_key: signer_key.to_string(),
        signature,
        signed_at: chrono::Utc::now().to_rfc3339(),
    };

    tx.signatures.push(sig);

    // Best-effort tracking; callers should keep `current_weight` coherent.
    tx.current_weight = tx.signatures.len().min(u8::MAX as usize) as u8;

    // Update status
    if check_transaction_ready(tx) {
        tx.status = TransactionStatus::ReadyToSubmit;
    }

    Ok(())
}

pub fn load_transaction_xdr(path: &Path) -> Result<String> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    if let Ok(tx) = serde_json::from_str::<MultiSigTransaction>(&raw) {
        validate_transaction_envelope_xdr(&tx.transaction_xdr)?;
        return Ok(tx.transaction_xdr);
    }

    let xdr = raw.trim().to_string();
    validate_transaction_envelope_xdr(&xdr)?;
    Ok(xdr)
}

pub fn save_transaction_xdr(path: &Path, transaction_xdr: &str) -> Result<()> {
    fs::write(path, format!("{}\n", transaction_xdr.trim()))
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

pub fn validate_transaction_envelope_xdr(transaction_xdr: &str) -> Result<()> {
    decode_transaction_envelope(transaction_xdr).map(|_| ())
}

pub fn signature_count(transaction_xdr: &str) -> Result<usize> {
    let envelope = decode_transaction_envelope(transaction_xdr)?;
    Ok(match envelope {
        TransactionEnvelope::TxV0(tx_v0) => tx_v0.signatures.len(),
        TransactionEnvelope::Tx(tx_v1) => tx_v1.signatures.len(),
        TransactionEnvelope::TxFeeBump(fee_bump) => fee_bump.signatures.len(),
    })
}

pub fn build_account_setup_transaction_xdr(
    account: &MultiSigAccount,
    source_sequence: &str,
) -> Result<String> {
    let source_account = MuxedAccount::from_str(&account.account_id)
        .map_err(|_| anyhow::anyhow!("Invalid source account: {}", account.account_id))?;
    let sequence = next_sequence_number(source_sequence)?;

    let mut operations = Vec::with_capacity(account.signers.len() + 1);
    for signer in &account.signers {
        let signer_key = SignerKey::from_str(&signer.public_key)
            .map_err(|_| anyhow::anyhow!("Invalid signer public key: {}", signer.public_key))?;
        operations.push(set_options_operation(SetOptionsOp {
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
                weight: signer.weight as u32,
            }),
        }));
    }

    operations.push(set_options_operation(SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: None,
        master_weight: None,
        low_threshold: Some(account.thresholds.low as u32),
        med_threshold: Some(account.thresholds.medium as u32),
        high_threshold: Some(account.thresholds.high as u32),
        home_domain: None,
        signer: None,
    }));

    let fee = (operations.len() as u32)
        .checked_mul(100)
        .context("Transaction fee overflow")?;
    let tx = Transaction {
        source_account,
        fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: operations
            .try_into()
            .map_err(|_| anyhow::anyhow!("Operation count exceeds Stellar transaction limit"))?,
        ext: TransactionExt::V0,
    };

    encode_transaction_envelope(&TransactionEnvelope::from(tx))
}

pub fn build_account_setup_transaction(
    account: &MultiSigAccount,
    source_sequence: &str,
) -> Result<MultiSigTransaction> {
    let transaction_xdr = build_account_setup_transaction_xdr(account, source_sequence)?;

    Ok(MultiSigTransaction {
        id: format!("setup-{}", account.name),
        account_id: account.account_id.clone(),
        transaction_xdr,
        signatures: Vec::new(),
        threshold_required: account.thresholds.high,
        current_weight: 0,
        status: TransactionStatus::Pending,
        created_at: chrono::Utc::now().to_rfc3339(),
    })
}

pub fn sign_transaction_envelope(
    transaction_xdr: &str,
    secret_key: &str,
    network: &str,
) -> Result<(String, String, bool)> {
    let mut envelope = decode_transaction_envelope(transaction_xdr)?;
    let signing_key = signing_key_from_secret(secret_key)?;
    let public_key = signing_key.verifying_key().to_bytes();
    let signer_public_key = StellarPublicKey(public_key).to_string();
    let hint = SignatureHint([
        public_key[28],
        public_key[29],
        public_key[30],
        public_key[31],
    ]);

    if envelope_has_signature_hint(&envelope, &hint) {
        return Ok((transaction_xdr.trim().to_string(), signer_public_key, false));
    }

    let hash = transaction_signature_hash(&envelope, network)?;
    let signature = signing_key.sign(&hash);
    let decorated = DecoratedSignature {
        hint,
        signature: XdrSignature(
            BytesM::try_from(signature.to_bytes().to_vec())
                .map_err(|_| anyhow::anyhow!("Failed to encode ed25519 signature as XDR bytes"))?,
        ),
    };

    append_decorated_signature(&mut envelope, decorated)?;
    Ok((encode_transaction_envelope(&envelope)?, signer_public_key, true))
}

fn set_options_operation(set_options: SetOptionsOp) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::SetOptions(set_options),
    }
}

fn next_sequence_number(source_sequence: &str) -> Result<i64> {
    let sequence = source_sequence
        .parse::<i64>()
        .with_context(|| format!("Invalid source account sequence: {}", source_sequence))?;
    sequence
        .checked_add(1)
        .context("Source account sequence overflow")
}

fn signing_key_from_secret(secret_key: &str) -> Result<SigningKey> {
    let decoded = StellarPrivateKey::from_string(secret_key)
        .context("Failed to parse Stellar secret key for signing")?;
    Ok(SigningKey::from_bytes(&decoded.0))
}

fn decode_transaction_envelope(transaction_xdr: &str) -> Result<TransactionEnvelope> {
    let xdr_bytes = BASE64
        .decode(transaction_xdr.trim())
        .context("Failed to decode base64 transaction envelope XDR")?;
    TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
        .context("Failed to parse transaction envelope XDR")
}

fn encode_transaction_envelope(envelope: &TransactionEnvelope) -> Result<String> {
    let xdr_bytes = envelope
        .to_xdr(Limits::none())
        .context("Failed to encode transaction envelope XDR")?;
    Ok(BASE64.encode(xdr_bytes))
}

fn transaction_signature_hash(envelope: &TransactionEnvelope, network: &str) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let network_passphrase = config::get_network_passphrase(network);
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
    let tagged_transaction = match envelope {
        TransactionEnvelope::Tx(tx_v1) => {
            TransactionSignaturePayloadTaggedTransaction::Tx(tx_v1.tx.clone())
        }
        TransactionEnvelope::TxFeeBump(fee_bump) => {
            TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fee_bump.tx.clone())
        }
        TransactionEnvelope::TxV0(_) => {
            anyhow::bail!("TransactionEnvelope::TxV0 signing is not supported")
        }
    };

    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id),
        tagged_transaction,
    };
    let payload_xdr = payload
        .to_xdr(Limits::none())
        .context("Failed to XDR-encode transaction signature payload")?;
    Ok(Sha256::digest(&payload_xdr).into())
}

fn envelope_has_signature_hint(envelope: &TransactionEnvelope, hint: &SignatureHint) -> bool {
    match envelope {
        TransactionEnvelope::TxV0(tx_v0) => tx_v0
            .signatures
            .iter()
            .any(|sig| sig.hint.0 == hint.0),
        TransactionEnvelope::Tx(tx_v1) => tx_v1
            .signatures
            .iter()
            .any(|sig| sig.hint.0 == hint.0),
        TransactionEnvelope::TxFeeBump(fee_bump) => {
            fee_bump.signatures.iter().any(|sig| sig.hint.0 == hint.0)
        }
    }
}

fn append_decorated_signature(
    envelope: &mut TransactionEnvelope,
    signature: DecoratedSignature,
) -> Result<()> {
    match envelope {
        TransactionEnvelope::Tx(tx_v1) => {
            let mut signatures: Vec<DecoratedSignature> =
                tx_v1.signatures.iter().cloned().collect();
            signatures.push(signature);
            tx_v1.signatures = signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("Signature count exceeds envelope limit"))?;
        }
        TransactionEnvelope::TxFeeBump(fee_bump) => {
            let mut signatures: Vec<DecoratedSignature> =
                fee_bump.signatures.iter().cloned().collect();
            signatures.push(signature);
            fee_bump.signatures = signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("Signature count exceeds envelope limit"))?;
        }
        TransactionEnvelope::TxV0(_) => {
            anyhow::bail!("TransactionEnvelope::TxV0 signing is not supported")
        }
    }
    Ok(())
}

pub fn build_stellar_cli_steps(account: &MultiSigAccount, network: &str) -> Vec<MultisigSetupStep> {
    let signer_args = account
        .signers
        .iter()
        .map(|signer| {
            format!(
                "--signer {} --signer-weight {}",
                signer.public_key, signer.weight
            )
        })
        .collect::<Vec<_>>()
        .join(" ");

    vec![
        MultisigSetupStep {
            title: "Inspect the current account state".to_string(),
            command: format!(
                "stellar account show --account {} --network {}",
                account.account_id, network
            ),
        },
        MultisigSetupStep {
            title: "Apply signer weights and thresholds on-chain".to_string(),
            command: format!(
                "stellar tx new set-options --source-account {} {} --low-threshold {} --med-threshold {} --high-threshold {} --network {}",
                account.account_id,
                signer_args,
                account.thresholds.low,
                account.thresholds.medium,
                account.thresholds.high,
                network
            ),
        },
        MultisigSetupStep {
            title: "Verify the account now reflects the multi-sig settings".to_string(),
            command: format!(
                "stellar account show --account {} --network {}",
                account.account_id, network
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_signer() {
        // Generate a valid key for testing
        use ed25519_dalek::SigningKey;
        use rand::RngCore;
        use stellar_strkey::ed25519::PublicKey as StellarPublicKey;

        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let valid_key = StellarPublicKey(verifying_key.to_bytes()).to_string();

        assert!(validate_signer(&valid_key).is_ok());

        let invalid_key = "INVALID_KEY";
        assert!(validate_signer(invalid_key).is_err());
    }

    #[test]
    fn test_validate_weight() {
        assert!(validate_weight(1).is_ok());
        assert!(validate_weight(255).is_ok());
        assert!(validate_weight(0).is_err());
    }

    #[test]
    fn test_calculate_total_weight() {
        let signers = vec![
            Signer {
                public_key: "GABC...".to_string(),
                weight: 10,
                name: None,
            },
            Signer {
                public_key: "GDEF...".to_string(),
                weight: 20,
                name: None,
            },
        ];
        assert_eq!(calculate_total_weight(&signers), 30);
    }

    #[test]
    fn test_validate_thresholds() {
        let thresholds = Thresholds {
            low: 10,
            medium: 20,
            high: 30,
        };
        assert!(validate_thresholds(&thresholds, 30).is_ok());
        assert!(validate_thresholds(&thresholds, 25).is_err());
    }

    #[test]
    fn test_check_transaction_ready() {
        let tx = MultiSigTransaction {
            id: "tx1".to_string(),
            account_id: "GABC...".to_string(),
            transaction_xdr: "mock_xdr".to_string(),
            signatures: vec![],
            threshold_required: 20,
            current_weight: 25,
            status: TransactionStatus::Pending,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        assert!(check_transaction_ready(&tx));

        let tx2 = MultiSigTransaction {
            current_weight: 15,
            ..tx
        };
        assert!(!check_transaction_ready(&tx2));
    }

    #[test]
    fn build_account_setup_transaction_xdr_creates_set_options_envelope() {
        let (source_public, _) = test_keypair();
        let (signer_public, _) = test_keypair();
        let account = MultiSigAccount {
            name: "treasury".to_string(),
            account_id: source_public,
            signers: vec![Signer {
                public_key: signer_public,
                weight: 1,
                name: Some("alice".to_string()),
            }],
            thresholds: Thresholds {
                low: 1,
                medium: 1,
                high: 1,
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let xdr = build_account_setup_transaction_xdr(&account, "123").unwrap();
        let envelope = decode_transaction_envelope(&xdr).unwrap();
        let TransactionEnvelope::Tx(tx_v1) = envelope else {
            panic!("expected v1 transaction envelope");
        };

        assert_eq!(tx_v1.tx.seq_num.0, 124);
        assert_eq!(tx_v1.tx.fee, 200);
        assert_eq!(tx_v1.tx.operations.len(), 2);

        let OperationBody::SetOptions(signer_options) = &tx_v1.tx.operations[0].body else {
            panic!("expected signer SetOptions operation");
        };
        assert_eq!(signer_options.signer.as_ref().unwrap().weight, 1);

        let OperationBody::SetOptions(threshold_options) = &tx_v1.tx.operations[1].body else {
            panic!("expected threshold SetOptions operation");
        };
        assert_eq!(threshold_options.low_threshold, Some(1));
        assert_eq!(threshold_options.med_threshold, Some(1));
        assert_eq!(threshold_options.high_threshold, Some(1));
    }

    #[test]
    fn sign_transaction_envelope_appends_decorated_signature_once() {
        let (source_public, _) = test_keypair();
        let (signer_public, signer_secret) = test_keypair();
        let account = MultiSigAccount {
            name: "treasury".to_string(),
            account_id: source_public,
            signers: vec![Signer {
                public_key: signer_public,
                weight: 1,
                name: Some("alice".to_string()),
            }],
            thresholds: Thresholds {
                low: 1,
                medium: 1,
                high: 1,
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let xdr = build_account_setup_transaction_xdr(&account, "123").unwrap();
        let (signed_xdr, _, added) =
            sign_transaction_envelope(&xdr, &signer_secret, "testnet").unwrap();
        assert!(added);
        assert_eq!(signature_count(&signed_xdr).unwrap(), 1);

        let (signed_again, _, added_again) =
            sign_transaction_envelope(&signed_xdr, &signer_secret, "testnet").unwrap();
        assert!(!added_again);
        assert_eq!(signature_count(&signed_again).unwrap(), 1);
    }

    fn test_keypair() -> (String, String) {
        use rand::RngCore;

        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = StellarPublicKey(signing_key.verifying_key().to_bytes()).to_string();
        let secret_key = StellarPrivateKey(seed).to_string();
        (public_key, secret_key)
    }
}
