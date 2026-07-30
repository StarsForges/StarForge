use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;

use crate::utils::config::{self, WalletEntry};
use crate::utils::horizon::{self, BatchPaymentOp};

/// Maximum Stellar operations per transaction.
pub const MAX_OPS_PER_TRANSACTION: usize = 100;

/// Default retry attempts for failed chunk submissions.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Base fee per operation in stroops (0.00001 XLM).
pub const BASE_FEE_PER_OP_STROOPS: u64 = 100_000;

/// Checkpoint schema version written to disk.
pub const CHECKPOINT_VERSION: u32 = 1;

// ── Legacy JSON batch (starforge tx batch) ───────────────────────────────────

/// Root document for `starforge tx batch --file operations.json`.
#[derive(Debug, Deserialize)]
pub struct BatchOperationsFile {
    pub operations: Vec<BatchOperation>,
}

/// A single operation in a batch transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BatchOperation {
    #[serde(rename = "payment")]
    Payment {
        to: String,
        amount: String,
        #[serde(default = "default_asset")]
        asset: String,
    },
}

fn default_asset() -> String {
    "XLM".to_string()
}

pub fn load_batch_file(path: &Path) -> Result<BatchOperationsFile> {
    config::validate_file_path(path, Some("json"))?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read batch file: {}", path.display()))?;
    let doc: BatchOperationsFile = serde_json::from_str(&raw)
        .with_context(|| "Invalid batch operations JSON. Expected { \"operations\": [ ... ] }")?;
    if doc.operations.is_empty() {
        anyhow::bail!("Batch file must contain at least one operation");
    }
    if doc.operations.len() > MAX_OPS_PER_TRANSACTION {
        anyhow::bail!(
            "Batch file contains {} operations; maximum is {} per transaction",
            doc.operations.len(),
            MAX_OPS_PER_TRANSACTION
        );
    }
    Ok(doc)
}

pub fn validate_batch_operations(ops: &[BatchOperation]) -> Result<()> {
    for (i, op) in ops.iter().enumerate() {
        match op {
            BatchOperation::Payment { to, amount, asset } => {
                validate_destination_checksum(to)
                    .with_context(|| format!("Operation {}: invalid destination", i + 1))?;
                config::validate_amount(amount)
                    .with_context(|| format!("Operation {}: invalid amount", i + 1))?;
                validate_batch_asset(asset)
                    .with_context(|| format!("Operation {}: invalid asset", i + 1))?;
            }
        }
    }
    Ok(())
}

fn validate_batch_asset(asset: &str) -> Result<()> {
    if asset.to_uppercase() == "XLM" {
        return Ok(());
    }
    if asset.contains(':') {
        let parts: Vec<&str> = asset.split(':').collect();
        if parts.len() == 2 && !parts[0].is_empty() {
            validate_destination_checksum(parts[1])?;
            return Ok(());
        }
    }
    anyhow::bail!("Invalid asset format. Use XLM or CODE:ISSUER");
}

// ── CSV batch pay engine ─────────────────────────────────────────────────────

/// Parsed row from a batch payout CSV.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchRecipientRow {
    pub row_index: usize,
    pub destination: String,
    pub amount: String,
    pub asset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// Per-row execution status tracked in the checkpoint file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RowStatus {
    Pending,
    Submitted {
        tx_hash: String,
    },
    Confirmed {
        tx_hash: String,
    },
    Failed {
        error: String,
        attempts: u32,
    },
}

/// A single row in the resumable batch checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchRowState {
    pub row_index: usize,
    pub destination: String,
    pub amount: String,
    pub asset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(flatten)]
    pub status: RowStatus,
}

/// Resumable batch checkpoint persisted as `<csv>.batch-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchCheckpoint {
    pub version: u32,
    pub source_file: String,
    pub wallet: String,
    pub network: String,
    pub payer_public_key: String,
    pub created_at: String,
    pub updated_at: String,
    pub next_sequence: i64,
    pub rows: Vec<BatchRowState>,
}

/// Summary returned after validation or dry-run cost estimation.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchValidationReport {
    pub row_count: usize,
    pub total_payment_amounts: HashMap<String, f64>,
    pub estimated_fee_stroops: u64,
    pub transaction_count: usize,
}

/// Summary after executing (or resuming) a batch run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BatchRunSummary {
    pub confirmed: usize,
    pub failed: usize,
    pub pending: usize,
    pub submitted: usize,
}

/// Options controlling batch execution.
#[derive(Debug, Clone)]
pub struct BatchRunOptions {
    pub csv_path: PathBuf,
    pub wallet_name: String,
    pub network: String,
    pub dry_run: bool,
    pub max_retries: u32,
    pub resume: bool,
}

impl BatchRowState {
    pub fn from_recipient(row: &BatchRecipientRow) -> Self {
        Self {
            row_index: row.row_index,
            destination: row.destination.clone(),
            amount: row.amount.clone(),
            asset: row.asset.clone(),
            memo: row.memo.clone(),
            status: RowStatus::Pending,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            RowStatus::Confirmed { .. } | RowStatus::Failed { .. }
        )
    }

    pub fn is_payable(&self) -> bool {
        matches!(self.status, RowStatus::Pending)
    }
}

pub fn checkpoint_path_for(csv_path: &Path) -> PathBuf {
    let file_name = csv_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "batch.csv".to_string());
    csv_path.with_file_name(format!("{file_name}.batch-state.json"))
}

pub fn validate_destination_checksum(address: &str) -> Result<()> {
    StellarPublicKey::from_string(address).map_err(|_| {
        anyhow::anyhow!(
            "Invalid Stellar address '{}': checksum verification failed",
            address
        )
    })?;
    Ok(())
}

pub fn parse_batch_csv(path: &Path) -> Result<Vec<BatchRecipientRow>> {
    config::validate_file_path(path, Some("csv"))?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read CSV file: {}", path.display()))?;

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(raw.as_bytes());

    let headers = reader.headers()?.clone();
    let has_header = headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("destination"));

    let mut rows = Vec::new();
    let mut row_index = 0usize;

    if has_header {
        for result in reader.records() {
            let record = result.with_context(|| format!("Invalid CSV row {}", row_index + 2))?;
            row_index += 1;
            rows.push(parse_csv_record(row_index, &headers, &record)?);
        }
    } else {
        let fallback_headers = csv::StringRecord::from(vec!["destination", "amount", "asset"]);
        for result in reader.records() {
            let record = result.with_context(|| format!("Invalid CSV row {}", row_index + 1))?;
            row_index += 1;
            rows.push(parse_csv_record(row_index, &fallback_headers, &record)?);
        }
    }

    if rows.is_empty() {
        anyhow::bail!("CSV file must contain at least one recipient row");
    }

    Ok(rows)
}

fn parse_csv_record(
    row_index: usize,
    headers: &csv::StringRecord,
    record: &csv::StringRecord,
) -> Result<BatchRecipientRow> {
    let get = |name: &str| -> Option<String> {
        headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .and_then(|idx| record.get(idx))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let destination = get("destination")
        .or_else(|| record.get(0).map(|v| v.trim().to_string()))
        .ok_or_else(|| anyhow::anyhow!("Row {}: missing destination", row_index))?;
    let amount = get("amount")
        .or_else(|| record.get(1).map(|v| v.trim().to_string()))
        .ok_or_else(|| anyhow::anyhow!("Row {}: missing amount", row_index))?;
    let asset = get("asset")
        .or_else(|| record.get(2).map(|v| v.trim().to_string()))
        .unwrap_or_else(|| "XLM".to_string());
    let memo = get("memo").or_else(|| record.get(3).map(|v| v.trim().to_string()));

    Ok(BatchRecipientRow {
        row_index,
        destination,
        amount,
        asset,
        memo,
    })
}

pub fn validate_recipient_rows(rows: &[BatchRecipientRow]) -> Result<()> {
    for row in rows {
        validate_destination_checksum(&row.destination)
            .with_context(|| format!("Row {}: invalid destination address", row.row_index))?;
        config::validate_amount(&row.amount)
            .with_context(|| format!("Row {}: invalid amount", row.row_index))?;
        validate_batch_asset(&row.asset)
            .with_context(|| format!("Row {}: invalid asset", row.row_index))?;
    }
    Ok(())
}

pub fn chunk_pending_row_indices(rows: &[BatchRowState]) -> Vec<Vec<usize>> {
    let pending: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.is_payable())
        .map(|(idx, _)| idx)
        .collect();

    pending
        .chunks(MAX_OPS_PER_TRANSACTION)
        .map(|chunk| chunk.to_vec())
        .collect()
}

pub fn estimate_batch_cost(rows: &[BatchRowState]) -> BatchValidationReport {
    let payable = rows.iter().filter(|r| !r.is_terminal()).count();
    let tx_count = payable.div_ceil(MAX_OPS_PER_TRANSACTION);
    let mut totals: HashMap<String, f64> = HashMap::new();

    for row in rows {
        if row.is_terminal() {
            continue;
        }
        let amount = row.amount.parse::<f64>().unwrap_or(0.0);
        *totals.entry(row.asset.to_uppercase()).or_insert(0.0) += amount;
    }

    BatchValidationReport {
        row_count: rows.len(),
        total_payment_amounts: totals,
        estimated_fee_stroops: (payable as u64).saturating_mul(BASE_FEE_PER_OP_STROOPS),
        transaction_count: tx_count,
    }
}

pub fn load_checkpoint(path: &Path) -> Result<Option<BatchCheckpoint>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read checkpoint: {}", path.display()))?;
    let checkpoint: BatchCheckpoint = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid checkpoint JSON: {}", path.display()))?;
    Ok(Some(checkpoint))
}

pub fn init_checkpoint(
    csv_path: &Path,
    wallet: &WalletEntry,
    network: &str,
    rows: Vec<BatchRecipientRow>,
    starting_sequence: i64,
) -> Result<BatchCheckpoint> {
    let now = Utc::now().to_rfc3339();
    Ok(BatchCheckpoint {
        version: CHECKPOINT_VERSION,
        source_file: csv_path.display().to_string(),
        wallet: wallet.name.clone(),
        network: network.to_string(),
        payer_public_key: wallet.public_key.clone(),
        created_at: now.clone(),
        updated_at: now,
        next_sequence: starting_sequence,
        rows: rows
            .iter()
            .map(BatchRowState::from_recipient)
            .collect(),
    })
}

/// Atomic checkpoint write: temp file + rename (same pattern as config migrations).
pub fn save_checkpoint_atomic(path: &Path, checkpoint: &BatchCheckpoint) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create checkpoint dir {}", parent.display()))?;
        }
    }

    let tmp_path = path.with_extension("batch-state.json.tmp");
    let json = serde_json::to_string_pretty(checkpoint)
        .with_context(|| "Failed to serialize batch checkpoint")?;
    fs::write(&tmp_path, json)
        .with_context(|| format!("Failed to write checkpoint temp file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to atomically replace checkpoint {}",
            path.display()
        )
    })?;
    Ok(())
}

pub fn summarize_checkpoint(checkpoint: &BatchCheckpoint) -> BatchRunSummary {
    let mut summary = BatchRunSummary::default();
    for row in &checkpoint.rows {
        match row.status {
            RowStatus::Pending => summary.pending += 1,
            RowStatus::Submitted { .. } => summary.submitted += 1,
            RowStatus::Confirmed { .. } => summary.confirmed += 1,
            RowStatus::Failed { .. } => summary.failed += 1,
        }
    }
    summary
}

pub fn row_to_payment_op(row: &BatchRowState) -> Result<BatchPaymentOp> {
    let (asset_code, asset_issuer) = parse_asset(&row.asset)?;
    Ok(BatchPaymentOp {
        destination: row.destination.clone(),
        amount: row.amount.clone(),
        asset_code,
        asset_issuer,
    })
}

fn parse_asset(asset: &str) -> Result<(Option<String>, Option<String>)> {
    if asset.to_uppercase() == "XLM" {
        Ok((None, None))
    } else if asset.contains(':') {
        let parts: Vec<&str> = asset.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid asset format. Use CODE:ISSUER or XLM");
        }
        Ok((Some(parts[0].to_string()), Some(parts[1].to_string())))
    } else {
        anyhow::bail!("Invalid asset format. Use CODE:ISSUER or XLM")
    }
}

pub fn validate_payer_balances(
    checkpoint: &BatchCheckpoint,
    network: &str,
) -> Result<()> {
    let account = horizon::fetch_account(&checkpoint.payer_public_key, network)
        .with_context(|| "Failed to fetch payer account for balance validation")?;

    let report = estimate_batch_cost(&checkpoint.rows);
    for (asset, needed) in &report.total_payment_amounts {
        if asset == "XLM" {
            let available = account
                .balances
                .iter()
                .find(|b| b.asset_type == "native")
                .and_then(|b| b.balance.parse::<f64>().ok())
                .unwrap_or(0.0);
            let fee_xlm = report.estimated_fee_stroops as f64 / 10_000_000.0;
            if available < needed + fee_xlm {
                anyhow::bail!(
                    "Insufficient XLM balance: have {:.7}, need {:.7} + {:.7} fees",
                    available,
                    needed,
                    fee_xlm
                );
            }
        } else if asset.contains(':') {
            let parts: Vec<&str> = asset.split(':').collect();
            if parts.len() == 2 {
                let code = parts[0];
                let available = account
                    .balances
                    .iter()
                    .find(|b| b.asset_code.as_deref() == Some(code) && b.asset_type != "native")
                    .and_then(|b| b.balance.parse::<f64>().ok())
                    .unwrap_or(0.0);
                if available < *needed {
                    anyhow::bail!(
                        "Insufficient {} balance: have {:.7}, need {:.7}",
                        asset,
                        available,
                        needed
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn reconcile_submitted_rows(checkpoint: &mut BatchCheckpoint, network: &str) -> Result<()> {
    let submitted: Vec<(usize, String)> = checkpoint
        .rows
        .iter()
        .enumerate()
        .filter_map(|(idx, row)| match &row.status {
            RowStatus::Submitted { tx_hash } => Some((idx, tx_hash.clone())),
            _ => None,
        })
        .collect();

    for (idx, tx_hash) in submitted {
        if let Ok(record) = horizon::fetch_transaction_by_hash(&tx_hash, network) {
            if record.successful {
                checkpoint.rows[idx].status = RowStatus::Confirmed {
                    tx_hash: tx_hash.clone(),
                };
            } else {
                checkpoint.rows[idx].status = RowStatus::Pending;
            }
        }
    }
    Ok(())
}

pub fn execute_batch_chunk(
    checkpoint: &mut BatchCheckpoint,
    row_indices: &[usize],
    secret_key: &str,
    network: &str,
    max_retries: u32,
    fee_multiplier: f64,
) -> Result<String> {
    let ops: Vec<BatchPaymentOp> = row_indices
        .iter()
        .map(|&idx| row_to_payment_op(&checkpoint.rows[idx]))
        .collect::<Result<Vec<_>>>()?;

    let sequence = (checkpoint.next_sequence + 1).to_string();
    let tx_result = horizon::build_and_simulate_batch(
        &checkpoint.payer_public_key,
        &ops,
        &sequence,
        network,
    )?;

    for &idx in row_indices {
        checkpoint.rows[idx].status = RowStatus::Submitted {
            tx_hash: "pending".to_string(),
        };
    }

    let submit = horizon::submit_payment_with_retry(
        &tx_result.transaction_xdr,
        secret_key,
        network,
        max_retries,
        fee_multiplier,
        checkpoint.next_sequence + 1,
    )?;

    for &idx in row_indices {
        checkpoint.rows[idx].status = RowStatus::Confirmed {
            tx_hash: submit.hash.clone(),
        };
    }

    checkpoint.next_sequence += 1;
    checkpoint.updated_at = Utc::now().to_rfc3339();
    Ok(submit.hash)
}

pub fn mark_chunk_failed(
    checkpoint: &mut BatchCheckpoint,
    row_indices: &[usize],
    error: &str,
    attempts: u32,
) {
    for &idx in row_indices {
        checkpoint.rows[idx].status = RowStatus::Failed {
            error: error.to_string(),
            attempts,
        };
    }
    checkpoint.updated_at = Utc::now().to_rfc3339();
}

pub fn run_batch_pay(
    options: &BatchRunOptions,
    wallet: &WalletEntry,
    secret_key: Option<&str>,
) -> Result<(BatchCheckpoint, BatchRunSummary)> {
    let checkpoint_path = checkpoint_path_for(&options.csv_path);
    let mut checkpoint = if options.resume || checkpoint_path.exists() {
        load_checkpoint(&checkpoint_path)?
            .ok_or_else(|| anyhow::anyhow!("Expected checkpoint at {}", checkpoint_path.display()))?
    } else {
        let rows = parse_batch_csv(&options.csv_path)?;
        validate_recipient_rows(&rows)?;
        let sequence = horizon::fetch_account_sequence(&wallet.public_key, &options.network)?;
        init_checkpoint(
            &options.csv_path,
            wallet,
            &options.network,
            rows,
            sequence,
        )?
    };

    if checkpoint.wallet != wallet.name {
        anyhow::bail!(
            "Checkpoint wallet '{}' does not match requested wallet '{}'",
            checkpoint.wallet,
            wallet.name
        );
    }
    if checkpoint.network != options.network {
        anyhow::bail!(
            "Checkpoint network '{}' does not match requested network '{}'",
            checkpoint.network,
            options.network
        );
    }

    reconcile_submitted_rows(&mut checkpoint, &options.network)?;

    if options.dry_run {
        validate_payer_balances(&checkpoint, &options.network)?;
        let summary = summarize_checkpoint(&checkpoint);
        return Ok((checkpoint, summary));
    }

    let secret = secret_key.ok_or_else(|| anyhow::anyhow!("Secret key required for live batch pay"))?;

    validate_payer_balances(&checkpoint, &options.network)?;

    let chunks = chunk_pending_row_indices(&checkpoint.rows);
    for chunk in chunks {
        match execute_batch_chunk(
            &mut checkpoint,
            &chunk,
            secret,
            &options.network,
            options.max_retries,
            1.5,
        ) {
            Ok(_hash) => {
                save_checkpoint_atomic(&checkpoint_path, &checkpoint)?;
            }
            Err(error) => {
                mark_chunk_failed(&mut checkpoint, &chunk, &error.to_string(), options.max_retries);
                save_checkpoint_atomic(&checkpoint_path, &checkpoint)?;
            }
        }
    }

    let summary = summarize_checkpoint(&checkpoint);
    Ok((checkpoint, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_key(n: u8) -> String {
        format!(
            "G{:55}",
            match n {
                1 => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                _ => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHE",
            }
        )
    }

    fn test_wallet(name: &str, public_key: &str) -> WalletEntry {
        WalletEntry {
            name: name.to_string(),
            public_key: public_key.to_string(),
            secret_key: None,
            network: "testnet".to_string(),
            created_at: Utc::now().to_rfc3339(),
            funded: false,
            rotation_history: vec![],
        }
    }

    #[test]
    fn parses_payment_operations() {
        let json = r#"{
            "operations": [
                { "type": "payment", "to": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "amount": "10" }
            ]
        }"#;
        let doc: BatchOperationsFile = serde_json::from_str(json).unwrap();
        assert_eq!(doc.operations.len(), 1);
    }

    #[test]
    fn parses_csv_with_header_and_memo() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recipients.csv");
        fs::write(
            &path,
            "destination,amount,asset,memo\n\
             GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF,10,XLM,hello\n",
        )
        .unwrap();

        let rows = parse_batch_csv(&path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "10");
        assert_eq!(rows[0].memo.as_deref(), Some("hello"));
    }

    #[test]
    fn rejects_invalid_destination_checksum() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.csv");
        fs::write(
            &path,
            "destination,amount,asset\nGINVALIDKEYCHECKSUMFAILCHECKSUMFAILCHECKSUMFAILCH,1,XLM\n",
        )
        .unwrap();

        let rows = parse_batch_csv(&path).unwrap();
        assert!(validate_recipient_rows(&rows).is_err());
    }

    #[test]
    fn chunks_at_max_operations_boundary() {
        let rows: Vec<BatchRowState> = (0..101)
            .map(|i| BatchRowState {
                row_index: i + 1,
                destination: sample_key(1),
                amount: "1".to_string(),
                asset: "XLM".to_string(),
                memo: None,
                status: RowStatus::Pending,
            })
            .collect();

        let chunks = chunk_pending_row_indices(&rows);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 100);
        assert_eq!(chunks[1].len(), 1);
    }

    #[test]
    fn checkpoint_roundtrip_and_atomic_write() {
        let dir = TempDir::new().unwrap();
        let csv_path = dir.path().join("pay.csv");
        let checkpoint_path = checkpoint_path_for(&csv_path);

        let wallet = test_wallet("payer", &sample_key(1));

        let rows = vec![BatchRecipientRow {
            row_index: 1,
            destination: sample_key(1),
            amount: "5".to_string(),
            asset: "XLM".to_string(),
            memo: None,
        }];

        let checkpoint = init_checkpoint(&csv_path, &wallet, "testnet", rows, 100).unwrap();
        save_checkpoint_atomic(&checkpoint_path, &checkpoint).unwrap();

        let loaded = load_checkpoint(&checkpoint_path).unwrap().unwrap();
        assert_eq!(loaded.rows.len(), 1);
        assert_eq!(loaded.next_sequence, 100);
    }

    #[test]
    fn resume_skips_confirmed_rows() {
        let rows: Vec<BatchRowState> = vec![
            BatchRowState {
                row_index: 1,
                destination: sample_key(1),
                amount: "1".to_string(),
                asset: "XLM".to_string(),
                memo: None,
                status: RowStatus::Confirmed {
                    tx_hash: "abc".to_string(),
                },
            },
            BatchRowState {
                row_index: 2,
                destination: sample_key(1),
                amount: "2".to_string(),
                asset: "XLM".to_string(),
                memo: None,
                status: RowStatus::Pending,
            },
        ];

        let chunks = chunk_pending_row_indices(&rows);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], vec![1]);
    }

    #[test]
    fn simulated_crash_resume_restores_pending_only() {
        let dir = TempDir::new().unwrap();
        let csv_path = dir.path().join("airdrop.csv");
        fs::write(
            &csv_path,
            "destination,amount,asset\n\
             GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF,1,XLM\n\
             GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHE,2,XLM\n",
        )
        .unwrap();

        let wallet = test_wallet("payer", &sample_key(1));

        let parsed = parse_batch_csv(&csv_path).unwrap();
        let mut checkpoint = init_checkpoint(&csv_path, &wallet, "testnet", parsed, 10).unwrap();
        checkpoint.rows[0].status = RowStatus::Confirmed {
            tx_hash: "tx1".to_string(),
        };
        checkpoint.next_sequence = 11;

        let checkpoint_path = checkpoint_path_for(&csv_path);
        save_checkpoint_atomic(&checkpoint_path, &checkpoint).unwrap();

        let resumed = load_checkpoint(&checkpoint_path).unwrap().unwrap();
        let chunks = chunk_pending_row_indices(&resumed.rows);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], vec![1]);
    }

    #[test]
    fn failed_rows_do_not_block_remaining_chunks() {
        let rows: Vec<BatchRowState> = (0..3)
            .map(|i| BatchRowState {
                row_index: i + 1,
                destination: sample_key(1),
                amount: "1".to_string(),
                asset: "XLM".to_string(),
                memo: None,
                status: if i == 0 {
                    RowStatus::Failed {
                        error: "insufficient fee".to_string(),
                        attempts: 3,
                    }
                } else {
                    RowStatus::Pending
                },
            })
            .collect();

        let chunks = chunk_pending_row_indices(&rows);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], vec![1, 2]);
    }

    #[test]
    fn dry_run_cost_estimate_accounts_for_all_pending_rows() {
        let rows: Vec<BatchRowState> = (0..250)
            .map(|i| BatchRowState {
                row_index: i + 1,
                destination: sample_key(1),
                amount: "1".to_string(),
                asset: "XLM".to_string(),
                memo: None,
                status: if i < 50 {
                    RowStatus::Confirmed {
                        tx_hash: format!("tx{i}"),
                    }
                } else {
                    RowStatus::Pending
                },
            })
            .collect();

        let report = estimate_batch_cost(&rows);
        assert_eq!(report.row_count, 250);
        assert_eq!(report.transaction_count, 2);
        assert_eq!(report.estimated_fee_stroops, 200 * BASE_FEE_PER_OP_STROOPS);
        assert_eq!(report.total_payment_amounts.get("XLM"), Some(&200.0));
    }

    #[test]
    fn mark_chunk_failed_records_attempts() {
        let dir = TempDir::new().unwrap();
        let csv_path = dir.path().join("fail.csv");
        let wallet = test_wallet("payer", &sample_key(1));
        let rows = vec![BatchRecipientRow {
            row_index: 1,
            destination: sample_key(1),
            amount: "1".to_string(),
            asset: "XLM".to_string(),
            memo: None,
        }];
        let mut checkpoint = init_checkpoint(&csv_path, &wallet, "testnet", rows, 1).unwrap();
        mark_chunk_failed(&mut checkpoint, &[0], "tx_insufficient_fee", 3);

        match &checkpoint.rows[0].status {
            RowStatus::Failed { attempts, error } => {
                assert_eq!(*attempts, 3);
                assert!(error.contains("insufficient_fee"));
            }
            other => panic!("expected failed status, got {other:?}"),
        }
    }
}
