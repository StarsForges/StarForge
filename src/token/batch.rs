//! Batch token operation manifests.

use crate::token::domain::*;
use crate::token::read::TokenReader;
use crate::token::transport::TokenRpcTransport;
use crate::token::write::TokenWriter;
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::Path;

pub fn load_manifest(path: &Path) -> Result<BatchManifest> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read batch manifest {}", path.display()))?;
    let manifest: BatchManifest =
        serde_json::from_str(&contents).context("invalid batch manifest JSON")?;
    if manifest.schema_version > TOKEN_BATCH_SCHEMA_VERSION {
        anyhow::bail!(
            "batch manifest schema {} is newer than supported {}",
            manifest.schema_version,
            TOKEN_BATCH_SCHEMA_VERSION
        );
    }
    Ok(manifest)
}

pub struct BatchExecutor<'a, T: TokenRpcTransport> {
    reader: TokenReader<'a, T>,
    writer: TokenWriter<'a, T>,
}

impl<'a, T: TokenRpcTransport> BatchExecutor<'a, T> {
    pub fn new(transport: &'a T) -> Self {
        Self {
            reader: TokenReader::new(transport),
            writer: TokenWriter::new(transport),
        }
    }

    pub fn save_manifest(path: &Path, manifest: &BatchManifest) -> Result<()> {
        let json = serde_json::to_string_pretty(manifest)?;
        crate::signer_rotation::write_private_text_atomic(path, &json)?;
        Ok(())
    }

    pub fn execute(
        &self,
        manifest: &BatchManifest,
        simulate_only: bool,
    ) -> Result<BatchExecutionReport> {
        let options = ReadOptions {
            network: manifest.network.clone(),
            contract_id: manifest
                .entries
                .first()
                .map(|e| e.contract_id.clone())
                .unwrap_or_default(),
            timeout_ms: 5_000,
        };
        let inspect = self.reader.inspect(&options)?;
        let decimals = inspect.metadata.decimals;
        let capabilities = inspect.metadata.capabilities;

        let mut receipts = Vec::new();
        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;

        for entry in &manifest.entries {
            let write_opts = WriteOptions {
                network: manifest.network.clone(),
                contract_id: entry.contract_id.clone(),
                source_wallet: entry.source_account.clone(),
                simulate_only,
                yes: true,
                expiration_ledger: entry.expiration_ledger,
                ..Default::default()
            };
            let plan_result = self.plan_entry(entry, &write_opts, &capabilities, decimals);
            match plan_result {
                Ok(plan) => match self.writer.execute_simulate_only(&plan, decimals) {
                    Ok(receipt) => {
                        succeeded += 1;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        failed += 1;
                        receipts.push(TokenReceipt {
                            schema_version: TOKEN_RECEIPT_SCHEMA_VERSION,
                            operation: entry.operation,
                            contract_id: entry.contract_id.clone(),
                            network: manifest.network.clone(),
                            source_account: entry.source_account.clone(),
                            tx_hash: None,
                            ledger: None,
                            fee_stroops: None,
                            amount: entry
                                .amount_raw
                                .map(|raw| TokenAmount::from_raw(raw, decimals)),
                            status: TokenReceiptStatus::Failed,
                            simulation: None,
                            completed_at: Utc::now(),
                            redacted: false,
                        });
                        let _ = e;
                    }
                },
                Err(_) => {
                    skipped += 1;
                    receipts.push(TokenReceipt {
                        schema_version: TOKEN_RECEIPT_SCHEMA_VERSION,
                        operation: entry.operation,
                        contract_id: entry.contract_id.clone(),
                        network: manifest.network.clone(),
                        source_account: entry.source_account.clone(),
                        tx_hash: None,
                        ledger: None,
                        fee_stroops: None,
                        amount: None,
                        status: TokenReceiptStatus::Skipped,
                        simulation: None,
                        completed_at: Utc::now(),
                        redacted: false,
                    });
                }
            }
        }

        Ok(BatchExecutionReport {
            schema_version: TOKEN_BATCH_SCHEMA_VERSION,
            manifest: manifest.clone(),
            receipts,
            succeeded,
            failed,
            skipped,
            completed_at: Utc::now(),
        })
    }

    fn plan_entry(
        &self,
        entry: &BatchManifestEntry,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        decimals: u8,
    ) -> Result<TokenOperationPlan> {
        let amount_str = entry
            .amount_raw
            .map(|raw| crate::token::amount::format_amount(raw, decimals))
            .unwrap_or_else(|| "0".into());
        match entry.operation {
            TokenOperationKind::Transfer => {
                let to = entry.args.get("to").context("batch entry missing to")?;
                self.writer
                    .plan_transfer(options, capabilities, to, &amount_str, decimals)
            }
            TokenOperationKind::Approve => {
                let spender = entry
                    .args
                    .get("spender")
                    .context("batch entry missing spender")?;
                self.writer
                    .plan_approve(options, capabilities, spender, &amount_str, decimals)
            }
            TokenOperationKind::Mint => {
                let to = entry.args.get("to").context("batch entry missing to")?;
                self.writer
                    .plan_mint(options, capabilities, to, &amount_str, decimals)
            }
            TokenOperationKind::Burn => {
                self.writer
                    .plan_burn(options, capabilities, &amount_str, decimals)
            }
            _ => anyhow::bail!("batch operation {:?} not supported", entry.operation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::spec::builtin_test_token_spec;
    use crate::token::transport::MockTokenTransport;

    #[test]
    fn batch_partial_failure_is_reported() {
        let transport = MockTokenTransport::from_fixture_spec(builtin_test_token_spec());
        let executor = BatchExecutor::new(&transport);
        let manifest = BatchManifest {
            schema_version: 1,
            network: "testnet".into(),
            decimals: 7,
            created_at: Utc::now(),
            entries: vec![
                BatchManifestEntry {
                    id: "ok".into(),
                    operation: TokenOperationKind::Transfer,
                    contract_id: "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A".into(),
                    source_account: "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T"
                        .into(),
                    args: [(
                        "to".into(),
                        "GBBO4ZDDZTSM2IUKQYBAST3CFHNPFXECGEFTGWTA3WUYC3IDATK4YALU".into(),
                    )]
                    .into_iter()
                    .collect(),
                    amount_raw: Some(1_000_000),
                    expiration_ledger: None,
                },
                BatchManifestEntry {
                    id: "bad".into(),
                    operation: TokenOperationKind::TransferFrom,
                    contract_id: "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A".into(),
                    source_account: "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T"
                        .into(),
                    args: [
                        (
                            "spender".into(),
                            "GBBO4ZDDZTSM2IUKQYBAST3CFHNPFXECGEFTGWTA3WUYC3IDATK4YALU".into(),
                        ),
                        (
                            "from".into(),
                            "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T".into(),
                        ),
                        (
                            "to".into(),
                            "GBBO4ZDDZTSM2IUKQYBAST3CFHNPFXECGEFTGWTA3WUYC3IDATK4YALU".into(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    amount_raw: Some(1),
                    expiration_ledger: None,
                },
            ],
        };
        let report = executor.execute(&manifest, true).unwrap();
        assert!(report.succeeded >= 1);
        assert!(report.skipped + report.failed >= 1);
    }
}
