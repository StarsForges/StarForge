//! Stable JSON receipt serialization and redaction.

use crate::token::domain::TokenReceipt;
use crate::utils::logging::{redact_public_key, redact_secret_value};
use tracing::Level;

pub fn redact_receipt(receipt: &mut TokenReceipt) {
    receipt.source_account = redact_public_key(&receipt.source_account, Level::INFO);
    receipt.redacted = true;
    if let Some(sim) = &mut receipt.simulation {
        sim.plan.source_account = redact_public_key(&sim.plan.source_account, Level::INFO);
        for (_k, v) in sim.plan.args.iter_mut() {
            if v.starts_with('G') && v.len() == 56 {
                *v = redact_public_key(v, Level::INFO);
            } else if v.starts_with('S') && v.len() == 56 {
                *v = redact_secret_value(v).to_string();
            }
        }
    }
}

pub fn receipt_to_json(receipt: &TokenReceipt) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(receipt)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::domain::*;
    use chrono::Utc;

    #[test]
    fn redacts_public_keys_in_receipt() {
        let mut receipt = TokenReceipt {
            schema_version: 1,
            operation: TokenOperationKind::Transfer,
            contract_id: "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A".into(),
            network: "testnet".into(),
            source_account: "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T".into(),
            tx_hash: None,
            ledger: None,
            fee_stroops: None,
            amount: None,
            status: TokenReceiptStatus::Simulated,
            simulation: None,
            completed_at: Utc::now(),
            redacted: false,
        };
        redact_receipt(&mut receipt);
        assert!(receipt.redacted);
        assert!(receipt.source_account.contains("..."));
    }
}
