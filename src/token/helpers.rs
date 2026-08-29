//! Extended token domain helpers: events, admin state, and validation.

use crate::token::domain::*;
use anyhow::{bail, Result};

/// Parsed token event from simulation output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenEvent {
    pub name: String,
    pub contract_id: String,
    pub topics: Vec<String>,
    pub data: Vec<String>,
}

/// Validate a contract ID before any RPC call.
pub fn validate_contract_id(id: &str) -> Result<()> {
    crate::utils::config::validate_contract_id(id)
}

/// Validate account strkey or wallet name reference.
pub fn validate_account_ref(value: &str) -> Result<()> {
    if value.starts_with('G') && value.len() == 56 {
        return crate::utils::config::validate_public_key(value);
    }
    crate::utils::config::validate_wallet_name(value)
}

/// Build a capability summary string for human output.
pub fn capability_summary(caps: &TokenCapabilities) -> String {
    let mut parts = Vec::new();
    if caps.is_sep41 {
        parts.push("SEP-41".into());
    }
    for ext in &caps.extensions {
        parts.push(format!("{ext:?}"));
    }
    if parts.is_empty() {
        "custom".into()
    } else {
        parts.join(", ")
    }
}

/// Parse mock event lines into structured events.
pub fn parse_events(contract_id: &str, raw_events: &[String]) -> Vec<TokenEvent> {
    raw_events
        .iter()
        .map(|line| TokenEvent {
            name: line.clone(),
            contract_id: contract_id.to_string(),
            topics: vec![],
            data: vec![],
        })
        .collect()
}

/// Ensure an operation is permitted given capabilities and admin policy.
pub fn ensure_operation_allowed(
    caps: &TokenCapabilities,
    kind: TokenOperationKind,
    skip_admin_check: bool,
) -> Result<()> {
    let function = kind.function_name();
    if !caps.supports(function) {
        bail!("token contract does not support '{function}'");
    }
    if kind.is_admin() && caps.requires_admin(function) && !skip_admin_check {
        bail!("'{function}' requires admin authority; pass --yes after verifying capability");
    }
    Ok(())
}

/// Map operation kind to arg type list for Soroban simulation.
pub fn default_arg_types(kind: TokenOperationKind) -> Vec<&'static str> {
    match kind {
        TokenOperationKind::Transfer => vec!["address", "address", "i128"],
        TokenOperationKind::TransferFrom => vec!["address", "address", "address", "i128"],
        TokenOperationKind::Approve => vec!["address", "address", "i128", "u32"],
        TokenOperationKind::Mint => vec!["address", "i128"],
        TokenOperationKind::Burn => vec!["address", "i128"],
        TokenOperationKind::Clawback => vec!["address", "address", "i128"],
        TokenOperationKind::SetAuthorized => vec!["address", "bool"],
        TokenOperationKind::SetAdmin => vec!["address"],
    }
}

/// Describe ledger expiration semantics for allowances.
pub fn expiration_guidance(current_ledger: u32, expiration: Option<u32>) -> String {
    match expiration {
        None => "no expiration ledger specified".into(),
        Some(exp) if exp <= current_ledger => format!(
            "allowance expired at ledger {exp} (current {current_ledger})"
        ),
        Some(exp) => format!(
            "allowance expires at ledger {exp} ({} ledgers remaining)",
            exp - current_ledger
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn ensure_operation_allowed_rejects_missing_function() {
        let caps = TokenCapabilities {
            schema_version: 1,
            contract_id: "C".into(),
            network: "testnet".into(),
            is_sep41: false,
            functions: BTreeSet::new(),
            extensions: BTreeSet::new(),
            admin_required: BTreeSet::new(),
            notes: vec![],
        };
        assert!(ensure_operation_allowed(&caps, TokenOperationKind::Transfer, false).is_err());
    }

    #[test]
    fn expiration_guidance_describes_remaining_ledgers() {
        let msg = expiration_guidance(100, Some(200));
        assert!(msg.contains("100 ledgers remaining"));
    }
}
