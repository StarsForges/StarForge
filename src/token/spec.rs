//! Capability detection from Soroban contract specifications.

use crate::token::domain::*;
use anyhow::Result;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
struct ContractSpec {
    #[serde(default)]
    functions: Vec<SpecFunction>,
}

#[derive(Debug, Deserialize)]
struct SpecFunction {
    name: String,
}

/// Detect token capabilities from a JSON contract specification.
pub fn detect_from_spec_json(contract_id: &str, network: &str, spec_json: &str) -> Result<TokenCapabilities> {
    let spec: ContractSpec = serde_json::from_str(spec_json)?;
    Ok(detect_from_functions(
        contract_id,
        network,
        spec.functions.iter().map(|f| f.name.as_str()),
    ))
}

pub fn detect_from_functions<'a>(
    contract_id: &str,
    network: &str,
    functions: impl IntoIterator<Item = &'a str>,
) -> TokenCapabilities {
    let mut fn_set = BTreeSet::new();
    for name in functions {
        fn_set.insert(name.to_string());
    }

    let mut extensions = BTreeSet::new();
    let mut admin_required = BTreeSet::new();
    let mut notes = Vec::new();

    if fn_set.contains("allowance") || fn_set.contains("approve") {
        extensions.insert(TokenExtension::Allowance);
    }
    if fn_set.contains("transfer_from") {
        extensions.insert(TokenExtension::TransferFrom);
    }
    if fn_set.contains("mint") {
        extensions.insert(TokenExtension::Mint);
        admin_required.insert("mint".into());
    }
    if fn_set.contains("burn") {
        extensions.insert(TokenExtension::Burn);
    }
    if fn_set.contains("clawback") {
        extensions.insert(TokenExtension::Clawback);
        admin_required.insert("clawback".into());
    }
    if fn_set.contains("set_admin") {
        extensions.insert(TokenExtension::Admin);
        admin_required.insert("set_admin".into());
    }
    if fn_set.contains("set_authorized") {
        extensions.insert(TokenExtension::Authorization);
        admin_required.insert("set_authorized".into());
    }

    let is_sep41 = SEP41_FUNCTIONS
        .iter()
        .filter(|f| fn_set.contains(**f))
        .count()
        >= 4;

    if !is_sep41 {
        notes.push("contract does not expose a full SEP-41 surface".into());
    }

    TokenCapabilities {
        schema_version: TOKEN_SCHEMA_VERSION,
        contract_id: contract_id.to_string(),
        network: network.to_string(),
        is_sep41,
        functions: fn_set,
        extensions,
        admin_required,
        notes,
    }
}

pub fn builtin_test_token_spec() -> &'static str {
    include_str!("../../tests/fixtures/token/sep41_spec.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sep41_extensions() {
        let caps = detect_from_spec_json(
            "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A",
            "testnet",
            builtin_test_token_spec(),
        )
        .unwrap();
        assert!(caps.is_sep41);
        assert!(caps.supports("transfer"));
        assert!(caps.has_extension(&TokenExtension::Mint));
    }
}
