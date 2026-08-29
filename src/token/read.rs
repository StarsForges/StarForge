//! Token read operations: metadata, balance, allowance, supply, authorization.

use crate::token::domain::*;
use crate::token::spec::detect_from_spec_json;
use crate::token::transport::TokenRpcTransport;
use anyhow::{Context, Result};
use chrono::Utc;

pub struct TokenReader<'a, T: TokenRpcTransport> {
    transport: &'a T,
}

impl<'a, T: TokenRpcTransport> TokenReader<'a, T> {
    pub fn new(transport: &'a T) -> Self {
        Self { transport }
    }

    pub fn inspect(&self, options: &ReadOptions) -> Result<TokenInspectReport> {
        let spec = self
            .transport
            .get_contract_spec(&options.network, &options.contract_id)?;
        let capabilities = detect_from_spec_json(&options.contract_id, &options.network, &spec)?;
        let metadata = self.metadata(options, &capabilities)?;
        let supply = self.supply(options, &capabilities)?;
        let mut warnings = Vec::new();
        if !capabilities.is_sep41 {
            warnings.push(TokenWarning {
                code: "token.partial_sep41".into(),
                message: "Contract exposes a partial token interface".into(),
                severity: TokenWarningSeverity::Warning,
            });
        }
        Ok(TokenInspectReport {
            schema_version: TOKEN_SCHEMA_VERSION,
            metadata,
            supply,
            warnings,
        })
    }

    pub fn metadata(
        &self,
        options: &ReadOptions,
        capabilities: &TokenCapabilities,
    ) -> Result<TokenMetadata> {
        let name = self
            .optional_string_call(options, "name", &[])?
            .map(|s| trim_json_string(&s));
        let symbol = self
            .optional_string_call(options, "symbol", &[])?
            .map(|s| trim_json_string(&s));
        let decimals = self
            .required_u8_call(options, "decimals", &[])?
            .unwrap_or(7);
        let admin = if capabilities.supports("admin") || capabilities.supports("get_admin") {
            self.optional_string_call(options, "admin", &[])
                .ok()
                .flatten()
                .map(|s| trim_json_string(&s))
        } else {
            None
        };
        let total_supply = if capabilities.supports("total_supply") {
            self.raw_amount_call(options, "total_supply", &[], decimals)
                .ok()
        } else {
            None
        };
        Ok(TokenMetadata {
            schema_version: TOKEN_SCHEMA_VERSION,
            contract_id: options.contract_id.clone(),
            network: options.network.clone(),
            name,
            symbol,
            decimals,
            admin,
            total_supply,
            capabilities: capabilities.clone(),
            fetched_at: Utc::now(),
        })
    }

    pub fn balance(
        &self,
        options: &ReadOptions,
        account: &str,
        decimals: u8,
    ) -> Result<TokenBalance> {
        let resp = self.transport.simulate_contract_call(
            &options.network,
            &options.contract_id,
            "balance",
            &[account.into()],
            &["address".into()],
        )?;
        if !resp.errors.is_empty() {
            anyhow::bail!("balance call failed: {}", resp.errors.join("; "));
        }
        let raw = resp
            .return_raw
            .context("balance response missing numeric return value")?;
        Ok(TokenBalance {
            schema_version: TOKEN_SCHEMA_VERSION,
            contract_id: options.contract_id.clone(),
            network: options.network.clone(),
            account: account.to_string(),
            amount: TokenAmount::from_raw(raw, decimals),
            authorized: None,
            fetched_at: Utc::now(),
        })
    }

    pub fn allowance(
        &self,
        options: &ReadOptions,
        owner: &str,
        spender: &str,
        decimals: u8,
    ) -> Result<AllowanceState> {
        let resp = self.transport.simulate_contract_call(
            &options.network,
            &options.contract_id,
            "allowance",
            &[owner.into(), spender.into()],
            &["address".into(), "address".into()],
        )?;
        if !resp.errors.is_empty() {
            anyhow::bail!("allowance call failed: {}", resp.errors.join("; "));
        }
        let raw = resp.return_raw.unwrap_or(0);
        let latest = self.transport.latest_ledger(&options.network).unwrap_or(0);
        let expiration_ledger = None;
        let is_expired = false;
        Ok(AllowanceState {
            schema_version: TOKEN_SCHEMA_VERSION,
            contract_id: options.contract_id.clone(),
            network: options.network.clone(),
            owner: owner.to_string(),
            spender: spender.to_string(),
            amount: TokenAmount::from_raw(raw, decimals),
            expiration_ledger,
            live_until_ledger: Some(latest),
            is_expired,
            fetched_at: Utc::now(),
        })
    }

    pub fn authorization(
        &self,
        options: &ReadOptions,
        account: &str,
    ) -> Result<AuthorizationState> {
        let resp = self.transport.simulate_contract_call(
            &options.network,
            &options.contract_id,
            "authorized",
            &[account.into()],
            &["address".into()],
        );
        let authorized = match resp {
            Ok(r) => r.return_raw.unwrap_or(1) != 0,
            Err(_) => true,
        };
        Ok(AuthorizationState {
            schema_version: TOKEN_SCHEMA_VERSION,
            contract_id: options.contract_id.clone(),
            network: options.network.clone(),
            account: account.to_string(),
            authorized,
            fetched_at: Utc::now(),
        })
    }

    pub fn supply(
        &self,
        options: &ReadOptions,
        capabilities: &TokenCapabilities,
    ) -> Result<SupplyState> {
        let decimals = self
            .required_u8_call(options, "decimals", &[])?
            .unwrap_or(7);
        let total_supply = if capabilities.supports("total_supply") {
            self.raw_amount_call(options, "total_supply", &[], decimals)
                .ok()
        } else {
            None
        };
        Ok(SupplyState {
            schema_version: TOKEN_SCHEMA_VERSION,
            contract_id: options.contract_id.clone(),
            network: options.network.clone(),
            total_supply,
            admin: None,
            fetched_at: Utc::now(),
        })
    }

    fn optional_string_call(
        &self,
        options: &ReadOptions,
        function: &str,
        args: &[String],
    ) -> Result<Option<String>> {
        let resp = self.transport.simulate_contract_call(
            &options.network,
            &options.contract_id,
            function,
            args,
            &vec!["address".into(); args.len()],
        )?;
        Ok(resp.return_value)
    }

    fn required_u8_call(
        &self,
        options: &ReadOptions,
        function: &str,
        args: &[String],
    ) -> Result<Option<u8>> {
        let resp = self.transport.simulate_contract_call(
            &options.network,
            &options.contract_id,
            function,
            args,
            &vec!["address".into(); args.len()],
        )?;
        Ok(resp
            .return_raw
            .and_then(|v| u8::try_from(v).ok())
            .or_else(|| resp.return_value.as_ref().and_then(|v| v.parse().ok())))
    }

    fn raw_amount_call(
        &self,
        options: &ReadOptions,
        function: &str,
        args: &[String],
        decimals: u8,
    ) -> Result<TokenAmount> {
        let resp = self.transport.simulate_contract_call(
            &options.network,
            &options.contract_id,
            function,
            args,
            &vec!["address".into(); args.len()],
        )?;
        let raw = resp.return_raw.context("missing numeric return")?;
        Ok(TokenAmount::from_raw(raw, decimals))
    }
}

fn trim_json_string(value: &str) -> String {
    value.trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::spec::builtin_test_token_spec;
    use crate::token::transport::MockTokenTransport;

    fn reader(transport: &MockTokenTransport) -> TokenReader<'_, MockTokenTransport> {
        TokenReader::new(transport)
    }

    fn options() -> ReadOptions {
        ReadOptions {
            network: "testnet".into(),
            contract_id: "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A".into(),
            timeout_ms: 1000,
        }
    }

    #[test]
    fn reads_balance_from_mock() {
        let transport = MockTokenTransport::from_fixture_spec(builtin_test_token_spec());
        let balance = reader(&transport)
            .balance(
                &options(),
                "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T",
                7,
            )
            .unwrap();
        assert_eq!(balance.amount.raw, 1_500_000_000);
    }
}
