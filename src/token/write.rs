//! Token write operation planning, simulation, and submission.

use crate::token::amount::parse_amount;
use crate::token::domain::*;
use crate::token::transport::TokenRpcTransport;
use crate::utils::config::{self, WalletEntry};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::collections::BTreeMap;

pub struct TokenWriter<'a, T: TokenRpcTransport> {
    transport: &'a T,
}

impl<'a, T: TokenRpcTransport> TokenWriter<'a, T> {
    pub fn new(transport: &'a T) -> Self {
        Self { transport }
    }

    pub fn plan_transfer(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        to: &str,
        amount: &str,
        decimals: u8,
    ) -> Result<TokenOperationPlan> {
        self.plan_write(
            options,
            capabilities,
            TokenOperationKind::Transfer,
            |args| {
                args.insert("to".into(), to.to_string());
                args.insert("amount".into(), amount.to_string());
            },
            Some(parse_amount(amount, decimals)?),
            false,
        )
    }

    pub fn plan_approve(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        spender: &str,
        amount: &str,
        decimals: u8,
    ) -> Result<TokenOperationPlan> {
        self.plan_write(
            options,
            capabilities,
            TokenOperationKind::Approve,
            |args| {
                args.insert("spender".into(), spender.to_string());
                args.insert("amount".into(), amount.to_string());
                if let Some(exp) = options.expiration_ledger {
                    args.insert("expiration_ledger".into(), exp.to_string());
                }
            },
            Some(parse_amount(amount, decimals)?),
            false,
        )
    }

    pub fn plan_mint(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        to: &str,
        amount: &str,
        decimals: u8,
    ) -> Result<TokenOperationPlan> {
        self.plan_write(
            options,
            capabilities,
            TokenOperationKind::Mint,
            |args| {
                args.insert("to".into(), to.to_string());
                args.insert("amount".into(), amount.to_string());
            },
            Some(parse_amount(amount, decimals)?),
            true,
        )
    }

    pub fn plan_burn(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        amount: &str,
        decimals: u8,
    ) -> Result<TokenOperationPlan> {
        self.plan_write(
            options,
            capabilities,
            TokenOperationKind::Burn,
            |args| {
                args.insert("amount".into(), amount.to_string());
            },
            Some(parse_amount(amount, decimals)?),
            true,
        )
    }

    pub fn plan_authorize(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        account: &str,
        authorized: bool,
    ) -> Result<TokenOperationPlan> {
        self.plan_write(
            options,
            capabilities,
            TokenOperationKind::SetAuthorized,
            |args| {
                args.insert("account".into(), account.to_string());
                args.insert("authorized".into(), authorized.to_string());
            },
            None,
            true,
        )
    }

    pub fn plan_admin(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        new_admin: &str,
    ) -> Result<TokenOperationPlan> {
        self.plan_write(
            options,
            capabilities,
            TokenOperationKind::SetAdmin,
            |args| {
                args.insert("new_admin".into(), new_admin.to_string());
            },
            None,
            true,
        )
    }

    fn plan_write<F>(
        &self,
        options: &WriteOptions,
        capabilities: &TokenCapabilities,
        kind: TokenOperationKind,
        fill_args: F,
        amount: Option<i128>,
        admin_op: bool,
    ) -> Result<TokenOperationPlan>
    where
        F: FnOnce(&mut BTreeMap<String, String>),
    {
        let function = kind.function_name();
        let supported = capabilities.supports(function);
        let admin_required = capabilities.requires_admin(function) || admin_op;
        let capability_check = CapabilityCheckResult {
            supported,
            admin_required,
            message: if !supported {
                format!("contract does not expose '{function}'")
            } else if admin_required {
                format!("'{function}' requires administrative privileges")
            } else {
                "operation supported".into()
            },
        };
        if !supported {
            bail!(capability_check.message);
        }

        let wallet = resolve_wallet(&options.source_wallet)?;
        let mut args = BTreeMap::new();
        args.insert("from".into(), wallet.public_key.clone());
        fill_args(&mut args);

        Ok(TokenOperationPlan {
            schema_version: TOKEN_SCHEMA_VERSION,
            kind,
            contract_id: options.contract_id.clone(),
            network: options.network.clone(),
            source_account: wallet.public_key,
            args,
            amount: amount.map(|raw| TokenAmount::from_raw(raw, 7)),
            expiration_ledger: options.expiration_ledger,
            requires_confirmation: admin_required || !options.yes,
            capability_check,
        })
    }

    pub fn simulate(
        &self,
        plan: &TokenOperationPlan,
        decimals: u8,
    ) -> Result<TokenSimulationSummary> {
        let (args, types) = plan_to_invoke_args(plan, decimals)?;
        let resp = self.transport.simulate_contract_call(
            &plan.network,
            &plan.contract_id,
            plan.kind.function_name(),
            &args,
            &types,
        )?;
        Ok(TokenSimulationSummary {
            schema_version: TOKEN_SCHEMA_VERSION,
            plan: plan.clone(),
            fee_stroops: resp.fee_stroops,
            return_value: resp.return_value,
            events: resp.events,
            errors: resp.errors,
            auth_required: resp.auth,
            simulated_at: Utc::now(),
        })
    }

    pub fn confirmation_summary(
        &self,
        plan: &TokenOperationPlan,
        simulation: Option<&TokenSimulationSummary>,
    ) -> ConfirmationSummary {
        let mut warnings = Vec::new();
        if plan.capability_check.admin_required {
            warnings.push("This operation requires token admin authority".into());
        }
        ConfirmationSummary {
            schema_version: TOKEN_SCHEMA_VERSION,
            operation: plan.kind,
            contract_id: plan.contract_id.clone(),
            network: plan.network.clone(),
            from: plan.source_account.clone(),
            to: plan.args.get("to").cloned(),
            amount: plan.amount.clone(),
            expiration_ledger: plan.expiration_ledger,
            fee_estimate_stroops: simulation.map(|s| s.fee_stroops),
            warnings,
        }
    }

    pub fn execute_simulate_only(
        &self,
        plan: &TokenOperationPlan,
        decimals: u8,
    ) -> Result<TokenReceipt> {
        let simulation = self.simulate(plan, decimals)?;
        if !simulation.errors.is_empty() {
            bail!("simulation failed: {}", simulation.errors.join("; "));
        }
        Ok(TokenReceipt {
            schema_version: TOKEN_RECEIPT_SCHEMA_VERSION,
            operation: plan.kind,
            contract_id: plan.contract_id.clone(),
            network: plan.network.clone(),
            source_account: plan.source_account.clone(),
            tx_hash: None,
            ledger: None,
            fee_stroops: Some(simulation.fee_stroops),
            amount: plan.amount.clone(),
            status: TokenReceiptStatus::Simulated,
            simulation: Some(simulation),
            completed_at: Utc::now(),
            redacted: false,
        })
    }
}

pub fn resolve_wallet(name_or_key: &str) -> Result<WalletEntry> {
    let cfg = config::load()?;
    if let Some(wallet) = cfg
        .wallets
        .iter()
        .find(|w| w.name.eq_ignore_ascii_case(name_or_key))
    {
        return Ok(wallet.clone());
    }
    if name_or_key.starts_with('G') && name_or_key.len() == 56 {
        return Ok(WalletEntry {
            name: "external".into(),
            public_key: name_or_key.to_string(),
            secret_key: None,
            network: cfg.network.clone(),
            created_at: Utc::now().to_rfc3339(),
            funded: false,
            rotation_history: vec![],
        });
    }
    bail!("wallet '{name_or_key}' not found; create it with starforge wallet create")
}

pub fn check_signer(wallet_name: &str) -> Result<SignerCheckResult> {
    let wallet = resolve_wallet(wallet_name)?;
    Ok(SignerCheckResult {
        valid: wallet.secret_key.is_some(),
        wallet_name: if wallet.name == "external" {
            None
        } else {
            Some(wallet.name.clone())
        },
        public_key: wallet.public_key,
        network: wallet.network,
        message: if wallet.secret_key.is_some() {
            "signer available locally".into()
        } else {
            "no local secret key; submission requires external signing".into()
        },
    })
}

fn plan_to_invoke_args(
    plan: &TokenOperationPlan,
    decimals: u8,
) -> Result<(Vec<String>, Vec<String>)> {
    match plan.kind {
        TokenOperationKind::Transfer => {
            let to = plan.args.get("to").context("missing to")?;
            let amount = plan
                .amount
                .as_ref()
                .map(|a| a.raw.to_string())
                .context("missing amount")?;
            Ok((
                vec![plan.source_account.clone(), to.clone(), amount],
                vec!["address".into(), "address".into(), "i128".into()],
            ))
        }
        TokenOperationKind::Approve => {
            let spender = plan.args.get("spender").context("missing spender")?;
            let amount = plan
                .amount
                .as_ref()
                .map(|a| a.raw.to_string())
                .context("missing amount")?;
            Ok((
                vec![
                    plan.source_account.clone(),
                    spender.clone(),
                    amount,
                    plan.expiration_ledger.unwrap_or(0).to_string(),
                ],
                vec![
                    "address".into(),
                    "address".into(),
                    "i128".into(),
                    "u32".into(),
                ],
            ))
        }
        TokenOperationKind::Mint => {
            let to = plan.args.get("to").context("missing to")?;
            let amount = plan
                .amount
                .as_ref()
                .map(|a| a.raw.to_string())
                .context("missing amount")?;
            Ok((
                vec![to.clone(), amount],
                vec!["address".into(), "i128".into()],
            ))
        }
        TokenOperationKind::Burn => {
            let amount = plan
                .amount
                .as_ref()
                .map(|a| a.raw.to_string())
                .context("missing amount")?;
            Ok((
                vec![plan.source_account.clone(), amount],
                vec!["address".into(), "i128".into()],
            ))
        }
        TokenOperationKind::SetAuthorized => {
            let account = plan.args.get("account").context("missing account")?;
            let authorized = plan.args.get("authorized").context("missing authorized")?;
            Ok((
                vec![account.clone(), authorized.clone()],
                vec!["address".into(), "bool".into()],
            ))
        }
        TokenOperationKind::SetAdmin => {
            let new_admin = plan.args.get("new_admin").context("missing new_admin")?;
            Ok((vec![new_admin.clone()], vec!["address".into()]))
        }
        TokenOperationKind::TransferFrom | TokenOperationKind::Clawback => {
            let _ = decimals;
            bail!("operation not yet exposed via CLI planner")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::spec::detect_from_spec_json;

    #[test]
    fn rejects_unsupported_operation() {
        let caps = detect_from_spec_json("C", "testnet", r#"{"functions":[{"name":"transfer"}]}"#)
            .unwrap();
        let options = WriteOptions {
            contract_id: "C".into(),
            source_wallet: "alice".into(),
            ..Default::default()
        };
        let transport = crate::token::transport::MockTokenTransport::from_fixture_spec("{}");
        let writer = TokenWriter::new(&transport);
        assert!(writer.plan_mint(&options, &caps, "G", "1", 7).is_err());
    }
}
