//! Human and JSON rendering for token operations.

use crate::token::domain::*;
use crate::utils::print as p;
use anyhow::Result;

pub fn render_inspect(report: &TokenInspectReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    p::header("Token Inspection");
    p::kv("Contract", &report.metadata.contract_id);
    p::kv("Network", &report.metadata.network);
    if let Some(name) = &report.metadata.name {
        p::kv("Name", name);
    }
    if let Some(symbol) = &report.metadata.symbol {
        p::kv("Symbol", symbol);
    }
    p::kv("Decimals", &report.metadata.decimals.to_string());
    p::kv("SEP-41", &report.metadata.capabilities.is_sep41.to_string());
    p::kv(
        "Functions",
        &report.metadata.capabilities.functions.len().to_string(),
    );
    for warning in &report.warnings {
        p::warn(&format!("[{}] {}", warning.code, warning.message));
    }
    Ok(())
}

pub fn render_balance(balance: &TokenBalance, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(balance)?);
        return Ok(());
    }
    p::header("Token Balance");
    p::kv("Account", &balance.account);
    p::kv("Amount", &balance.amount.display);
    p::kv("Raw", &balance.amount.raw.to_string());
    Ok(())
}

pub fn render_allowance(state: &AllowanceState, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(state)?);
        return Ok(());
    }
    p::header("Token Allowance");
    p::kv("Owner", &state.owner);
    p::kv("Spender", &state.spender);
    p::kv("Amount", &state.amount.display);
    if state.is_expired {
        p::warn("Allowance is expired");
    }
    Ok(())
}

pub fn render_receipt(receipt: &TokenReceipt, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(receipt)?);
        return Ok(());
    }
    p::header("Token Receipt");
    p::kv("Operation", &format!("{:?}", receipt.operation));
    p::kv("Status", &format!("{:?}", receipt.status));
    if let Some(fee) = receipt.fee_stroops {
        p::kv("Fee (stroops)", &fee.to_string());
    }
    if let Some(amount) = &receipt.amount {
        p::kv("Amount", &amount.display);
    }
    Ok(())
}

pub fn render_batch(report: &BatchExecutionReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    p::header("Batch Execution");
    p::kv("Succeeded", &report.succeeded.to_string());
    p::kv("Failed", &report.failed.to_string());
    p::kv("Skipped", &report.skipped.to_string());
    Ok(())
}

pub fn render_confirmation(summary: &ConfirmationSummary, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(summary)?);
        return Ok(());
    }
    p::header("Confirmation Summary");
    p::kv("Operation", &format!("{:?}", summary.operation));
    p::kv("Contract", &summary.contract_id);
    if let Some(to) = &summary.to {
        p::kv("To", to);
    }
    if let Some(amount) = &summary.amount {
        p::kv("Amount", &amount.display);
    }
    Ok(())
}
