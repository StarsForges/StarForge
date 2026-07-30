use anyhow::Result;
use clap::{Args, Subcommand};
use colored::*;

use crate::utils::confirmation;
use crate::utils::config;
use crate::utils::crypto;
use crate::utils::print as p;
use crate::utils::tx_batch::{
    self, checkpoint_path_for, estimate_batch_cost, load_checkpoint, parse_batch_csv,
    summarize_checkpoint, validate_recipient_rows, BatchRunOptions, DEFAULT_MAX_RETRIES,
};

#[derive(Args)]
pub struct BatchArgs {
    #[command(subcommand)]
    pub command: BatchCommands,
}

#[derive(Subcommand)]
pub enum BatchCommands {
    /// Pay recipients from a CSV file with checkpointing and resume support
    Pay(PayArgs),
    /// Show batch payout progress from the checkpoint file
    Status(StatusArgs),
    /// Explicitly resume an interrupted batch payout
    Resume(ResumeArgs),
}

#[derive(Args)]
pub struct PayArgs {
    /// Path to recipients CSV (destination,amount,asset[,memo])
    #[arg(long)]
    pub file: std::path::PathBuf,
    /// Wallet name to send from
    #[arg(long)]
    pub wallet: String,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Validate and report total cost without submitting transactions
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
    /// Maximum submission retries per transaction chunk (fee-bump / sequence retry)
    #[arg(long, default_value_t = DEFAULT_MAX_RETRIES)]
    pub max_retries: u32,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Path to the recipients CSV used for the batch run
    #[arg(long)]
    pub file: std::path::PathBuf,
}

#[derive(Args)]
pub struct ResumeArgs {
    /// Path to recipients CSV (must match the original batch run)
    #[arg(long)]
    pub file: std::path::PathBuf,
    /// Wallet name to send from
    #[arg(long)]
    pub wallet: String,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
    /// Maximum submission retries per transaction chunk
    #[arg(long, default_value_t = DEFAULT_MAX_RETRIES)]
    pub max_retries: u32,
}

pub fn handle(args: BatchArgs) -> Result<()> {
    match args.command {
        BatchCommands::Pay(pay_args) => handle_pay(pay_args, false),
        BatchCommands::Status(status_args) => handle_status(status_args),
        BatchCommands::Resume(resume_args) => handle_resume(resume_args),
    }
}

fn handle_status(args: StatusArgs) -> Result<()> {
    p::header("Batch Payout Status");

    let checkpoint_path = checkpoint_path_for(&args.file);
    let checkpoint = load_checkpoint(&checkpoint_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No checkpoint found at {}. Run `starforge batch pay --file {}` first.",
            checkpoint_path.display(),
            args.file.display()
        )
    })?;

    print_status_report(&checkpoint);
    Ok(())
}

fn handle_resume(args: ResumeArgs) -> Result<()> {
    handle_pay(
        PayArgs {
            file: args.file,
            wallet: args.wallet,
            network: args.network,
            dry_run: false,
            yes: args.yes,
            max_retries: args.max_retries,
        },
        true,
    )
}

fn handle_pay(args: PayArgs, force_resume: bool) -> Result<()> {
    p::header(if args.dry_run {
        "Batch Payout Dry Run"
    } else if force_resume {
        "Resume Batch Payout"
    } else {
        "Batch Payout"
    });

    config::validate_wallet_name(&args.wallet)?;
    config::validate_network(&args.network)?;

    let checkpoint_path = checkpoint_path_for(&args.file);
    let has_checkpoint = checkpoint_path.exists();

    if !has_checkpoint && !force_resume {
        let rows = parse_batch_csv(&args.file)?;
        validate_recipient_rows(&rows)?;
        p::kv("Recipients", &rows.len().to_string());
    } else if force_resume && !has_checkpoint {
        anyhow::bail!(
            "No checkpoint found at {}. Nothing to resume.",
            checkpoint_path.display()
        );
    }

    let (wallet, secret_key) = load_wallet_secret(&args.wallet)?;

    p::separator();
    p::kv("Wallet", &wallet.name);
    p::kv("Payer", &wallet.public_key);
    p::kv("CSV File", &args.file.display().to_string());
    p::kv("Network", &args.network);
    p::kv("Checkpoint", &checkpoint_path.display().to_string());

    if has_checkpoint && !force_resume {
        p::info("Existing checkpoint detected — resuming from last confirmed row.");
    }

    if args.network == "mainnet" && !args.dry_run {
        p::warn("You are submitting on MAINNET. This will cost real XLM.");
    }

    let options = BatchRunOptions {
        csv_path: args.file.clone(),
        wallet_name: args.wallet.clone(),
        network: args.network.clone(),
        dry_run: args.dry_run,
        max_retries: args.max_retries,
        resume: has_checkpoint || force_resume,
    };

    if args.dry_run {
        let (checkpoint, _summary) =
            tx_batch::run_batch_pay(&options, &wallet, None)?;
        let report = estimate_batch_cost(&checkpoint.rows);
        print_cost_report(&report);
        let summary = summarize_checkpoint(&checkpoint);
        print_status_report(&checkpoint);
        p::info("Dry run complete — no transactions were submitted.");
        if summary.pending > 0 {
            p::kv("Pending Rows", &summary.pending.to_string());
        }
        return Ok(());
    }

    let report_preview = if has_checkpoint {
        load_checkpoint(&checkpoint_path)?
            .map(|cp| estimate_batch_cost(&cp.rows))
    } else {
        let rows = parse_batch_csv(&args.file)?;
        let row_states: Vec<_> = rows.iter().map(tx_batch::BatchRowState::from_recipient).collect();
        Some(estimate_batch_cost(&row_states))
    }
    .unwrap_or(tx_batch::BatchValidationReport {
        row_count: 0,
        total_payment_amounts: std::collections::HashMap::new(),
        estimated_fee_stroops: 0,
        transaction_count: 0,
    });

    print_cost_report(&report_preview);

    let risk_level = if args.network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };

    let summary = confirmation::OperationSummary::new(
        "Batch CSV Payout".to_string(),
        args.network.clone(),
        risk_level,
    )
    .add("Wallet", &wallet.name)
    .add("CSV File", args.file.display().to_string())
    .add("Transactions (est.)", report_preview.transaction_count.to_string())
    .add(
        "Estimated Fees",
        format!(
            "{:.7} XLM",
            report_preview.estimated_fee_stroops as f64 / 10_000_000.0
        ),
    );

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: args.network.clone(),
        skip_confirm: args.yes,
        dry_run: false,
        prompt: Some("Proceed with batch payout?".to_string()),
        require_type_confirmation: args.network == "mainnet",
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    println!();
    p::info("Executing batch payout…");

    let secret_ref = secret_key.as_str();
    let (_checkpoint, run_summary) = tx_batch::run_batch_pay(&options, &wallet, Some(secret_ref))?;

    println!();
    p::separator();
    println!(
        "  {} {}",
        "✓".green().bold(),
        "Batch payout pass complete.".bright_white()
    );
    p::kv("Confirmed", &run_summary.confirmed.to_string());
    p::kv("Failed", &run_summary.failed.to_string());
    p::kv("Pending", &run_summary.pending.to_string());
    p::kv("Checkpoint", &checkpoint_path.display().to_string());
    p::separator();

    if run_summary.pending > 0 || run_summary.failed > 0 {
        p::info("Re-run `starforge batch pay` or `starforge batch resume` to continue.");
    }

    Ok(())
}

fn load_wallet_secret(wallet_name: &str) -> Result<(config::WalletEntry, String)> {
    let cfg = config::load()?;
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == wallet_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Wallet '{}' not found. Run `starforge wallet list`",
                wallet_name
            )
        })?
        .clone();

    let Some(stored_secret) = wallet.secret_key.clone() else {
        anyhow::bail!("Wallet '{}' has no secret key stored", wallet_name);
    };

    let mut secret_key = stored_secret;
    if secret_key.contains(':') {
        let pwd = crypto::prompt_password(
            &format!("Enter password to decrypt wallet '{}'", wallet.name),
            false,
        )?;
        secret_key = crypto::decrypt_secret(&pwd, &secret_key)?;
    }

    Ok((wallet, secret_key))
}

fn print_cost_report(report: &tx_batch::BatchValidationReport) {
    p::separator();
    p::kv("Rows", &report.row_count.to_string());
    p::kv("Transactions (est.)", &report.transaction_count.to_string());
    p::kv(
        "Estimated Fees",
        &format!("{:.7} XLM", report.estimated_fee_stroops as f64 / 10_000_000.0),
    );

    for (asset, total) in &report.total_payment_amounts {
        p::kv(
            &format!("Total {asset}"),
            &format!("{total:.7}"),
        );
    }
    p::separator();
}

fn print_status_report(checkpoint: &tx_batch::BatchCheckpoint) {
    let summary = summarize_checkpoint(checkpoint);
    let report = estimate_batch_cost(&checkpoint.rows);

    p::separator();
    p::kv("Source File", &checkpoint.source_file);
    p::kv("Wallet", &checkpoint.wallet);
    p::kv("Network", &checkpoint.network);
    p::kv("Updated", &checkpoint.updated_at);
    p::kv("Confirmed", &summary.confirmed.to_string());
    p::kv("Failed", &summary.failed.to_string());
    p::kv("Pending", &summary.pending.to_string());
    p::kv("Submitted", &summary.submitted.to_string());
    p::kv(
        "Total Paid (pending estimate)",
        &format!(
            "{:.7} XLM (+ other assets)",
            report
                .total_payment_amounts
                .get("XLM")
                .copied()
                .unwrap_or(0.0)
        ),
    );
    p::separator();
}
