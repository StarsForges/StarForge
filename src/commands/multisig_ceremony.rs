//! `starforge multisig ceremony ...` — orchestrated M-of-N signing sessions
//! carried as a single portable file across independent (potentially
//! air-gapped) signer machines. See `crate::utils::ceremony` for the file
//! format and integrity model.

use crate::utils::hardware_wallet::HardwareWalletKind;
use crate::utils::tx_batch::BatchOperation;
use crate::utils::{ceremony, config, confirmation, crypto, horizon, print as p};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum MultisigCommands {
    /// Coordinate a multi-party (M-of-N) signing session as a portable file
    #[command(subcommand)]
    Ceremony(CeremonyCommands),
}

#[derive(Subcommand)]
pub enum CeremonyCommands {
    /// Start a ceremony: build the unsigned transaction + manifest into one file
    ///
    /// Example:
    /// starforge multisig ceremony start --source G... --op '{"type":"payment","to":"G...","amount":"100"}' \
    ///   --threshold 3 --signers G1,G2,G3,G4 --output tx.ceremony
    Start(StartArgs),
    /// Add this signer's signature to a ceremony file (no network access required)
    ///
    /// Example:
    /// starforge multisig ceremony sign --input tx.ceremony --wallet alice --output tx.ceremony
    Sign(SignArgs),
    /// Show collected vs. required signatures and time remaining before expiry
    Status(StatusArgs),
    /// Verify the threshold is met and submit the assembled transaction
    Submit(SubmitArgs),
}

#[derive(Args)]
pub struct StartArgs {
    /// Source account for the transaction (G...)
    #[arg(long)]
    pub source: String,
    /// Operation spec: inline JSON (e.g. '{"type":"payment","to":"G...","amount":"100"}')
    /// or a path to a JSON file containing the same object.
    #[arg(long)]
    pub op: String,
    /// Number of signatures required before the transaction can be submitted
    #[arg(long)]
    pub threshold: u8,
    /// Comma-separated list of required signer public keys (G1,G2,G3,...)
    #[arg(long)]
    pub signers: String,
    /// Network to build the transaction for
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet", "docker-testnet"])]
    pub network: String,
    /// Minutes until the transaction's time bounds expire (omit for no expiry)
    #[arg(long, default_value = "60")]
    pub expires_in_minutes: i64,
    /// Output path for the ceremony file
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct SignArgs {
    /// Path to the ceremony file
    #[arg(long)]
    pub input: PathBuf,
    /// Local wallet name to sign with
    #[arg(long)]
    pub wallet: String,
    /// Sign using a connected hardware wallet instead of the wallet's local secret key
    #[arg(long)]
    pub hardware: Option<HardwareWalletKind>,
    /// Output file (defaults to in-place update)
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Path to the ceremony file
    #[arg(long)]
    pub input: PathBuf,
}

#[derive(Args)]
pub struct SubmitArgs {
    /// Path to the ceremony file
    #[arg(long)]
    pub input: PathBuf,
    /// Network to submit on (defaults to the network recorded at ceremony start)
    #[arg(long, value_parser = ["testnet", "mainnet", "docker-testnet"])]
    pub network: Option<String>,
    /// Skip the confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
}

pub fn handle(cmd: MultisigCommands) -> Result<()> {
    match cmd {
        MultisigCommands::Ceremony(cmd) => match cmd {
            CeremonyCommands::Start(args) => start(args),
            CeremonyCommands::Sign(args) => sign(args),
            CeremonyCommands::Status(args) => status(args),
            CeremonyCommands::Submit(args) => submit(args),
        },
    }
}

fn parse_operation(op: &str) -> Result<BatchOperation> {
    let path = PathBuf::from(op);
    let raw = if path.exists() {
        std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read operation file {}", path.display()))?
    } else {
        op.to_string()
    };
    serde_json::from_str(&raw).with_context(|| {
        "Invalid --op. Expected JSON like {\"type\":\"payment\",\"to\":\"G...\",\"amount\":\"100\"} \
         or a path to a file containing it"
            .to_string()
    })
}

fn start(args: StartArgs) -> Result<()> {
    p::header("Multisig Ceremony — Start");

    config::validate_public_key(&args.source)?;
    config::validate_network(&args.network)?;

    let signers: Vec<String> = args
        .signers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if signers.is_empty() {
        anyhow::bail!("--signers must list at least one signer public key");
    }
    for signer in &signers {
        config::validate_public_key(signer)
            .with_context(|| format!("Invalid signer public key: {}", signer))?;
    }

    let operation = parse_operation(&args.op)?;
    crate::utils::tx_batch::validate_batch_operations(std::slice::from_ref(&operation))?;

    let expires_in_minutes = if args.expires_in_minutes > 0 {
        Some(args.expires_in_minutes)
    } else {
        None
    };

    p::step(1, 2, "Fetching source account sequence number…");
    let sequence = horizon::fetch_account_sequence(&args.source, &args.network)
        .map_err(|e| anyhow::anyhow!("Failed to fetch source account on {}: {}", args.network, e))?
        .to_string();

    p::step(2, 2, "Building unsigned transaction and manifest…");
    let file = ceremony::build_ceremony(
        &args.source,
        &operation,
        &sequence,
        args.threshold,
        signers,
        &args.network,
        expires_in_minutes,
    )?;

    ceremony::save_ceremony_file(&args.output, &file)?;

    println!();
    p::success("Ceremony started");
    p::kv("Source", &file.manifest.source_account);
    p::kv("Operation", &file.manifest.operation_summary);
    p::kv("Network", &file.manifest.network);
    p::kv(
        "Threshold",
        &format!(
            "{} of {}",
            file.manifest.threshold,
            file.manifest.required_signers.len()
        ),
    );
    for (i, signer) in file.manifest.required_signers.iter().enumerate() {
        p::kv(&format!("  Signer {}", i + 1), signer);
    }
    if let Some(expires_at) = &file.manifest.expires_at {
        p::kv("Expires At", expires_at);
    } else {
        p::kv("Expires At", "never");
    }
    p::kv("Manifest Hash", &file.manifest.manifest_hash);
    p::kv("Ceremony File", &args.output.display().to_string());

    println!();
    p::info("Copy this file to each signer (USB drive, QR export, shared repo/PR) and run:");
    println!(
        "  {}",
        format!(
            "starforge multisig ceremony sign --input {} --wallet <name>",
            args.output.display()
        )
        .cyan()
    );
    println!(
        "  {}",
        format!(
            "starforge multisig ceremony status --input {}",
            args.output.display()
        )
        .cyan()
    );

    Ok(())
}

fn resolve_local_secret(wallet_name: &str) -> Result<String> {
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
        })?;

    let secret = wallet
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' has no local secret key", wallet_name))?;

    if secret.contains(':') {
        let pwd = crypto::prompt_password(
            &format!("Enter password to decrypt wallet '{}'", wallet_name),
            false,
        )?;
        crypto::decrypt_secret(&pwd, secret)
            .map_err(|_| anyhow::anyhow!("Incorrect password or unable to decrypt."))
    } else {
        Ok(secret.clone())
    }
}

fn sign(args: SignArgs) -> Result<()> {
    p::header("Multisig Ceremony — Sign");
    config::validate_file_path(&args.input, None)?;

    let mut file = ceremony::load_ceremony_file(&args.input)?;
    p::kv("Wallet", &args.wallet);
    p::kv("Source", &file.manifest.source_account);
    p::kv("Operation", &file.manifest.operation_summary);

    let secret_key = if args.hardware.is_some() {
        if let Some(kind) = args.hardware {
            p::info(&format!("Requesting signature from connected {}…", kind));
        }
        None
    } else {
        Some(resolve_local_secret(&args.wallet)?)
    };

    let outcome = ceremony::add_signature(&mut file, secret_key.as_deref(), args.hardware)?;

    let output_path = args.output.unwrap_or_else(|| args.input.clone());
    ceremony::save_ceremony_file(&output_path, &file)?;

    println!();
    if outcome.already_signed {
        p::warn(&format!(
            "Signer '{}' had already signed this ceremony; no change made.",
            outcome.signer
        ));
    } else {
        p::success(&format!("Signature recorded for '{}'", outcome.signer));
    }

    let report = ceremony::status(&file)?;
    p::kv(
        "Signatures",
        &format!(
            "{} of {} required (threshold {})",
            report.collected, report.required_total, report.required_threshold
        ),
    );
    if !report.outstanding_signers.is_empty() {
        p::kv("Outstanding", &report.outstanding_signers.join(", "));
    }
    p::kv("Ceremony File", &output_path.display().to_string());

    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    p::header("Multisig Ceremony — Status");
    config::validate_file_path(&args.input, None)?;

    let file = ceremony::load_ceremony_file(&args.input)?;
    let report = ceremony::status(&file)?;

    p::kv("Source", &file.manifest.source_account);
    p::kv("Operation", &file.manifest.operation_summary);
    p::kv("Network", &file.manifest.network);
    p::separator();
    p::kv(
        "Signatures",
        &format!(
            "{} of {} required (threshold {})",
            report.collected, report.required_total, report.required_threshold
        ),
    );

    for signer in &file.manifest.required_signers {
        let signed = report.signed_signers.iter().any(|s| s == signer);
        let mark = if signed {
            "✓ signed".green().to_string()
        } else {
            "… waiting".yellow().to_string()
        };
        println!("    {}  {}", mark, signer.dimmed());
    }

    println!();
    if report.threshold_met {
        p::success("Threshold met — ready to submit");
    } else {
        p::warn(&format!(
            "Waiting on {} more signature(s)",
            report.required_threshold as usize - report.collected
        ));
    }

    match (&report.expires_at, report.seconds_remaining) {
        (Some(expires_at), Some(remaining)) if report.expired => {
            p::kv("Expired", &format!("at {}", expires_at));
            let _ = remaining;
        }
        (Some(expires_at), Some(remaining)) => {
            p::kv("Expires At", expires_at);
            p::kv("Time Remaining", &format_duration(remaining));
        }
        _ => {
            p::kv("Expires At", "never");
        }
    }

    Ok(())
}

fn format_duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    format!("{}h {}m {}s", hours, minutes, secs)
}

fn submit(args: SubmitArgs) -> Result<()> {
    p::header("Multisig Ceremony — Submit");
    config::validate_file_path(&args.input, None)?;

    let file = ceremony::load_ceremony_file(&args.input)?;
    let network = args
        .network
        .unwrap_or_else(|| file.manifest.network.clone());
    config::validate_network(&network)?;

    let report = ceremony::status(&file)?;
    p::kv("Source", &file.manifest.source_account);
    p::kv("Operation", &file.manifest.operation_summary);
    p::kv("Network", &network);
    p::kv(
        "Signatures",
        &format!(
            "{} of {} required (threshold {})",
            report.collected, report.required_total, report.required_threshold
        ),
    );

    let signed_xdr = ceremony::assemble_for_submit(&file)?;

    let risk_level = if network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };
    let summary = confirmation::OperationSummary::new(
        "Submit Multisig Ceremony Transaction".to_string(),
        network.clone(),
        risk_level,
    )
    .add("Source", &file.manifest.source_account)
    .add("Operation", &file.manifest.operation_summary)
    .add(
        "Signatures",
        format!("{} of {}", report.collected, report.required_total),
    );

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: network.clone(),
        skip_confirm: args.yes,
        dry_run: false,
        prompt: Some("Submit this ceremony transaction?".to_string()),
        require_type_confirmation: network == "mainnet",
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    p::info("Submitting signed envelope to Horizon…");
    let result = horizon::submit_multisig_transaction(&signed_xdr, &network)?;

    println!();
    p::success("Transaction submitted");
    p::kv_accent("Transaction Hash", &result.hash);

    let explorer_base = if network == "mainnet" {
        "https://stellar.expert/explorer/public/tx"
    } else {
        "https://stellar.expert/explorer/testnet/tx"
    };
    p::kv(
        "Stellar Expert",
        &format!("{}/{}", explorer_base, result.hash),
    );

    Ok(())
}
