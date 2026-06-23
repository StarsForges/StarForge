use anyhow::Result;
use clap::{Args, Subcommand};
use colored::*;

use crate::utils::confirmation;
use crate::utils::horizon::FeeStats;
use crate::utils::{config, crypto, horizon, print as p, tx_batch}; // Import FeeStats

#[derive(Args)]
pub struct TxArgs {
    #[command(subcommand)]
    pub command: TxCommands,
}

#[derive(Subcommand)]
pub enum TxCommands {
    /// Send a Stellar payment transaction
    Send(SendArgs),
    /// Submit multiple operations in one transaction from a JSON file
    Batch(BatchArgs),
    /// Fetch and display recent transactions for a Stellar account
    History(HistoryArgs),
    /// Show recommended fee levels based on Horizon fee stats
    Fees {
        /// Optional network (testnet/mainnet)
        #[arg(short, long)]
        network: Option<String>,
    },
}

#[derive(Args)]
pub struct BatchArgs {
    /// Path to operations JSON file
    #[arg(long)]
    pub file: std::path::PathBuf,
    /// Wallet name to send from
    #[arg(long)]
    pub from: String,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
}

#[derive(Args)]
pub struct SendArgs {
    /// Wallet name to send from
    #[arg(long)]
    pub from: String,
    /// Destination public key
    #[arg(long)]
    pub to: String,
    /// Amount to send
    #[arg(long)]
    pub amount: String,
    /// Asset to send (XLM or CODE:ISSUER format)
    #[arg(long, default_value = "XLM")]
    pub asset: String,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
}

#[derive(Args)]
pub struct HistoryArgs {
    /// Public key to fetch history for
    pub public_key: String,
    /// Limit number of transactions
    #[arg(long, default_value = "10")]
    pub limit: u8,
    /// Optional network (testnet/mainnet)
    #[arg(long)]
    pub network_override: Option<String>,
    /// Cursor for pagination
    #[arg(long)]
    pub cursor: Option<String>,
    /// Get transactions after cursor
    #[arg(long)]
    pub after: Option<String>,
    /// Get transactions before cursor
    #[arg(long)]
    pub before: Option<String>,
    /// Only successful transactions
    #[arg(long)]
    pub successful_only: bool,
    /// Include details
    #[arg(long)]
    pub details: bool,
}

pub fn handle(args: TxArgs) -> Result<()> {
    match args.command {
        TxCommands::Fees { network } => handle_fees(network),
        TxCommands::Send(args) => handle_send(args),
        TxCommands::Batch(args) => handle_batch(args),
        TxCommands::History(args) => handle_history(args),
    }
}

fn handle_batch(args: BatchArgs) -> Result<()> {
    p::header("Batch Stellar Transaction");

    config::validate_wallet_name(&args.from)?;
    config::validate_network(&args.network)?;

    let doc = tx_batch::load_batch_file(&args.file)?;
    tx_batch::validate_batch_operations(&doc.operations)?;

    let cfg = config::load()?;
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == args.from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Wallet '{}' not found. Run `starforge wallet list`",
                args.from
            )
        })?;

    if wallet.secret_key.is_none() {
        anyhow::bail!("Wallet '{}' has no secret key stored", args.from);
    }

    let payment_ops: Vec<horizon::BatchPaymentOp> = doc
        .operations
        .iter()
        .map(batch_operation_to_payment)
        .collect::<Result<Vec<_>>>()?;

    p::separator();
    p::kv("From Wallet", &wallet.name);
    p::kv("From Address", &wallet.public_key);
    p::kv("Operations", &doc.operations.len().to_string());
    p::kv("Batch File", &args.file.display().to_string());
    p::kv("Network", &args.network);

    if args.network == "mainnet" {
        p::warn("You are submitting on MAINNET. This will cost real XLM.");
    }

    for (i, op) in payment_ops.iter().enumerate() {
        let asset_label = match (&op.asset_code, &op.asset_issuer) {
            (None, None) => "XLM".to_string(),
            (Some(code), Some(issuer)) => format!("{}:{}", code, issuer),
            _ => "unknown".to_string(),
        };
        p::kv(
            &format!("Op {}", i + 1),
            &format!("payment → {} {} {}", op.destination, op.amount, asset_label),
        );
    }

    p::separator();

    println!();
    p::step(1, 2, "Fetching source account info…");
    let source_account =
        horizon::fetch_account(&wallet.public_key, &args.network).map_err(|e| {
            anyhow::anyhow!(
                "Source account not found on {}: {}\nFund it with: starforge wallet fund {}",
                args.network,
                e,
                wallet.name
            )
        })?;

    p::step(2, 2, "Building batch transaction…");
    let tx_result = horizon::build_and_simulate_batch(
        &wallet.public_key,
        &payment_ops,
        &source_account.sequence,
        &args.network,
    )?;

    p::kv(
        "Estimated Fee",
        &format!("{:.7} XLM", tx_result.fee as f64 / 10_000_000.0),
    );
    p::kv(
        "Transaction XDR",
        &format!(
            "{}...",
            &tx_result.transaction_xdr[..tx_result.transaction_xdr.len().min(20)]
        ),
    );

    // Build operation summary for confirmation
    let risk_level = if args.network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };

    let mut summary = confirmation::OperationSummary::new(
        "Batch Stellar Transaction".to_string(),
        args.network.clone(),
        risk_level,
    )
    .add("From Wallet", &wallet.name)
    .add("From Address", &wallet.public_key)
    .add("Operations", doc.operations.len().to_string())
    .add("Batch File", args.file.display().to_string())
    .add(
        "Estimated Fee",
        format!("{:.7} XLM", tx_result.fee as f64 / 10_000_000.0),
    );

    // Add operation details to summary
    for (i, op) in payment_ops.iter().enumerate() {
        let asset_label = match (&op.asset_code, &op.asset_issuer) {
            (None, None) => "XLM".to_string(),
            (Some(code), Some(issuer)) => format!("{}:{}", code, issuer),
            _ => "unknown".to_string(),
        };
        summary = summary.add(
            format!("Op {}", i + 1),
            format!("payment → {} {} {}", op.destination, op.amount, asset_label),
        );
    }

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: args.network.clone(),
        skip_confirm: args.yes,
        dry_run: false,
        prompt: Some("Proceed with batch transaction?".to_string()),
        require_type_confirmation: args.network == "mainnet",
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    println!();

    let mut secret_key = wallet.secret_key.as_ref().unwrap().clone();
    if secret_key.contains(':') {
        let pwd = crypto::prompt_password(
            &format!("Enter password to decrypt wallet '{}'", wallet.name),
            false,
        )?;
        secret_key = crypto::decrypt_secret(&pwd, &secret_key)?;
    }

    p::info("Submitting batch transaction…");
    let submit_result = horizon::submit_payment_transaction(
        &tx_result.transaction_xdr,
        &secret_key,
        &args.network,
    )?;

    println!();
    p::separator();
    println!(
        "  {} {}",
        "✓".green().bold(),
        "Batch transaction submitted successfully!".bright_white()
    );
    println!();
    p::kv_accent("Transaction Hash", &submit_result.hash);

    let explorer_base = if args.network == "mainnet" {
        "https://stellar.expert/explorer/public/tx"
    } else {
        "https://stellar.expert/explorer/testnet/tx"
    };

    p::kv(
        "Stellar Expert",
        &format!("{}/{}", explorer_base, submit_result.hash),
    );
    p::separator();

    Ok(())
}

fn batch_operation_to_payment(op: &tx_batch::BatchOperation) -> Result<horizon::BatchPaymentOp> {
    match op {
        tx_batch::BatchOperation::Payment { to, amount, asset } => {
            let (asset_code, asset_issuer) = parse_asset(asset)?;
            Ok(horizon::BatchPaymentOp {
                destination: to.clone(),
                amount: amount.clone(),
                asset_code,
                asset_issuer,
            })
        }
    }
}

fn handle_send(args: SendArgs) -> Result<()> {
    p::header("Send Stellar Payment");

    config::validate_wallet_name(&args.from)?;
    config::validate_public_key(&args.to)?;
    config::validate_network(&args.network)?;
    config::validate_amount(&args.amount)?;

    // Load configuration and find wallet
    let cfg = config::load()?;
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == args.from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Wallet '{}' not found. Run `starforge wallet list`",
                args.from
            )
        })?;

    // Validate wallet has secret key
    if wallet.secret_key.is_none() {
        anyhow::bail!("Wallet '{}' has no secret key stored", args.from);
    }

    // Parse asset
    let (asset_code, asset_issuer) = parse_asset(&args.asset)?;

    // Validate amount
    let amount_f64 = config::validate_amount(&args.amount)?;

    p::separator();
    p::kv("From Wallet", &wallet.name);
    p::kv("From Address", &wallet.public_key);
    p::kv("To Address", &args.to);
    p::kv("Amount", &format!("{} {}", args.amount, args.asset));
    p::kv("Network", &args.network);

    if args.network == "mainnet" {
        p::warn("You are sending on MAINNET. This will cost real XLM.");
    }

    p::separator();

    // Step 1: Fetch source account info
    println!();
    p::step(1, 3, "Fetching source account info…");
    let source_account =
        horizon::fetch_account(&wallet.public_key, &args.network).map_err(|e| {
            anyhow::anyhow!(
                "Source account not found on {}: {}\nFund it with: starforge wallet fund {}",
                args.network,
                e,
                wallet.name
            )
        })?;

    // Check balance if sending XLM
    if asset_code.is_none() {
        let xlm_balance = source_account
            .balances
            .iter()
            .find(|b| b.asset_type == "native")
            .map(|b| b.balance.parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        p::kv("XLM Balance", &format!("{:.7} XLM", xlm_balance));

        if xlm_balance < amount_f64 + 0.00001 {
            // Reserve for fees
            anyhow::bail!(
                "Insufficient XLM balance. Have: {:.7}, Need: {:.7} + fees",
                xlm_balance,
                amount_f64
            );
        }
    }

    // Step 2: Validate destination account
    p::step(2, 3, "Validating destination account…");
    match horizon::fetch_account(&args.to, &args.network) {
        Ok(_) => p::kv("Destination", "✓ Account exists"),
        Err(_) => {
            if asset_code.is_none() {
                p::kv(
                    "Destination",
                    "⚠ Account will be created (requires 1 XLM minimum)",
                );
                if amount_f64 < 1.0 {
                    anyhow::bail!("Destination account doesn't exist. Minimum 1 XLM required to create account.");
                }
            } else {
                anyhow::bail!("Destination account doesn't exist and cannot be created with non-native assets");
            }
        }
    }

    // Step 3: Build and simulate transaction
    p::step(3, 3, "Building and simulating transaction…");
    let tx_result = horizon::build_and_simulate_payment(
        &wallet.public_key,
        &args.to,
        &args.amount,
        asset_code.as_deref(),
        asset_issuer.as_deref(),
        &source_account.sequence,
        &args.network,
    )?;

    p::kv(
        "Estimated Fee",
        &format!("{:.7} XLM", tx_result.fee as f64 / 10_000_000.0),
    );
    p::kv(
        "Transaction XDR",
        &format!("{}...", &tx_result.transaction_xdr[..20]),
    );

    // Build operation summary for confirmation
    let risk_level = if args.network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };

    let summary = confirmation::OperationSummary::new(
        "Send Stellar Payment".to_string(),
        args.network.clone(),
        risk_level,
    )
    .add("From Wallet", &wallet.name)
    .add("From Address", &wallet.public_key)
    .add("To Address", &args.to)
    .add("Amount", format!("{} {}", args.amount, args.asset))
    .add(
        "Estimated Fee",
        format!("{:.7} XLM", tx_result.fee as f64 / 10_000_000.0),
    );

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: args.network.clone(),
        skip_confirm: args.yes,
        dry_run: false,
        prompt: Some("Proceed with payment?".to_string()),
        require_type_confirmation: args.network == "mainnet",
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    // Submit transaction
    println!();

    let mut secret_key = wallet.secret_key.as_ref().unwrap().clone();
    if secret_key.contains(':') {
        let pwd = crypto::prompt_password(
            &format!("Enter password to decrypt wallet '{}'", wallet.name),
            false,
        )?;
        secret_key = crypto::decrypt_secret(&pwd, &secret_key)?;
    }

    p::info("Submitting transaction…");
    let submit_result = horizon::submit_payment_transaction(
        &tx_result.transaction_xdr,
        &secret_key,
        &args.network,
    )?;

    println!();
    p::separator();
    println!(
        "  {} {}",
        "✓".green().bold(),
        "Payment sent successfully!".bright_white()
    );
    println!();
    p::kv_accent("Transaction Hash", &submit_result.hash);

    let explorer_base = if args.network == "mainnet" {
        "https://stellar.expert/explorer/public/tx"
    } else {
        "https://stellar.expert/explorer/testnet/tx"
    };

    p::kv(
        "Stellar Expert",
        &format!("{}/{}", explorer_base, submit_result.hash),
    );
    p::separator();

    Ok(())
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
        anyhow::bail!("Invalid asset format. Use CODE:ISSUER or XLM");
    }
}

fn handle_history(args: HistoryArgs) -> Result<()> {
    let limit = args.limit.min(200);

    config::validate_public_key(&args.public_key)?;

    let network = args.network_override.unwrap_or_else(|| {
        config::load()
            .map(|c| c.network)
            .unwrap_or_else(|_| "testnet".to_string())
    });
    config::validate_network(&network)?;

    println!();
    println!(
        "  {} {}",
        "◆".cyan().bold(),
        "Transaction History".white().bold()
    );
    println!("  {} {}", "Account :".dimmed(), args.public_key.yellow());
    println!("  {} {}", "Network :".dimmed(), network.cyan());
    println!(
        "  {} {}",
        "Showing :".dimmed(),
        format!("up to {} txs", limit).white()
    );

    if args.after.is_some() || args.before.is_some() {
        let range = format!(
            "{} → {}",
            args.after.as_deref().unwrap_or("*"),
            args.before.as_deref().unwrap_or("*")
        );
        println!("  {} {}", "Range   :".dimmed(), range.white());
    }
    if args.successful_only {
        println!("  {} {}", "Filter  :".dimmed(), "successful only".white());
    }
    if args.cursor.is_some() {
        println!(
            "  {} {}",
            "Cursor  :".dimmed(),
            "paginating from cursor".white()
        );
    }

    println!("  {}", "─".repeat(72).dimmed());

    let filter = horizon::TxFilter {
        limit,
        cursor: args.cursor,
        after: args.after,
        before: args.before,
        order: None,
        type_filter: None,
        successful_only: if args.successful_only {
            Some(true)
        } else {
            None
        },
    };

    match horizon::fetch_transactions_filtered(&args.public_key, &network, filter) {
        Err(e) => {
            println!("\n  {} {}\n", "✗".red().bold(), e.to_string().red());
        }
        Ok(txs) if txs.is_empty() => {
            println!(
                "\n  {} No transactions found for this account.\n",
                "!".yellow().bold()
            );
        }
        Ok(txs) => {
            print_transactions(&txs, &network, args.details);
        }
    }

    Ok(())
}

fn handle_fees(network_opt: Option<String>) -> Result<()> {
    // Determine the network, default to config or testnet
    let network = match network_opt {
        Some(net) => net,
        None => config::load()?.network,
    };
    config::validate_network(&network)?;
    let stats: FeeStats = horizon::fetch_fee_stats(&network)?;
    p::header("Recommended Fee Levels");
    p::kv("Network", &network);
    p::kv("Low Fee (stroops)", &stats.low_fee);
    p::kv("Medium Fee (stroops)", &stats.mode_fee);
    p::kv("High Fee (stroops)", &stats.high_fee);
    Ok(())
}

fn decode_memo(memo_type: Option<&str>, memo: Option<&str>) -> String {
    match (memo_type, memo) {
        (Some("text"), Some(m)) => format!("\"{}\"", m),
        (Some("id"), Some(m)) => format!("id:{}", m),
        (Some("hash"), Some(m)) => format!("hash:{}", &m[..m.len().min(16)]),
        (Some("return"), Some(m)) => format!("return:{}", &m[..m.len().min(16)]),
        (Some("none"), _) | (None, _) => "none".to_string(),
        _ => "—".to_string(),
    }
}

fn print_transactions(txs: &[horizon::TransactionRecord], network: &str, details: bool) {
    println!(
        "  {:<14}  {:<6}  {:<4}  {:<12}  {}",
        "Hash".dimmed(),
        "Status".dimmed(),
        "Ops".dimmed(),
        "Fee (XLM)".dimmed(),
        "Timestamp (UTC)".dimmed(),
    );
    println!("  {}", "─".repeat(72).dimmed());

    for tx in txs {
        let short_hash = format!("{}…", &tx.hash[..12]);

        let status = if tx.successful {
            "✓ ok".green().to_string()
        } else {
            "✗ fail".red().to_string()
        };

        let fee_xlm = tx
            .fee_charged
            .parse::<f64>()
            .map(|s| format!("{:.7}", s / 10_000_000.0))
            .unwrap_or_else(|_| tx.fee_charged.clone());

        let ts = tx
            .created_at
            .replace('T', " ")
            .get(..16)
            .unwrap_or(&tx.created_at)
            .to_string();

        println!(
            "  {:<14}  {:<6}  {:<4}  {:<12}  {}",
            short_hash.white(),
            status,
            tx.operation_count.to_string().white(),
            fee_xlm.yellow(),
            ts.dimmed(),
        );

        if details {
            if let Some(ref src) = tx.source_account {
                println!(
                    "  {:<14}  {}",
                    "".dimmed(),
                    format!("src: {}…", &src[..16]).dimmed()
                );
            }
            let memo = decode_memo(tx.memo_type.as_deref(), tx.memo.as_deref());
            println!(
                "  {:<14}  {}",
                "".dimmed(),
                format!("memo: {}", memo).dimmed()
            );
        }
    }

    println!("  {}", "─".repeat(72).dimmed());

    // Pagination hint
    if let Some(last) = txs.last() {
        if let Some(ref token) = last.paging_token {
            println!(
                "\n  {} {}",
                "Next page:".dimmed(),
                format!("--cursor {}", token).cyan()
            );
        }
    }

    // Explorer deep link
    let explorer_base = if network == "mainnet" {
        "https://stellar.expert/explorer/public/tx"
    } else {
        "https://stellar.expert/explorer/testnet/tx"
    };

    if let Some(first) = txs.first() {
        println!(
            "\n  {} {}/{}\n",
            "🔗 Latest tx:".dimmed(),
            explorer_base,
            first.hash.cyan()
        );
    }
}
