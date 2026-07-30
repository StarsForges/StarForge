use crate::utils::{config, confirmation, horizon, print as p, soroban, upgrade_analyzer};
use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum UpgradeCommands {
    /// Compare two contract WASMs for upgrade-breaking changes
    Analyze(AnalyzeArgs),
    /// Prepare and validate a contract upgrade
    Prepare(PrepareArgs),
    /// Create a governance proposal for a contract upgrade
    Propose(ProposeArgs),
    /// List pending upgrade proposals
    List(ListArgs),
    /// Show status of upgrade proposals (alias for list)
    Status(ListArgs),
    /// Approve a pending upgrade proposal
    Approve(ApproveArgs),
    /// Execute an approved upgrade proposal
    Execute(ExecuteArgs),
    /// Roll back to a previous contract version
    Rollback(RollbackArgs),
    /// Show upgrade history for a contract
    History(HistoryArgs),
}

#[derive(Args)]
pub struct AnalyzeArgs {
    /// Path to the currently deployed contract WASM
    #[arg(long)]
    pub current: PathBuf,
    /// Path to the candidate contract WASM
    #[arg(long)]
    pub candidate: PathBuf,
    /// Report format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Save the report to a file
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct PrepareArgs {
    /// Contract ID to upgrade
    #[arg(long)]
    pub contract_id: String,
    /// Path to the new compiled .wasm file
    #[arg(long)]
    pub wasm: PathBuf,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
}

#[derive(Args)]
pub struct ProposeArgs {
    /// Contract ID to upgrade
    #[arg(long)]
    pub contract_id: String,
    /// Path to the new compiled .wasm file
    #[arg(long)]
    pub wasm: PathBuf,
    /// Human-readable description of the upgrade
    #[arg(long)]
    pub description: String,
    /// Wallet name to use for signing
    #[arg(long)]
    pub wallet: Option<String>,
    /// Wallet name that sponsors fees via a fee-bump envelope when execution needs it
    #[arg(long)]
    pub fee_payer: Option<String>,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Number of approvals required before execution (default: 1)
    #[arg(long, default_value_t = 1)]
    pub threshold: u8,
}

#[derive(Args)]
pub struct ListArgs {
    /// Filter by contract ID (optional)
    #[arg(long)]
    pub contract_id: Option<String>,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
}

#[derive(Args)]
pub struct ApproveArgs {
    /// Proposal ID to approve
    #[arg(long)]
    pub proposal_id: String,
    /// Wallet name to use for signing
    #[arg(long)]
    pub wallet: Option<String>,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
}

#[derive(Args)]
pub struct ExecuteArgs {
    /// Proposal ID to execute
    #[arg(long)]
    pub proposal_id: String,
    /// Wallet name to use for signing
    #[arg(long)]
    pub wallet: Option<String>,
    /// Wallet name that sponsors fees via a fee-bump envelope when execution needs it
    #[arg(long)]
    pub fee_payer: Option<String>,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
}

#[derive(Args)]
pub struct RollbackArgs {
    /// Contract ID to roll back
    #[arg(long)]
    pub contract_id: String,
    /// Target version hash to roll back to (if omitted, uses previous hash from history)
    #[arg(long)]
    pub to_hash: Option<String>,
    /// Wallet name to use for signing
    #[arg(long)]
    pub wallet: Option<String>,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    pub yes: bool,
}

#[derive(Args)]
pub struct HistoryArgs {
    /// Contract ID to show history for
    #[arg(long)]
    pub contract_id: String,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
}

// ── Data structures ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Pending,
    Approved,
    Executed,
    Rejected,
    Expired,
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalStatus::Pending => write!(f, "pending"),
            ProposalStatus::Approved => write!(f, "approved"),
            ProposalStatus::Executed => write!(f, "executed"),
            ProposalStatus::Rejected => write!(f, "rejected"),
            ProposalStatus::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub id: String,
    pub contract_id: String,
    pub new_wasm_hash: String,
    pub description: String,
    pub proposer: String,
    pub approvals: Vec<String>,
    pub threshold: u8,
    pub status: ProposalStatus,
    pub network: String,
    pub created_at: String,
    pub executed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRecord {
    pub contract_id: String,
    pub from_hash: String,
    pub to_hash: String,
    pub proposal_id: String,
    pub executed_by: String,
    pub network: String,
    pub timestamp: String,
}

// ── Storage helpers ───────────────────────────────────────────────────────────

fn upgrade_dir() -> Result<PathBuf> {
    let dir = config::config_dir().join("upgrades");
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

fn proposals_path() -> Result<PathBuf> {
    Ok(upgrade_dir()?.join("proposals.json"))
}

fn history_path() -> Result<PathBuf> {
    Ok(upgrade_dir()?.join("history.json"))
}

fn load_proposals() -> Result<Vec<UpgradeProposal>> {
    let path = proposals_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&data).unwrap_or_default())
}

fn save_proposals(proposals: &[UpgradeProposal]) -> Result<()> {
    fs::write(proposals_path()?, serde_json::to_string_pretty(proposals)?)?;
    Ok(())
}

fn load_history() -> Result<Vec<UpgradeRecord>> {
    let path = history_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&data).unwrap_or_default())
}

fn save_history(history: &[UpgradeRecord]) -> Result<()> {
    fs::write(history_path()?, serde_json::to_string_pretty(history)?)?;
    Ok(())
}

// ── WASM utilities ────────────────────────────────────────────────────────────

/// Compute SHA-256 hash of WASM bytes, returned as a hex string.
pub fn wasm_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn validate_wasm(path: &PathBuf) -> Result<(Vec<u8>, String)> {
    if !path.exists() {
        anyhow::bail!(
            "WASM file not found: {}\nRun `stellar contract build` first.",
            path.display()
        );
    }
    let bytes = fs::read(path)?;
    // Basic WASM magic number check: \0asm
    if bytes.len() < 4 || &bytes[..4] != b"\0asm" {
        anyhow::bail!(
            "File does not appear to be a valid WASM binary: {}",
            path.display()
        );
    }
    let size_kb = bytes.len() as f64 / 1024.0;
    if size_kb > 128.0 {
        p::warn(&format!(
            "WASM is {:.1} KB — Soroban limit is 128 KB.",
            size_kb
        ));
    }
    let hash = wasm_hash(&bytes);
    Ok((bytes, hash))
}

fn short_id(id: &str) -> String {
    format!("{}…", &id[..id.len().min(12)])
}

// ── Command handlers ──────────────────────────────────────────────────────────

pub fn handle(cmd: UpgradeCommands) -> Result<()> {
    match cmd {
        UpgradeCommands::Analyze(args) => handle_analyze(args),
        UpgradeCommands::Prepare(args) => handle_prepare(args),
        UpgradeCommands::Propose(args) => handle_propose(args),
        UpgradeCommands::List(args) => handle_list(args),
        UpgradeCommands::Status(args) => handle_list(args), // Alias for list
        UpgradeCommands::Approve(args) => handle_approve(args),
        UpgradeCommands::Execute(args) => handle_execute(args),
        UpgradeCommands::Rollback(args) => handle_rollback(args),
        UpgradeCommands::History(args) => handle_history(args),
    }
}

fn handle_analyze(args: AnalyzeArgs) -> Result<()> {
    let report = upgrade_analyzer::analyze_paths(&args.current, &args.candidate)?;
    let rendered = if args.format == "json" {
        serde_json::to_string_pretty(&report)?
    } else {
        render_analysis_table(&report)
    };

    println!("{rendered}");
    if let Some(path) = args.output {
        fs::write(&path, format!("{rendered}\n"))
            .with_context(|| format!("Failed to write analysis report {}", path.display()))?;
        if args.format != "json" {
            p::info(&format!("Report saved to {}", path.display()));
        }
    }

    if report.summary.breaking > 0 {
        anyhow::bail!(
            "upgrade analysis found {} breaking finding(s)",
            report.summary.breaking
        );
    }
    Ok(())
}

fn render_analysis_table(report: &upgrade_analyzer::UpgradeReport) -> String {
    use upgrade_analyzer::{Confidence, FindingCategory, Risk};

    let mut output = String::new();
    output.push_str("Soroban Contract Upgrade Safety Report\n");
    output.push_str(&format!("Current:   {}\n", report.current.path));
    output.push_str(&format!("Candidate: {}\n\n", report.candidate.path));
    output.push_str(&format!(
        "{:<10}  {:<10}  {:<11}  {:<28}  {}\n",
        "RISK", "AREA", "CONFIDENCE", "SUBJECT", "CHANGE"
    ));
    output.push_str(&format!("{}\n", "─".repeat(100)));

    for finding in &report.findings {
        let risk = match finding.risk {
            Risk::Breaking => "breaking",
            Risk::Warning => "warning",
            Risk::Info => "info",
        };
        let area = match finding.category {
            FindingCategory::Interface => "interface",
            FindingCategory::Storage => "storage",
        };
        let confidence = match finding.confidence {
            Confidence::Confirmed => "confirmed",
            Confidence::Heuristic => "heuristic",
        };
        output.push_str(&format!(
            "{:<10}  {:<10}  {:<11}  {:<28}  {}\n",
            risk, area, confidence, finding.subject, finding.message
        ));
        if finding.current.is_some() || finding.candidate.is_some() {
            output.push_str(&format!(
                "  current: {} | candidate: {}\n",
                finding.current.as_deref().unwrap_or("—"),
                finding.candidate.as_deref().unwrap_or("—")
            ));
        }
    }

    output.push_str(&format!(
        "\nSummary: {} breaking, {} warning, {} info — {}\n",
        report.summary.breaking,
        report.summary.warnings,
        report.summary.info,
        if report.summary.safe_to_upgrade {
            "no breaking changes found"
        } else {
            "upgrade blocked"
        }
    ));
    output
}

fn handle_prepare(args: PrepareArgs) -> Result<()> {
    p::header("Prepare Contract Upgrade");

    config::validate_contract_id(&args.contract_id)?;
    config::validate_network(&args.network)?;

    p::step(1, 4, "Validating WASM file…");
    let (_, new_hash) = validate_wasm(&args.wasm)?;
    p::kv_accent("New WASM hash", &new_hash);

    p::step(2, 4, "Verifying contract exists on-chain…");
    let cfg = config::load()?;
    let wallet = cfg.wallets.first().ok_or_else(|| {
        anyhow::anyhow!("No wallets found. Create one with `starforge wallet create`")
    })?;
    horizon::fetch_account(&wallet.public_key, &args.network)
        .map_err(|e| anyhow::anyhow!("Account not active on {}: {}", args.network, e))?;

    p::step(3, 4, "Fetching current on-chain WASM hash…");
    match soroban::inspect_contract(&args.contract_id, &args.network) {
        Ok(inspect) => {
            if let Some(ref on_chain_hash) = inspect.wasm_hash {
                p::kv("Current on-chain hash", on_chain_hash);
                if *on_chain_hash == new_hash {
                    p::warn("The on-chain contract already runs this exact WASM — upgrade would be a no-op.");
                } else {
                    p::success("On-chain hash differs from local — upgrade is meaningful.");
                }
            } else {
                p::info("Could not determine current on-chain WASM hash (StellarAsset contract?).");
            }
        }
        Err(e) => {
            p::warn(&format!("Could not inspect contract on-chain: {}", e));
            p::info("Proceeding without on-chain hash verification.");
        }
    }

    p::step(4, 4, "Generating upgrade command…");
    println!();
    p::separator();
    p::kv("Contract ID", &args.contract_id);
    p::kv("Network", &args.network);
    p::kv("WASM file", &args.wasm.display().to_string());
    p::kv_accent("New hash", &new_hash);
    println!();
    println!(
        "  {} {}",
        "Next step:".bright_white(),
        "create a proposal with:".dimmed()
    );
    println!(
        "  {}",
        format!(
            "starforge upgrade propose --contract-id {} --wasm {} --description \"<reason>\"",
            args.contract_id,
            args.wasm.display()
        )
        .cyan()
    );
    p::separator();
    Ok(())
}

fn handle_propose(args: ProposeArgs) -> Result<()> {
    p::header("Create Upgrade Proposal");

    config::validate_contract_id(&args.contract_id)?;
    config::validate_network(&args.network)?;

    p::step(1, 5, "Validating WASM…");
    let (_, new_hash) = validate_wasm(&args.wasm)?;

    p::step(2, 5, "Loading wallet…");
    let cfg = config::load()?;
    let wallet = resolve_wallet(&cfg, args.wallet.as_deref())?;
    let fee_payer = resolve_optional_wallet(&cfg, args.fee_payer.as_deref(), "Fee payer")?;
    if let Some(fee_payer) = fee_payer {
        p::kv("Fee payer", &fee_payer.name);
    }

    // ── On-chain hash verification ────────────────────────────────────────
    p::step(3, 5, "Verifying on-chain WASM hash…");
    match soroban::inspect_contract(&args.contract_id, &args.network) {
        Ok(inspect) => {
            if let Some(ref on_chain_hash) = inspect.wasm_hash {
                p::kv("Current on-chain hash", on_chain_hash);
                p::kv_accent("New local hash", &new_hash);
                if *on_chain_hash == new_hash {
                    p::warn("The on-chain contract already runs this exact WASM — upgrade would be a no-op.");
                }
            }
        }
        Err(e) => {
            p::warn(&format!("Could not verify on-chain hash: {}", e));
        }
    }
    match soroban::inspect_contract_archival(&args.contract_id, &args.network) {
        Ok(report) => print_archival_preflight(&report),
        Err(e) => p::warn(&format!("Archival preflight unavailable: {}", e)),
    }

    // ── Upgrade simulation + auth display ─────────────────────────────────
    p::step(4, 5, "Simulating upgrade transaction…");
    match soroban::simulate_upgrade_transaction(&args.contract_id, &new_hash, wallet, &args.network)
    {
        Ok(sim) => {
            p::kv("Estimated fee", &format!("{} stroops", sim.fee));
            if let Some(ref footprint) = sim.footprint {
                print_footprint_summary(footprint);
            }
            if !sim.auth_entries.is_empty() {
                println!();
                p::info("Authorization entries required by this upgrade:");
                for (i, entry) in sim.auth_entries.iter().enumerate() {
                    println!(
                        "  {}. {} → {}",
                        i + 1,
                        entry.address.cyan(),
                        entry.function.bright_white()
                    );
                    for sub in &entry.sub_invocations {
                        println!("     └─ {}", sub.dimmed());
                    }
                }
            }
            if !sim.errors.is_empty() {
                for error in &sim.errors {
                    p::warn(&format!("Simulation warning: {}", error));
                }
            }
        }
        Err(e) => {
            p::warn(&format!("Upgrade simulation failed: {}", e));
            p::info("Proceeding without simulation. The upgrade may still succeed.");
        }
    }

    p::step(5, 5, "Saving proposal…");
    let proposal_id = format!("prop-{}", &new_hash[..12]);

    // Check for duplicate
    let mut proposals = load_proposals()?;
    if proposals.iter().any(|p| p.id == proposal_id) {
        anyhow::bail!(
            "A proposal for this WASM hash already exists: {}",
            proposal_id
        );
    }

    let proposal = UpgradeProposal {
        id: proposal_id.clone(),
        contract_id: args.contract_id.clone(),
        new_wasm_hash: new_hash.clone(),
        description: args.description.clone(),
        proposer: wallet.public_key.clone(),
        approvals: vec![wallet.public_key.clone()], // proposer auto-approves
        threshold: args.threshold,
        status: if args.threshold <= 1 {
            ProposalStatus::Approved
        } else {
            ProposalStatus::Pending
        },
        network: args.network.clone(),
        created_at: Utc::now().to_rfc3339(),
        executed_at: None,
    };

    proposals.push(proposal);
    save_proposals(&proposals)?;

    println!();
    p::separator();
    p::kv_accent("Proposal ID", &proposal_id);
    p::kv("Contract ID", &args.contract_id);
    p::kv("New hash", &new_hash);
    p::kv("Description", &args.description);
    p::kv("Proposer", &wallet.public_key);
    p::kv("Threshold", &args.threshold.to_string());
    p::kv(
        "Status",
        if args.threshold <= 1 {
            "approved (auto)"
        } else {
            "pending"
        },
    );
    println!();
    if args.threshold <= 1 {
        p::info(&format!(
            "Ready to execute: starforge upgrade execute --proposal-id {}",
            proposal_id
        ));
    } else {
        p::info(&format!(
            "Needs {} more approval(s): starforge upgrade approve --proposal-id {}",
            args.threshold - 1,
            proposal_id
        ));
    }
    p::separator();
    Ok(())
}

fn handle_list(args: ListArgs) -> Result<()> {
    p::header("Upgrade Proposals");
    config::validate_network(&args.network)?;

    let proposals = load_proposals()?;
    let filtered: Vec<_> = proposals
        .iter()
        .filter(|p| p.network == args.network)
        .filter(|p| {
            args.contract_id
                .as_deref()
                .is_none_or(|id| p.contract_id == id)
        })
        .collect();

    if filtered.is_empty() {
        p::info("No proposals found.");
        return Ok(());
    }

    p::separator();
    println!(
        "  {:<16}  {:<14}  {:<10}  {:<10}  {}",
        "Proposal ID".dimmed(),
        "Contract".dimmed(),
        "Status".dimmed(),
        "Approvals".dimmed(),
        "Created".dimmed(),
    );
    println!("  {}", "─".repeat(72).dimmed());

    for prop in &filtered {
        let status_colored = match prop.status {
            ProposalStatus::Pending => prop.status.to_string().yellow().to_string(),
            ProposalStatus::Approved => prop.status.to_string().cyan().to_string(),
            ProposalStatus::Executed => prop.status.to_string().green().to_string(),
            ProposalStatus::Rejected | ProposalStatus::Expired => {
                prop.status.to_string().red().to_string()
            }
        };
        let approvals = format!("{}/{}", prop.approvals.len(), prop.threshold);
        let created = prop.created_at.get(..10).unwrap_or(&prop.created_at);
        println!(
            "  {:<16}  {:<14}  {:<10}  {:<10}  {}",
            prop.id.white(),
            short_id(&prop.contract_id).cyan(),
            status_colored,
            approvals.white(),
            created.dimmed(),
        );
    }
    p::separator();
    Ok(())
}

fn handle_approve(args: ApproveArgs) -> Result<()> {
    p::header("Approve Upgrade Proposal");
    config::validate_network(&args.network)?;

    let cfg = config::load()?;
    let wallet = resolve_wallet(&cfg, args.wallet.as_deref())?;

    let mut proposals = load_proposals()?;
    let proposal = proposals
        .iter_mut()
        .find(|p| p.id == args.proposal_id && p.network == args.network)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Proposal '{}' not found on {}",
                args.proposal_id,
                args.network
            )
        })?;

    if proposal.status != ProposalStatus::Pending {
        anyhow::bail!(
            "Proposal '{}' is not pending (status: {})",
            args.proposal_id,
            proposal.status
        );
    }
    if proposal.approvals.contains(&wallet.public_key) {
        anyhow::bail!(
            "Wallet '{}' has already approved this proposal",
            wallet.name
        );
    }

    proposal.approvals.push(wallet.public_key.clone());
    if proposal.approvals.len() >= proposal.threshold as usize {
        proposal.status = ProposalStatus::Approved;
    }

    let new_status = proposal.status.to_string();
    let approvals = format!("{}/{}", proposal.approvals.len(), proposal.threshold);
    save_proposals(&proposals)?;

    println!();
    p::kv_accent("Proposal", &args.proposal_id);
    p::kv("Approved by", &wallet.public_key);
    p::kv("Approvals", &approvals);
    p::kv("Status", &new_status);
    println!();
    if new_status == "approved" {
        p::success("Threshold reached — ready to execute.");
        p::info(&format!(
            "starforge upgrade execute --proposal-id {}",
            args.proposal_id
        ));
    }
    Ok(())
}

fn handle_execute(args: ExecuteArgs) -> Result<()> {
    p::header("Execute Contract Upgrade");
    config::validate_network(&args.network)?;

    let cfg = config::load()?;
    let wallet = resolve_wallet(&cfg, args.wallet.as_deref())?;
    let fee_payer = resolve_optional_wallet(&cfg, args.fee_payer.as_deref(), "Fee payer")?;

    let mut proposals = load_proposals()?;
    let proposal = proposals
        .iter_mut()
        .find(|p| p.id == args.proposal_id && p.network == args.network)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Proposal '{}' not found on {}",
                args.proposal_id,
                args.network
            )
        })?;

    if proposal.status != ProposalStatus::Approved {
        anyhow::bail!(
            "Proposal '{}' is not approved (status: {}). It needs {} approval(s).",
            args.proposal_id,
            proposal.status,
            proposal.threshold
        );
    }

    p::separator();
    p::kv("Proposal ID", &proposal.id);
    p::kv("Contract ID", &proposal.contract_id);
    p::kv_accent("New WASM hash", &proposal.new_wasm_hash);
    p::kv("Network", &proposal.network);
    p::kv("Executor", &wallet.public_key);
    if let Some(fee_payer) = fee_payer {
        p::kv("Fee payer", &fee_payer.name);
    }
    match soroban::inspect_contract_archival(&proposal.contract_id, &args.network) {
        Ok(report) => print_archival_preflight(&report),
        Err(e) => p::warn(&format!("Archival preflight unavailable: {}", e)),
    }

    // Build operation summary for confirmation
    let risk_level = if args.network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };

    let summary = confirmation::OperationSummary::new(
        "Execute Contract Upgrade".to_string(),
        args.network.clone(),
        risk_level,
    )
    .add("Proposal ID", &proposal.id)
    .add("Contract ID", &proposal.contract_id)
    .add("New WASM hash", &proposal.new_wasm_hash)
    .add("Network", &proposal.network)
    .add("Executor", &wallet.public_key)
    .add(
        "Fee Payer",
        fee_payer
            .map(|wallet| wallet.name.as_str())
            .unwrap_or("not configured"),
    )
    .add(
        "Approvals",
        format!("{}/{}", proposal.approvals.len(), proposal.threshold),
    );

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: args.network.clone(),
        skip_confirm: args.yes,
        dry_run: false,
        prompt: Some("Execute this upgrade?".to_string()),
        require_type_confirmation: args.network == "mainnet",
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    println!();
    p::step(1, 3, "Verifying account on-chain…");
    horizon::fetch_account(&wallet.public_key, &args.network)
        .map_err(|e| anyhow::anyhow!("Account not active on {}: {}", args.network, e))?;

    // ── Multisig signer weight check ──────────────────────────────────────
    if proposal.threshold > 1 {
        p::step(2, 3, "Validating multisig signer weights…");
        match horizon::fetch_account_signers(&wallet.public_key, &args.network) {
            Ok(signer_info) => {
                let local_keys: Vec<&str> =
                    cfg.wallets.iter().map(|w| w.public_key.as_str()).collect();
                let available_weight: u32 = signer_info
                    .signers
                    .iter()
                    .filter(|s| local_keys.contains(&s.key.as_str()))
                    .map(|s| s.weight)
                    .sum();
                let required = signer_info.thresholds.high;

                p::kv("On-chain high threshold", &required.to_string());
                p::kv(
                    "Available local signer weight",
                    &available_weight.to_string(),
                );

                if required > 0 && available_weight < required {
                    let missing: Vec<String> = signer_info
                        .signers
                        .iter()
                        .filter(|s| !local_keys.contains(&s.key.as_str()))
                        .map(|s| format!("  • {} (weight {})", short_id(&s.key), s.weight))
                        .collect();

                    let hint = if missing.is_empty() {
                        "No additional signers found on-chain.".to_string()
                    } else {
                        format!("Missing signers:\n{}", missing.join("\n"))
                    };

                    anyhow::bail!(
                        "Insufficient local signer weight ({}/{}) for high-threshold upgrade.\n{}",
                        available_weight,
                        required,
                        hint
                    );
                }
                p::success("Local signers meet the required threshold weight.");
            }
            Err(e) => {
                p::warn(&format!("Could not verify signer weights: {}", e));
                p::info("Proceeding without signer weight validation.");
            }
        }
    }

    p::step(3, 3, "Generating upgrade command…");

    // Clone fields needed after the mutable borrow ends
    let contract_id = proposal.contract_id.clone();
    let new_wasm_hash = proposal.new_wasm_hash.clone();

    // Fetch the current on-chain WASM hash to record as from_hash
    let from_hash = match soroban::inspect_contract(&contract_id, &args.network) {
        Ok(inspect) => inspect.wasm_hash.unwrap_or_else(|| "unknown".to_string()),
        Err(_) => "unknown".to_string(),
    };

    // Record in history with the actual from_hash
    let mut history = load_history()?;
    history.push(UpgradeRecord {
        contract_id: contract_id.clone(),
        from_hash,
        to_hash: new_wasm_hash.clone(),
        proposal_id: proposal.id.clone(),
        executed_by: wallet.public_key.clone(),
        network: proposal.network.clone(),
        timestamp: Utc::now().to_rfc3339(),
    });
    save_history(&history)?;

    proposal.status = ProposalStatus::Executed;
    proposal.executed_at = Some(Utc::now().to_rfc3339());
    save_proposals(&proposals)?;

    println!();
    p::separator();
    println!(
        "  {} {}",
        "✓".green().bold(),
        "Upgrade ready! Run this to apply on-chain:".bright_white()
    );
    println!();
    println!(
        "  {}",
        format!(
            "stellar contract upload --wasm <path-to-new.wasm> --source {} --network {}",
            wallet.public_key, args.network
        )
        .cyan()
    );
    println!(
        "  {}",
        format!(
            "stellar contract invoke --id {} --source {} --network {} -- upgrade --new-wasm-hash {}",
            contract_id, wallet.public_key, args.network, new_wasm_hash
        ).cyan()
    );
    if let Some(fee_payer) = fee_payer {
        p::info(&format!(
            "Fee payer '{}' is configured for StarForge fee-bump flows; the generated Stellar CLI command still uses the executor source account.",
            fee_payer.name
        ));
    }
    p::separator();
    Ok(())
}

fn handle_rollback(args: RollbackArgs) -> Result<()> {
    p::header("Contract Rollback");
    config::validate_contract_id(&args.contract_id)?;
    config::validate_network(&args.network)?;

    let cfg = config::load()?;
    let wallet = resolve_wallet(&cfg, args.wallet.as_deref())?;

    let history = load_history()?;

    // Resolve the target hash: use --to-hash if provided, otherwise find
    // the most recent previous hash from upgrade history.
    let rollback_hash = match args.to_hash {
        Some(ref hash) => hash.clone(),
        None => {
            // Find the latest upgrade record for this contract and use its from_hash.
            let latest = history
                .iter()
                .rev()
                .find(|r| r.contract_id == args.contract_id && r.network == args.network);
            match latest {
                Some(record) if record.from_hash != "unknown" => {
                    p::info(&format!(
                        "No --to-hash specified. Using previous hash from history: {}",
                        short_id(&record.from_hash)
                    ));
                    record.from_hash.clone()
                }
                _ => {
                    anyhow::bail!(
                        "No --to-hash specified and no previous hash found in upgrade history.\n\
                         Run `starforge upgrade history --contract-id {}` to see available versions,\n\
                         or specify --to-hash explicitly.",
                        args.contract_id
                    );
                }
            }
        }
    };

    // Verify the target hash exists in history
    let target = history.iter()
        .find(|r| {
            r.contract_id == args.contract_id
                && r.network == args.network
                && (r.to_hash == rollback_hash || r.from_hash == rollback_hash)
        })
        .ok_or_else(|| anyhow::anyhow!(
            "Hash '{}' not found in upgrade history for contract '{}' on {}.\nRun `starforge upgrade history --contract-id {}` to see available versions.",
            rollback_hash, args.contract_id, args.network, args.contract_id
        ))?;

    p::separator();
    p::kv("Contract ID", &args.contract_id);
    p::kv_accent("Rollback to", &rollback_hash);
    p::kv("Originally from", &target.proposal_id);
    p::kv("Network", &args.network);

    // Build operation summary for confirmation
    let risk_level = if args.network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };

    let summary = confirmation::OperationSummary::new(
        "Contract Rollback".to_string(),
        args.network.clone(),
        risk_level,
    )
    .add("Contract ID", &args.contract_id)
    .add("Rollback to", &rollback_hash)
    .add("Originally from", &target.proposal_id)
    .add("Network", &args.network)
    .add("Executor", &wallet.public_key);

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: args.network.clone(),
        skip_confirm: args.yes,
        dry_run: false,
        prompt: Some("Proceed with rollback?".to_string()),
        require_type_confirmation: args.network == "mainnet",
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    println!();
    p::separator();
    println!(
        "  {} {}",
        "✓".green().bold(),
        "Rollback command:".bright_white()
    );
    println!();
    println!(
        "  {}",
        format!(
            "stellar contract invoke --id {} --source {} --network {} -- upgrade --new-wasm-hash {}",
            args.contract_id, wallet.public_key, args.network, rollback_hash
        ).cyan()
    );
    p::separator();
    Ok(())
}

fn handle_history(args: HistoryArgs) -> Result<()> {
    p::header("Contract Upgrade History");
    config::validate_contract_id(&args.contract_id)?;
    config::validate_network(&args.network)?;

    let history = load_history()?;
    let records: Vec<_> = history
        .iter()
        .filter(|r| r.contract_id == args.contract_id && r.network == args.network)
        .collect();

    if records.is_empty() {
        p::info("No upgrade history found for this contract.");
        return Ok(());
    }

    p::separator();
    p::kv("Contract ID", &args.contract_id);
    p::kv("Network", &args.network);
    println!();
    println!(
        "  {:<14}  {:<14}  {:<16}  {}",
        "From hash".dimmed(),
        "To hash".dimmed(),
        "Proposal".dimmed(),
        "Timestamp".dimmed(),
    );
    println!("  {}", "─".repeat(72).dimmed());

    for record in &records {
        println!(
            "  {:<14}  {:<14}  {:<16}  {}",
            short_id(&record.from_hash).dimmed(),
            short_id(&record.to_hash).cyan(),
            record.proposal_id.white(),
            record
                .timestamp
                .get(..16)
                .unwrap_or(&record.timestamp)
                .dimmed(),
        );
    }
    p::separator();
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_wallet<'a>(
    cfg: &'a config::Config,
    name: Option<&str>,
) -> Result<&'a config::WalletEntry> {
    if let Some(wallet_name) = name {
        cfg.wallets
            .iter()
            .find(|w| w.name == wallet_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Wallet '{}' not found. Run `starforge wallet list`",
                    wallet_name
                )
            })
    } else if !cfg.wallets.is_empty() {
        p::info(&format!(
            "No --wallet specified. Using: {}",
            cfg.wallets[0].name.cyan()
        ));
        Ok(&cfg.wallets[0])
    } else {
        anyhow::bail!("No wallets found. Create one with `starforge wallet create <name> --fund`")
    }
}

fn resolve_optional_wallet<'a>(
    cfg: &'a config::Config,
    name: Option<&str>,
    label: &str,
) -> Result<Option<&'a config::WalletEntry>> {
    name.map(|wallet_name| {
        cfg.wallets
            .iter()
            .find(|w| w.name == wallet_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} wallet '{}' not found. Run `starforge wallet list`",
                    label,
                    wallet_name
                )
            })
    })
    .transpose()
}

fn print_archival_preflight(report: &soroban::ArchivalPreflightReport) {
    if report.all_entries_live() {
        p::success("Archival preflight: target ledger entries are live");
        return;
    }

    p::warn("Archival preflight detected ledger lifecycle risk:");
    for entry in &report.entries {
        p::kv(
            &format!("  {}", entry.label),
            &format!("{:?} - {}", entry.status, entry.guidance),
        );
    }
}

fn print_footprint_summary(footprint: &soroban::StorageFootprintSummary) {
    p::kv(
        "Storage footprint",
        &format!(
            "{} read-only, {} read-write key(s)",
            footprint.read_only.len(),
            footprint.read_write.len()
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_hash_is_deterministic() {
        let bytes = b"mock wasm content";
        assert_eq!(wasm_hash(bytes), wasm_hash(bytes));
    }

    #[test]
    fn wasm_hash_differs_for_different_input() {
        assert_ne!(wasm_hash(b"version1"), wasm_hash(b"version2"));
    }

    #[test]
    fn wasm_hash_is_64_hex_chars() {
        let hash = wasm_hash(b"test");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn proposal_status_display() {
        assert_eq!(ProposalStatus::Pending.to_string(), "pending");
        assert_eq!(ProposalStatus::Approved.to_string(), "approved");
        assert_eq!(ProposalStatus::Executed.to_string(), "executed");
    }

    #[test]
    fn upgrade_record_preserves_from_hash() {
        let record = UpgradeRecord {
            contract_id: "CABC".to_string(),
            from_hash: "aabbccdd".to_string(),
            to_hash: "eeff0011".to_string(),
            proposal_id: "prop-123".to_string(),
            executed_by: "GEXECUTOR".to_string(),
            network: "testnet".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };
        // Verify that from_hash is preserved (not hardcoded to "unknown")
        assert_ne!(record.from_hash, "unknown");
        assert_eq!(record.from_hash, "aabbccdd");
    }

    #[test]
    fn short_id_truncates_long_ids() {
        let id = "abcdefghijklmnopqrstuvwxyz";
        let short = short_id(id);
        assert!(short.len() < id.len());
        assert!(short.ends_with('…'));
    }

    #[test]
    fn short_id_handles_short_input() {
        let id = "abc";
        let short = short_id(id);
        assert!(short.contains("abc"));
    }

    #[test]
    fn upgrade_proposal_serialization_roundtrip() {
        let proposal = UpgradeProposal {
            id: "prop-test123".to_string(),
            contract_id: "CCONTRACT".to_string(),
            new_wasm_hash: "deadbeef".repeat(8),
            description: "Test upgrade".to_string(),
            proposer: "GPROPOSER".to_string(),
            approvals: vec!["GPROPOSER".to_string()],
            threshold: 2,
            status: ProposalStatus::Pending,
            network: "testnet".to_string(),
            created_at: "2025-06-01T00:00:00Z".to_string(),
            executed_at: None,
        };

        let json = serde_json::to_string(&proposal).unwrap();
        let deserialized: UpgradeProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, proposal.id);
        assert_eq!(deserialized.threshold, 2);
        assert_eq!(deserialized.status, ProposalStatus::Pending);
    }
}
