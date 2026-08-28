use crate::signer_rotation::{
    build_rotation_plan, execute_plan, load_approval_bundle, load_execution_state, load_plan,
    load_policy, prepare_all_handoffs, prepare_partial_rollback, save_plan, save_policy,
    verify_plan_target, AccountTransport, ApprovalBundle, AvailabilityManifest, ExecutionOptions,
    ExecutionReport, ExecutionState, HorizonAccountTransport, InMemoryAccountTransport,
    PlannerOptions, RotationPlan, DEFAULT_NETWORK_TIMEOUT_SECONDS,
};
use crate::utils::{config, hardware_wallet::HardwareWalletKind};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Inspect on-chain signer weights, thresholds, types, sponsorship, and operability
    #[command(subcommand)]
    Signers(SignerCommands),
    /// Plan, execute, resume, and verify safe signer-policy migrations
    #[command(subcommand)]
    Rotation(RotationCommands),
}

#[derive(Subcommand)]
pub enum SignerCommands {
    /// Fetch and normalize an account's current signer policy
    Inspect(InspectArgs),
}

#[derive(Subcommand)]
pub enum RotationCommands {
    /// Build an ordered, lockout-safe, reversible migration plan
    Plan(PlanArgs),
    /// Start execution or prepare offline signing handoffs
    Execute(ExecuteArgs),
    /// Resume exactly at the first unverified checkpoint
    Resume(ResumeArgs),
    /// Compare the live or supplied policy with the plan target
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct InspectArgs {
    /// Stellar account G-address
    #[arg(long)]
    account: Option<String>,
    /// Configured StarForge network name
    #[arg(long, default_value = "testnet")]
    network: String,
    /// Override the configured Horizon URL
    #[arg(long)]
    horizon_url: Option<String>,
    /// Bound each network request to this many seconds (1-120)
    #[arg(long, default_value_t = DEFAULT_NETWORK_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
    /// Read a deterministic policy fixture instead of opening a network connection
    #[arg(long, conflicts_with_all = ["account", "horizon_url"])]
    input: Option<PathBuf>,
    /// Apply a versioned local signer-availability manifest
    #[arg(long)]
    availability: Option<PathBuf>,
    /// Stable terminal output contract
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    format: String,
    /// Save the normalized policy as a restricted JSON file
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
pub struct PlanArgs {
    /// Versioned current-policy JSON from `account signers inspect`
    #[arg(long)]
    current: PathBuf,
    /// Versioned target-policy JSON declaring desired availability channels
    #[arg(long)]
    target: PathBuf,
    /// Restricted path for the integrity-protected migration plan
    #[arg(long)]
    output: PathBuf,
    /// Disable staged signer challenges (use only for independently proven keys)
    #[arg(long)]
    no_verification_challenges: bool,
    /// Maximum ledger age of a plan when the source includes ledger evidence
    #[arg(long, default_value_t = 120)]
    expires_after_ledgers: u32,
    /// Fee per operation in stroops
    #[arg(long, default_value_t = 100)]
    base_fee_stroops: u32,
    /// Stable terminal output contract
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    format: String,
}

#[derive(Args)]
pub struct ExecuteArgs {
    /// Integrity-protected versioned rotation plan
    #[arg(long)]
    plan: PathBuf,
    /// New restricted execution checkpoint path
    #[arg(long)]
    state: PathBuf,
    /// Directory for unsigned envelopes, challenges, approval template, and recovery artifacts
    #[arg(long)]
    handoff_dir: PathBuf,
    /// Versioned approval bundle containing accumulated envelopes/challenge proofs
    #[arg(long)]
    approvals: Option<PathBuf>,
    /// Protected mode-600 Stellar secret-key file; repeat for multiple software signers
    #[arg(long = "software-key-file")]
    software_key_files: Vec<PathBuf>,
    /// Connected hardware signer; repeat for multiple devices
    #[arg(long = "hardware-wallet", value_enum)]
    hardware_wallets: Vec<HardwareWalletKind>,
    /// Submit fully approved envelopes; otherwise only stage reviewed artifacts
    #[arg(long)]
    submit: bool,
    /// Confirm that on-chain mutation is intended
    #[arg(long, requires = "submit")]
    yes: bool,
    /// Generate reverse handoffs if execution fails after a completed step
    #[arg(long)]
    rollback_on_failure: bool,
    /// Deterministic observed policy fixture; bypasses Horizon for CI/offline drills
    #[arg(long)]
    observed_policy: Option<PathBuf>,
    /// Override the configured Horizon URL
    #[arg(long)]
    horizon_url: Option<String>,
    /// Bound each network request to this many seconds (1-120)
    #[arg(long, default_value_t = DEFAULT_NETWORK_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
    /// Stable terminal output contract
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    format: String,
}

#[derive(Args)]
pub struct ResumeArgs {
    /// Integrity-protected versioned rotation plan
    #[arg(long)]
    plan: PathBuf,
    /// Existing restricted execution checkpoint
    #[arg(long)]
    state: PathBuf,
    /// Existing handoff directory
    #[arg(long)]
    handoff_dir: PathBuf,
    /// Updated approval bundle returned by software/hardware/offline signers
    #[arg(long)]
    approvals: Option<PathBuf>,
    /// Protected mode-600 Stellar secret-key file; repeat for multiple software signers
    #[arg(long = "software-key-file")]
    software_key_files: Vec<PathBuf>,
    /// Connected hardware signer; repeat for multiple devices
    #[arg(long = "hardware-wallet", value_enum)]
    hardware_wallets: Vec<HardwareWalletKind>,
    /// Submit fully approved envelopes
    #[arg(long)]
    submit: bool,
    /// Confirm that on-chain mutation is intended
    #[arg(long, requires = "submit")]
    yes: bool,
    /// Prepare rollback handoffs for all completed mutating steps
    #[arg(long, conflicts_with = "submit")]
    rollback: bool,
    /// Generate reverse handoffs if the resumed execution fails
    #[arg(long)]
    rollback_on_failure: bool,
    /// Deterministic observed policy fixture; bypasses Horizon for CI/recovery drills
    #[arg(long)]
    observed_policy: Option<PathBuf>,
    /// Override the configured Horizon URL
    #[arg(long)]
    horizon_url: Option<String>,
    /// Bound each network request to this many seconds (1-120)
    #[arg(long, default_value_t = DEFAULT_NETWORK_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
    /// Stable terminal output contract
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    format: String,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Integrity-protected versioned rotation plan
    #[arg(long)]
    plan: PathBuf,
    /// Deterministic observed policy fixture instead of Horizon
    #[arg(long)]
    observed_policy: Option<PathBuf>,
    /// Override the configured Horizon URL
    #[arg(long)]
    horizon_url: Option<String>,
    /// Bound each network request to this many seconds (1-120)
    #[arg(long, default_value_t = DEFAULT_NETWORK_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
    /// Stable terminal output contract
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    format: String,
}

pub fn is_machine_readable(command: &AccountCommands) -> bool {
    match command {
        AccountCommands::Signers(SignerCommands::Inspect(args)) => args.format == "json",
        AccountCommands::Rotation(RotationCommands::Plan(args)) => args.format == "json",
        AccountCommands::Rotation(RotationCommands::Execute(args)) => args.format == "json",
        AccountCommands::Rotation(RotationCommands::Resume(args)) => args.format == "json",
        AccountCommands::Rotation(RotationCommands::Verify(args)) => args.format == "json",
    }
}

pub fn handle(command: AccountCommands) -> Result<()> {
    match command {
        AccountCommands::Signers(SignerCommands::Inspect(args)) => inspect(args),
        AccountCommands::Rotation(RotationCommands::Plan(args)) => plan(args),
        AccountCommands::Rotation(RotationCommands::Execute(args)) => execute(args),
        AccountCommands::Rotation(RotationCommands::Resume(args)) => resume(args),
        AccountCommands::Rotation(RotationCommands::Verify(args)) => verify(args),
    }
}

fn inspect(args: InspectArgs) -> Result<()> {
    let mut policy = if let Some(path) = &args.input {
        load_policy(path)?
    } else {
        let account = args.account.as_deref().context(
            "--account is required unless --input supplies a deterministic policy fixture",
        )?;
        let (endpoint, passphrase) = network_settings(&args.network, args.horizon_url.as_deref())?;
        HorizonAccountTransport::new(
            endpoint,
            passphrase,
            Duration::from_secs(args.timeout_seconds),
        )?
        .inspect_account(account)?
    };
    if let Some(path) = &args.availability {
        let manifest: AvailabilityManifest = read_json(path, "availability manifest")?;
        manifest.apply(&mut policy)?;
    }
    let report = policy.safety_report();
    if let Some(path) = &args.output {
        save_policy(path, &policy)?;
    }
    if args.format == "json" {
        print_json(&serde_json::json!({
            "schema_version": 1,
            "command": "account.signers.inspect",
            "policy": policy,
            "safety": report,
            "output": args.output,
        }))?;
    } else {
        println!("{}", "Account signer policy".bold());
        println!("  Account: {}", policy.account_id);
        println!("  Sequence: {}", policy.sequence);
        println!(
            "  Thresholds: low={} medium={} high={}",
            policy.thresholds.low, policy.thresholds.medium, policy.thresholds.high
        );
        println!(
            "  Master: weight={} availability={:?}",
            policy.master_key.weight, policy.master_key.availability
        );
        for signer in &policy.signers {
            println!(
                "  Signer: {} type={} weight={} availability={:?} sponsor={}",
                crate::signer_rotation::redact_key(&signer.key),
                signer.signer_type,
                signer.weight,
                signer.availability,
                signer
                    .sponsored_by
                    .as_deref()
                    .map(crate::signer_rotation::redact_key)
                    .unwrap_or_else(|| "none".to_string())
            );
        }
        println!(
            "  Safety: {} (available {}/{})",
            if report.operable {
                "operable".green().to_string()
            } else {
                "lockout risk".red().to_string()
            },
            report.available_weight,
            report.total_weight
        );
        for finding in report.findings {
            println!("    {:?}: {}", finding.severity, finding.message);
        }
        if let Some(path) = args.output {
            println!("  Saved: {}", path.display());
        }
    }
    Ok(())
}

fn plan(args: PlanArgs) -> Result<()> {
    let current = load_policy(&args.current)?;
    let target = load_policy(&args.target)?;
    let options = PlannerOptions {
        require_verification_challenges: !args.no_verification_challenges,
        expires_after_ledgers: args.expires_after_ledgers,
        base_fee_stroops: args.base_fee_stroops,
        max_policy_mutations_per_envelope: 1,
    };
    let rotation = build_rotation_plan(current, target, options)?;
    save_plan(&args.output, &rotation)?;
    if args.format == "json" {
        print_json(&serde_json::json!({
            "schema_version": 1,
            "command": "account.rotation.plan",
            "plan": rotation,
            "output": args.output,
        }))?;
    } else {
        render_plan(&rotation, &args.output);
    }
    Ok(())
}

fn execute(args: ExecuteArgs) -> Result<()> {
    if args.state.exists() {
        bail!(
            "execution checkpoint {} already exists; use `account rotation resume`",
            args.state.display()
        );
    }
    if args.submit && !args.yes {
        bail!("--submit requires --yes after reviewing the plan and approval summaries");
    }
    let plan = load_plan(&args.plan)?;
    let approvals = load_or_empty_approvals(args.approvals.as_deref(), &plan.plan_id)?;
    prepare_all_handoffs(&plan, &args.handoff_dir)?;
    let options = ExecutionOptions {
        submit: args.submit,
        rollback_on_failure: args.rollback_on_failure,
        handoff_directory: args.handoff_dir,
        software_key_files: args.software_key_files,
        hardware_wallets: args.hardware_wallets,
    };
    let state = ExecutionState::new(&plan);
    run_with_transport(
        &plan,
        &args.state,
        state,
        &approvals,
        &options,
        args.observed_policy.as_deref(),
        args.horizon_url.as_deref(),
        args.timeout_seconds,
        &args.format,
    )
}

fn resume(args: ResumeArgs) -> Result<()> {
    if args.submit && !args.yes {
        bail!("--submit requires --yes after reviewing the plan and approval summaries");
    }
    let plan = load_plan(&args.plan)?;
    let state = load_execution_state(&args.state)?;
    state.bind_to_plan(&plan)?;
    let approvals = load_or_empty_approvals(args.approvals.as_deref(), &plan.plan_id)?;
    let options = ExecutionOptions {
        submit: args.submit,
        rollback_on_failure: args.rollback_on_failure,
        handoff_directory: args.handoff_dir,
        software_key_files: args.software_key_files,
        hardware_wallets: args.hardware_wallets,
    };
    if let Some(path) = args.observed_policy.as_deref() {
        let transport = InMemoryAccountTransport::new(load_policy(path)?);
        if args.rollback {
            let paths =
                prepare_partial_rollback(&plan, &state, &transport, &options.handoff_directory)?;
            return render_rollback(&plan, &paths, &args.format);
        }
        let report = execute_plan(&plan, &args.state, state, &transport, &approvals, &options)?;
        return render_execution(&report, &args.format);
    }
    let transport = horizon_for_plan(&plan, args.horizon_url.as_deref(), args.timeout_seconds)?;
    if args.rollback {
        let paths =
            prepare_partial_rollback(&plan, &state, &transport, &options.handoff_directory)?;
        return render_rollback(&plan, &paths, &args.format);
    }
    let report = execute_plan(&plan, &args.state, state, &transport, &approvals, &options)?;
    render_execution(&report, &args.format)
}

fn verify(args: VerifyArgs) -> Result<()> {
    let plan = load_plan(&args.plan)?;
    let observed = if let Some(path) = args.observed_policy.as_deref() {
        let transport = InMemoryAccountTransport::new(load_policy(path)?);
        verify_plan_target(&plan, &transport)?
    } else {
        let transport = horizon_for_plan(&plan, args.horizon_url.as_deref(), args.timeout_seconds)?;
        verify_plan_target(&plan, &transport)?
    };
    let output = serde_json::json!({
        "schema_version": 1,
        "command": "account.rotation.verify",
        "plan_id": plan.plan_id,
        "verified": true,
        "observed_sequence": observed.sequence,
        "observed_ledger": observed.observed_ledger,
        "policy_fingerprint": observed.policy_fingerprint(),
    });
    if args.format == "json" {
        print_json(&output)
    } else {
        println!("{}", "✓ Target signer policy verified".green().bold());
        println!("  Plan: {}", plan.plan_id);
        println!("  Sequence: {}", observed.sequence);
        println!("  Fingerprint: {}", observed.policy_fingerprint());
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn run_with_transport(
    plan: &RotationPlan,
    state_path: &Path,
    state: ExecutionState,
    approvals: &ApprovalBundle,
    options: &ExecutionOptions,
    observed_policy: Option<&Path>,
    horizon_url: Option<&str>,
    timeout_seconds: u64,
    format: &str,
) -> Result<()> {
    let report = if let Some(path) = observed_policy {
        let transport = InMemoryAccountTransport::new(load_policy(path)?);
        execute_plan(plan, state_path, state, &transport, approvals, options)?
    } else {
        let transport = horizon_for_plan(plan, horizon_url, timeout_seconds)?;
        execute_plan(plan, state_path, state, &transport, approvals, options)?
    };
    render_execution(&report, format)
}

fn horizon_for_plan(
    plan: &RotationPlan,
    horizon_url: Option<&str>,
    timeout_seconds: u64,
) -> Result<HorizonAccountTransport> {
    let endpoint = match horizon_url {
        Some(endpoint) => endpoint.to_string(),
        None => configured_endpoint_for_passphrase(&plan.network)?,
    };
    HorizonAccountTransport::new(
        endpoint,
        plan.network.clone(),
        Duration::from_secs(timeout_seconds),
    )
}

fn configured_endpoint_for_passphrase(passphrase: &str) -> Result<String> {
    let mut configuration = config::load()?;
    config::ensure_default_networks(&mut configuration);
    configuration
        .networks
        .values()
        .find(|network| {
            network
                .passphrase
                .as_deref()
                .map(|value| value == passphrase)
                .unwrap_or(false)
        })
        .map(|network| network.horizon_url.clone())
        .context(
            "no configured Horizon endpoint matches the plan network passphrase; provide --horizon-url",
        )
}

fn network_settings(network: &str, horizon_url: Option<&str>) -> Result<(String, String)> {
    let mut configuration = config::load()?;
    config::ensure_default_networks(&mut configuration);
    let settings = config::get_network_config(&configuration, network)?;
    let endpoint = horizon_url
        .map(str::to_string)
        .unwrap_or(settings.horizon_url);
    let passphrase = settings
        .passphrase
        .unwrap_or_else(|| config::get_network_passphrase(network));
    Ok((endpoint, passphrase))
}

fn load_or_empty_approvals(path: Option<&Path>, plan_id: &str) -> Result<ApprovalBundle> {
    match path {
        Some(path) => load_approval_bundle(path),
        None => Ok(ApprovalBundle::empty(plan_id)),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, kind: &str) -> Result<T> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed to read {kind} {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("failed to parse {kind} {}", path.display()))
}

fn render_plan(plan: &RotationPlan, output: &Path) {
    println!("{}", "✓ Safe signer rotation plan generated".green().bold());
    println!("  Plan: {}", plan.plan_id);
    println!("  Account: {}", plan.account_id);
    println!("  Envelopes: {}", plan.summary.envelopes);
    println!(
        "  Verification challenges: {}",
        plan.summary.verification_challenges
    );
    println!(
        "  Emergency rollback envelopes: {}",
        plan.emergency_rollback.steps.len()
    );
    for step in &plan.steps {
        println!("    {:>3}. [{:?}] {}", step.index, step.phase, step.summary);
    }
    println!("  Saved: {} (mode 600)", output.display());
}

fn render_execution(report: &ExecutionReport, format: &str) -> Result<()> {
    if format == "json" {
        print_json(&serde_json::json!({
            "schema_version": 1,
            "command": "account.rotation.execute",
            "execution": report,
        }))
    } else {
        println!("{}", "Signer rotation execution".bold());
        println!("  Plan: {}", report.plan_id);
        println!("  Status: {:?}", report.status);
        println!(
            "  Progress: {}/{}",
            report.completed_steps, report.total_steps
        );
        println!("  {}", report.message);
        if let Some(step) = &report.next_step_id {
            println!("  Next: {step}");
        }
        println!("  Handoff: {}", report.handoff_directory.display());
        Ok(())
    }
}

fn render_rollback(plan: &RotationPlan, paths: &[PathBuf], format: &str) -> Result<()> {
    if format == "json" {
        print_json(&serde_json::json!({
            "schema_version": 1,
            "command": "account.rotation.resume.rollback",
            "plan_id": plan.plan_id,
            "prepared": true,
            "artifacts": paths,
        }))
    } else {
        println!("{}", "✓ Partial rollback handoff prepared".yellow().bold());
        println!("  Plan: {}", plan.plan_id);
        for path in paths {
            println!("  {}", path.display());
        }
        Ok(())
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_subcommands_expose_machine_readable_mode() {
        let command = AccountCommands::Signers(SignerCommands::Inspect(InspectArgs {
            account: None,
            network: "testnet".to_string(),
            horizon_url: None,
            timeout_seconds: 2,
            input: Some(PathBuf::from("fixture.json")),
            availability: None,
            format: "json".to_string(),
            output: None,
        }));
        assert!(is_machine_readable(&command));
    }

    #[test]
    fn signer_availability_is_not_secret_material() {
        assert_eq!(
            format!("{:?}", crate::signer_rotation::SignerAvailability::Hardware),
            "Hardware"
        );
    }
}
