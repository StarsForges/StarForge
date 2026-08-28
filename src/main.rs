#![allow(
    dead_code,
    clippy::needless_range_loop,
    clippy::redundant_closure,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_lazy_evaluations
)]

mod commands;
pub use starforge::{compatibility, plugins};
mod signer_rotation;
mod utils;

use anyhow::Context;
use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(
    name = "starforge",
    about = "⚡ Stellar & Soroban developer productivity CLI",
    long_about = "starforge is an open-source CLI toolkit for developers building on the Stellar network.\nManage wallets, deploy Soroban contracts, and scaffold new projects — all from your terminal.",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Suppress the ASCII banner and decorative output
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Log output format: human (default) or json
    #[arg(long, global = true, default_value = "human", value_parser = ["human", "json"])]
    log_format: String,

    /// Directory to write rotating log files into (optional)
    #[arg(long, global = true)]
    log_dir: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect and safely migrate on-chain account signer policies
    #[command(subcommand)]
    Account(commands::account::AccountCommands),
    /// Manage test wallets (create, list, fund, show, remove)
    #[command(subcommand)]
    Wallet(commands::wallet::WalletCommands),
    /// Generate Soroban project boilerplate
    #[command(subcommand)]
    New(commands::new::NewCommands),
    /// Contract operations (invoke, inspect, etc.)
    #[command(subcommand)]
    Contract(commands::contract::ContractCommands),
    /// Deep contract storage inspection (state, key, storage)
    #[command(subcommand)]
    Inspect(commands::inspect::InspectCommands),
    /// Deploy a compiled Soroban contract (.wasm)
    Deploy(commands::deploy::DeployArgs),
    /// Show starforge config and environment info
    Info,
    /// Manage starforge configuration (telemetry, network)
    #[command(subcommand)]
    Config(commands::config::ConfigCommands),

    /// Coordinate M-of-N multisig ceremonies as a portable file (start/sign/status/submit)
    #[command(subcommand)]
    Multisig(commands::multisig_ceremony::MultisigCommands),

    /// Manage telemetry collection
    #[command(subcommand)]
    Telemetry(commands::telemetry::TelemetryCommands),

    /// Resumable CSV batch payouts (airdrops, contributor payments)
    Batch(commands::batch::BatchArgs),

    Tx(commands::tx::TxArgs), // fetch transaction for the account

    /// View or switch the active network (testnet/mainnet)
    #[command(subcommand)]
    Network(commands::network::NetworkCommands),
    /// Local Soroban devnet (Docker quickstart)
    #[command(subcommand)]
    Node(commands::node::NodeCommands),
    /// Generate shell completions for bash, zsh, and fish
    Completions(commands::completions::CompletionArgs),

    /// Interactive REPL for local Soroban contract testing
    Shell(commands::shell::ShellArgs),

    /// Live monitoring (contract events or wallet threshold)
    Monitor(commands::monitor::MonitorArgs),

    /// Interactive CLI tutorials
    #[command(subcommand)]
    Tutorial(commands::tutorial::TutorialCommands),

    /// Performance benchmarking utilities
    Benchmark(commands::benchmark::BenchmarkArgs),

    /// Contract testing utilities for Soroban wasm
    Test(commands::test::TestArgs),

    /// Gas analysis and optimization helpers
    #[command(subcommand)]
    Gas(commands::gas::GasCommands),

    /// Manage third-party plugins
    #[command(subcommand)]
    Plugin(commands::plugin::PluginCommands),
    /// Manage community contract templates from the marketplace
    #[command(subcommand)]
    Template(commands::template::TemplateCommands),

    /// Contract upgrade management (propose, approve, execute, rollback)
    #[command(subcommand)]
    Upgrade(commands::upgrade::UpgradeCommands),

    /// Static analysis and linting for Soroban contracts
    Lint(commands::lint::LintArgs),

    /// Run connectivity diagnostics for attached Ledger/Trezor devices
    Diagnostics(commands::diagnostics::DiagnosticsArgs),

    /// AI-powered development assistance for Soroban contracts
    Ai(commands::ai::AiArgs),

    /// Regulatory compliance checking for Soroban contracts (profiles, checks, evidence, waivers)
    #[command(subcommand)]
    Compliance(commands::compliance::ComplianceCommands),

    /// AI-assisted cost estimation and economic analysis for Soroban operations
    #[command(subcommand)]
    Cost(commands::cost::CostCommands),

    /// Automated documentation generation and knowledge base for Soroban contracts
    #[command(subcommand)]
    Docs(commands::docs::DocsCommands),

    /// Enforceable transaction fee and Soroban resource budgets
    #[command(subcommand)]
    Budget(commands::budget::BudgetCommands),

    /// Ask natural-language questions about public Soroban contract data
    #[command(subcommand)]
    Query(commands::query::QueryCommands),

    /// AI-assisted performance profiling and optimization for Soroban contracts
    #[command(subcommand)]
    Profile(commands::profile::ProfileCommands),

    /// Real-time AI anomaly detection for Soroban contract monitoring
    #[command(subcommand)]
    Anomaly(commands::anomaly::AnomalyCommands),

    /// Audit Stellar protocol, Soroban RPC, XDR, and project compatibility
    #[command(subcommand)]
    Compatibility(commands::compatibility::CompatibilityCommands),

    /// Execute an installed plugin command (e.g. `starforge defi ...`)
    #[command(external_subcommand)]
    External(Vec<String>),
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "__run_plugin_library" {
        if let Err(e) = plugins::loader::run_plugin_library_internal(&args[2..]) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    if args.len() > 1 && args[1] == "__dump_plugin_metadata" {
        if args.len() < 3 {
            eprintln!("Error: Missing plugin library path");
            std::process::exit(1);
        }
        if let Err(e) = plugins::loader::dump_plugin_metadata_internal(&args[2]) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let cli = Cli::parse();
    let machine_readable = matches!(
        &cli.command,
        Commands::Upgrade(commands::upgrade::UpgradeCommands::Analyze(args))
            if args.format == "json"
    ) || matches!(&cli.command, Commands::Account(cmd) if commands::account::is_machine_readable(cmd))
        || matches!(&cli.command, Commands::Query(cmd) if commands::query::is_machine_readable(cmd))
        || matches!(&cli.command, Commands::Ai(args) if args.is_machine_readable());

    // Initialise structured logging before anything else runs.
    let log_cfg =
        utils::logging::config_from_env(Some(cli.log_format.as_str()), cli.log_dir.clone());
    if let Err(e) = utils::logging::init(log_cfg) {
        eprintln!("Warning: failed to initialise logger: {}", e);
    }

    if !cli.quiet && !machine_readable {
        print_banner();
    }

    // On first run after a schema version change, re-display the telemetry notice.
    if !cli.quiet && !machine_readable {
        if let Ok(true) = utils::telemetry::schema_version_changed() {
            eprintln!(
                "\n  {} Telemetry schema updated to v{}. starforge stores only: \
                 schema_version, timestamp, command, duration_ms, success, anonymous_id. \
                 No code, keys, or personal data. Run `starforge telemetry show` to audit \
                 or `starforge telemetry disable` to opt out.\n",
                "ℹ".cyan(),
                utils::telemetry::TELEMETRY_SCHEMA_VERSION,
            );
        }
    }

    let command_name = match &cli.command {
        Commands::Account(_) => "account",
        Commands::Wallet(_) => "wallet",
        Commands::New(_) => "new",
        Commands::Contract(_) => "contract",
        Commands::Inspect(_) => "inspect",
        Commands::Deploy(_) => "deploy",
        Commands::Info => "info",
        Commands::Config(_) => "config",
        Commands::Multisig(_) => "multisig",
        Commands::Telemetry(_) => "telemetry",
        Commands::Batch(_) => "batch",
        Commands::Tx(_) => "tx",
        Commands::Network(_) => "network",
        Commands::Node(_) => "node",
        Commands::Completions(_) => "completions",
        Commands::Shell(_) => "shell",
        Commands::Monitor(_) => "monitor",
        Commands::Tutorial(_) => "tutorial",
        Commands::Benchmark(_) => "benchmark",
        Commands::Test(_) => "test",
        Commands::Gas(_) => "gas",
        Commands::Plugin(_) => "plugin",
        Commands::Template(_) => "template",
        Commands::Upgrade(_) => "upgrade",
        Commands::Lint(_) => "lint",
        Commands::Diagnostics(_) => "diagnostics",
        Commands::Ai(_) => "ai",
        Commands::Compliance(_) => "compliance",
        Commands::Cost(_) => "cost",
        Commands::Docs(_) => "docs",
        Commands::Budget(_) => "budget",
        Commands::Query(_) => "query",
        Commands::Profile(_) => "profile",
        Commands::Anomaly(_) => "anomaly",
        Commands::Compatibility(_) => "compatibility",
        Commands::External(_) => "external",
    }
    .to_string();

    let start = std::time::Instant::now();
    let result = match cli.command {
        Commands::Account(cmd) => commands::account::handle(cmd),
        Commands::Wallet(cmd) => commands::wallet::handle(cmd),
        Commands::New(cmd) => commands::new::handle(cmd),
        Commands::Contract(cmd) => commands::contract::handle(cmd),
        Commands::Inspect(cmd) => commands::inspect::handle(cmd),
        Commands::Deploy(args) => commands::deploy::handle(args),
        Commands::Info => commands::info::handle(),
        Commands::Config(cmd) => commands::config::handle(cmd),
        Commands::Multisig(cmd) => commands::multisig_ceremony::handle(cmd),
        Commands::Telemetry(cmd) => commands::telemetry::handle(cmd),
        Commands::Batch(args) => commands::batch::handle(args),
        Commands::Tx(args) => commands::tx::handle(args),
        Commands::Network(cmd) => commands::network::handle(cmd),
        Commands::Node(cmd) => commands::node::handle(cmd),
        Commands::Completions(shell) => commands::completions::handle(shell),
        Commands::Shell(args) => commands::shell::handle(args),
        Commands::Monitor(args) => commands::monitor::handle(args),
        Commands::Tutorial(cmd) => commands::tutorial::handle(cmd),
        Commands::Benchmark(args) => commands::benchmark::handle(args),
        Commands::Test(args) => commands::test::handle(args),
        Commands::Gas(args) => commands::gas::handle(args),
        Commands::Plugin(args) => commands::plugin::handle(args),
        Commands::Template(args) => commands::template::handle(args),
        Commands::Upgrade(cmd) => commands::upgrade::handle(cmd),
        Commands::Lint(args) => commands::lint::handle(args),
        Commands::Diagnostics(args) => commands::diagnostics::handle(args),
        Commands::Ai(args) => tokio::runtime::Runtime::new()
            .context("Failed to create async runtime")
            .and_then(|rt| rt.block_on(commands::ai::handle(args))),
        Commands::Compliance(cmd) => commands::compliance::handle(cmd),
        Commands::Cost(cmd) => tokio::runtime::Runtime::new()
            .context("Failed to create async runtime")
            .and_then(|rt| rt.block_on(commands::cost::handle(cmd))),
        Commands::Docs(cmd) => commands::docs::handle(cmd),
        Commands::Budget(cmd) => commands::budget::handle(cmd),
        Commands::Query(cmd) => commands::query::handle(cmd),
        Commands::Profile(cmd) => tokio::runtime::Runtime::new()
            .context("Failed to create async runtime")
            .and_then(|rt| rt.block_on(commands::profile::handle(cmd))),
        Commands::Anomaly(cmd) => tokio::runtime::Runtime::new()
            .context("Failed to create async runtime")
            .and_then(|rt| rt.block_on(commands::anomaly::handle(cmd))),
        Commands::Compatibility(cmd) => commands::compatibility::handle(cmd),
        Commands::External(args) => handle_external_plugin(args),
    };
    let duration = start.elapsed();

    let _ = utils::telemetry::track_event(
        &command_name,
        serde_json::json!({
            "success": result.is_ok(),
            "duration_ms": duration.as_millis(),
        }),
    );

    if let Err(e) = result {
        eprintln!("\n  {} {}\n", "✗ Error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn handle_external_plugin(args: Vec<String>) -> anyhow::Result<()> {
    use anyhow::Context;

    if args.is_empty() {
        anyhow::bail!("No plugin command provided");
    }

    let plugin_name = &args[0];
    let plugin_args = &args[1..];

    let reg = plugins::registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        anyhow::bail!("No plugins registered. Use: starforge plugin install <name> --path <lib>");
    }

    // Check if the command matches any registered plugin command before loading .so files.
    let all_commands = plugins::registry::load_all_registered_commands();
    let known = all_commands.iter().any(|c| c.name == *plugin_name);

    if !known {
        let available: Vec<String> = all_commands
            .iter()
            .map(|c| format!("  • {}", c.name))
            .collect();
        let hint = if available.is_empty() {
            "No plugin commands registered. Re-install plugins to discover their commands."
                .to_string()
        } else {
            format!("Available plugin commands:\n{}", available.join("\n"))
        };
        anyhow::bail!("Unknown command '{}'.\n\n{}", plugin_name, hint);
    }

    let target_plugin = reg
        .plugins
        .iter()
        .find(|p| p.commands.iter().any(|c| c.name == *plugin_name))
        .ok_or_else(|| anyhow::anyhow!("Plugin command '{}' not found in registry", plugin_name))?;

    // Elevate Unknown plugins to blocked status
    if target_plugin.trust == plugins::registry::TrustLevel::Unknown {
        anyhow::bail!(
            "Execution blocked: plugin '{}' is from an untrusted source ({})",
            target_plugin.name,
            target_plugin.source
        );
    }

    let config = utils::config::load().unwrap_or_default();
    if config.plugin_trust.require_approval {
        let actual_hash =
            plugins::loader::calculate_sha256(std::path::Path::new(&target_plugin.path))
                .context("Failed to calculate plugin content hash")?;
        if target_plugin.content_hash.as_ref() != Some(&actual_hash) {
            anyhow::bail!(
                "Execution blocked: plugin '{}' content hash mismatch or not approved.\n\
                 Expected (approved): {:?}\n\
                 Actual             : {}",
                target_plugin.name,
                target_plugin.content_hash,
                actual_hash
            );
        }
    }

    let caps_str = if target_plugin.capabilities.is_empty() {
        "none".to_string()
    } else {
        target_plugin
            .capabilities
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .join(",")
    };

    let status = std::process::Command::new(std::env::current_exe()?)
        .arg("__run_plugin_library")
        .arg(&target_plugin.path)
        .arg(&target_plugin.name)
        .arg(&caps_str)
        .arg("--")
        .args(plugin_args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run plugin subprocess")?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        "\n  ███████╗████████╗ █████╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗\n  ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝\n  ███████╗   ██║   ███████║██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  \n  ╚════██║   ██║   ██╔══██║██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  \n  ███████║   ██║   ██║  ██║██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗\n  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝\n"
        .cyan().bold()
    );
    println!(
        "  {} {}\n",
        "⚡ Stellar & Soroban Developer CLI".bright_white(),
        "v0.1.0".dimmed()
    );
}
