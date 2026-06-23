#![allow(
    dead_code,
    clippy::needless_range_loop,
    clippy::redundant_closure,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_lazy_evaluations
)]

mod commands;
pub use starforge::plugins;
mod utils;

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

    /// Manage telemetry collection
    #[command(subcommand)]
    Telemetry(commands::telemetry::TelemetryCommands),

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

    /// Execute an installed plugin command (e.g. `starforge defi ...`)
    #[command(external_subcommand)]
    External(Vec<String>),
}

fn main() {
    let cli = Cli::parse();

    // Initialise structured logging before anything else runs.
    let log_cfg =
        utils::logging::config_from_env(Some(cli.log_format.as_str()), cli.log_dir.clone());
    if let Err(e) = utils::logging::init(log_cfg) {
        eprintln!("Warning: failed to initialise logger: {}", e);
    }

    if !cli.quiet {
        print_banner();
    }

    let command_name = match &cli.command {
        Commands::Wallet(_) => "wallet",
        Commands::New(_) => "new",
        Commands::Contract(_) => "contract",
        Commands::Inspect(_) => "inspect",
        Commands::Deploy(_) => "deploy",
        Commands::Info => "info",
        Commands::Config(_) => "config",
        Commands::Telemetry(_) => "telemetry",
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
        Commands::External(_) => "external",
    }
    .to_string();

    let start = std::time::Instant::now();
    let result = match cli.command {
        Commands::Wallet(cmd) => commands::wallet::handle(cmd),
        Commands::New(cmd) => commands::new::handle(cmd),
        Commands::Contract(cmd) => commands::contract::handle(cmd),
        Commands::Inspect(cmd) => commands::inspect::handle(cmd),
        Commands::Deploy(args) => commands::deploy::handle(args),
        Commands::Info => commands::info::handle(),
        Commands::Config(cmd) => commands::config::handle(cmd),
        Commands::Telemetry(cmd) => commands::telemetry::handle(cmd),
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
    use plugins::registry::TrustLevel;

    if args.is_empty() {
        anyhow::bail!("No plugin command provided");
    }

    let plugin_name = &args[0];
    let plugin_args = &args[1..];

    let reg = plugins::registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        anyhow::bail!(
            "Unknown command '{}'. No plugins installed.\n\nTry: starforge plugin install <name> --path <lib>",
            plugin_name
        );
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

    // Warn about unknown-trust plugins before loading.
    for pl in reg.plugins.iter().filter(|p| {
        plugins::registry::classify_source(&p.source) == TrustLevel::Unknown && !p.source.is_empty()
    }) {
        eprintln!(
            "  ⚠  Warning: plugin '{}' is from an untrusted source: {}",
            pl.name, pl.source
        );
    }

    let mut pm = plugins::PluginManager::new();
    for pl in &reg.plugins {
        unsafe {
            pm.load_plugin(&pl.path)
                .with_context(|| format!("Failed to load plugin '{}' from {}", pl.name, pl.path))?;
        }
    }

    pm.execute(plugin_name, plugin_args)
        .map_err(|e| anyhow::anyhow!(e))
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
