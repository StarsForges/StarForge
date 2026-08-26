//! Natural-language interface for safe Soroban contract analysis.
//!
//! Planning and execution are separate: every operation can be reviewed as a
//! versioned JSON artifact. AI output is untrusted and passes through the same
//! validator as locally generated or loaded plans.

pub mod executor;
pub mod model;
pub mod output;
pub mod parser;
pub mod provider;
pub mod safety;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use model::QueryPlan;
use output::OutputFormat;
use provider::PlanProvider;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum QueryCommands {
    /// Ask a question, show its plan, and execute read-only analysis
    Ask(AskArgs),
    /// Preview a deterministic or AI-assisted query plan without executing it
    Plan(PlanArgs),
    /// Execute a previously reviewed versioned query-plan JSON file
    Execute(ExecuteArgs),
}

#[derive(Args)]
pub struct AskArgs {
    /// Natural-language question about public Soroban state, events, or transactions
    pub question: String,
    /// Configured Stellar network
    #[arg(long, default_value = "testnet")]
    pub network: String,
    /// Use AI interpretation with deterministic fallback
    #[arg(long)]
    pub ai: bool,
    /// AI model name
    #[arg(long, default_value = "gpt-4")]
    pub model: String,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Save the answer and linked evidence to this file
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file
    #[arg(long, requires = "output")]
    pub overwrite: bool,
    /// Print planned operations without contacting Soroban RPC
    #[arg(long)]
    pub dry_run: bool,
    /// Override configured Soroban RPC URL (HTTPS or localhost only)
    #[arg(long, hide = true)]
    pub rpc_url: Option<String>,
}

#[derive(Args)]
pub struct PlanArgs {
    /// Natural-language question to interpret
    pub question: String,
    /// Configured Stellar network
    #[arg(long, default_value = "testnet")]
    pub network: String,
    /// Use AI interpretation with deterministic fallback
    #[arg(long)]
    pub ai: bool,
    /// AI model name
    #[arg(long, default_value = "gpt-4")]
    pub model: String,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Save the plan for later `query execute`
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file
    #[arg(long, requires = "output")]
    pub overwrite: bool,
}

#[derive(Args)]
pub struct ExecuteArgs {
    /// Path to a versioned query-plan JSON file
    pub plan_file: PathBuf,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Save the answer and linked evidence to this file
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file
    #[arg(long, requires = "output")]
    pub overwrite: bool,
    /// Print loaded plan without contacting Soroban RPC
    #[arg(long)]
    pub dry_run: bool,
    /// Override configured Soroban RPC URL (HTTPS or localhost only)
    #[arg(long, hide = true)]
    pub rpc_url: Option<String>,
}

pub fn handle(command: QueryCommands) -> Result<()> {
    match command {
        QueryCommands::Ask(args) => ask(args),
        QueryCommands::Plan(args) => preview(args),
        QueryCommands::Execute(args) => execute_file(args),
    }
}

pub fn is_machine_readable(command: &QueryCommands) -> bool {
    match command {
        QueryCommands::Ask(args) => args.format == "json",
        QueryCommands::Plan(args) => args.format == "json",
        QueryCommands::Execute(args) => args.format == "json",
    }
}

fn ask(args: AskArgs) -> Result<()> {
    let format = OutputFormat::parse(&args.format)?;
    let plan = create_plan(&args.question, &args.network, args.ai, &args.model)?;
    if args.dry_run {
        return emit(
            output::render_plan(&plan, format)?,
            args.output.as_deref(),
            args.overwrite,
        );
    }
    run_plan(
        plan,
        format,
        args.output,
        args.overwrite,
        args.rpc_url.as_deref(),
    )
}

fn preview(args: PlanArgs) -> Result<()> {
    let format = OutputFormat::parse(&args.format)?;
    let plan = create_plan(&args.question, &args.network, args.ai, &args.model)?;
    emit(
        output::render_plan(&plan, format)?,
        args.output.as_deref(),
        args.overwrite,
    )
}

fn execute_file(args: ExecuteArgs) -> Result<()> {
    let format = OutputFormat::parse(&args.format)?;
    let content = fs::read_to_string(&args.plan_file)
        .with_context(|| format!("Failed to read query plan {}", args.plan_file.display()))?;
    let plan: QueryPlan = serde_json::from_str(&content).with_context(|| {
        format!(
            "Query plan {} is not valid versioned JSON",
            args.plan_file.display()
        )
    })?;
    safety::validate_plan(&plan).map_err(|error| {
        anyhow::anyhow!(
            "Query plan {} is unsafe or incompatible: {error:#}",
            args.plan_file.display()
        )
    })?;
    if args.dry_run {
        return emit(
            output::render_plan(&plan, format)?,
            args.output.as_deref(),
            args.overwrite,
        );
    }
    run_plan(
        plan,
        format,
        args.output,
        args.overwrite,
        args.rpc_url.as_deref(),
    )
}

fn create_plan(question: &str, network: &str, ai: bool, model: &str) -> Result<QueryPlan> {
    if ai {
        match provider::HttpAiProvider::from_env(Some(model)) {
            Ok(provider) => provider::plan_with_fallback(question, network, &provider),
            Err(error) => {
                struct UnavailableProvider(String);
                impl PlanProvider for UnavailableProvider {
                    fn create_plan(&self, _question: &str, _network: &str) -> Result<QueryPlan> {
                        anyhow::bail!(self.0.clone())
                    }
                }
                provider::plan_with_fallback(
                    question,
                    network,
                    &UnavailableProvider(error.to_string()),
                )
            }
        }
    } else {
        parser::plan(question, network)
    }
}

fn run_plan(
    plan: QueryPlan,
    format: OutputFormat,
    output_path: Option<PathBuf>,
    overwrite: bool,
    rpc_url: Option<&str>,
) -> Result<()> {
    if format == OutputFormat::Human {
        println!("{}", output::render_plan(&plan, format)?);
    }
    let transport = executor::HttpRpcTransport::for_network(&plan.network, rpc_url)?;
    let report = executor::execute(plan, &transport)?;
    emit(
        output::render_report(&report, format)?,
        output_path.as_deref(),
        overwrite,
    )
}

fn emit(contents: String, path: Option<&std::path::Path>, overwrite: bool) -> Result<()> {
    match path {
        Some(path) => {
            output::write_private(path, &contents, overwrite)?;
            eprintln!("Saved query artifact to {}", display_safe_path(path));
        }
        None => println!("{}", contents),
    }
    Ok(())
}

fn display_safe_path(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("[output file]")
        .to_string()
}
