//! `starforge token` — SEP-41-style token administration commands.

mod output;

use crate::token::batch::load_manifest;
use crate::token::domain::{ReadOptions, WriteOptions};
use crate::token::engine::TokenEngine;
use crate::token::spec::builtin_test_token_spec;
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum TokenCommands {
    /// Inspect token metadata, capabilities, and supply indicators
    Inspect(InspectArgs),
    /// Read account token balance
    Balance(BalanceArgs),
    /// Read allowance between owner and spender
    Allowance(AllowanceArgs),
    /// Transfer tokens to another account
    Transfer(TransferArgs),
    /// Approve a spender allowance
    Approve(ApproveArgs),
    /// Mint tokens (admin capability required)
    Mint(MintArgs),
    /// Burn tokens from the source account
    Burn(BurnArgs),
    /// Set account authorization flag (when supported)
    Authorize(AuthorizeArgs),
    /// Rotate token admin (when supported)
    Admin(AdminArgs),
    /// Execute a batch manifest of token operations
    Batch(BatchArgs),
}

#[derive(Args)]
pub struct CommonTokenArgs {
    /// Soroban token contract ID
    #[arg(long)]
    pub id: String,
    /// Configured network
    #[arg(long, default_value = "testnet")]
    pub network: String,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Use deterministic mock RPC (CI/offline)
    #[arg(long, hide = true)]
    pub mock: bool,
    /// RPC timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
}

#[derive(Args)]
pub struct InspectArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
}

#[derive(Args)]
pub struct BalanceArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    /// Account public key or wallet name
    pub account: String,
}

#[derive(Args)]
pub struct AllowanceArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    /// Allowance owner public key or wallet name
    pub owner: String,
    /// Spender public key
    pub spender: String,
}

#[derive(Args)]
pub struct TransferArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    #[command(flatten)]
    pub write: WriteControlArgs,
    /// Destination public key or wallet name
    #[arg(long)]
    pub to: String,
    /// Decimal-safe amount (e.g. 10.5)
    #[arg(long)]
    pub amount: String,
}

#[derive(Args)]
pub struct ApproveArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    #[command(flatten)]
    pub write: WriteControlArgs,
    #[arg(long)]
    pub spender: String,
    #[arg(long)]
    pub amount: String,
    #[arg(long)]
    pub expiration_ledger: Option<u32>,
}

#[derive(Args)]
pub struct MintArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    #[command(flatten)]
    pub write: WriteControlArgs,
    #[arg(long)]
    pub to: String,
    #[arg(long)]
    pub amount: String,
}

#[derive(Args)]
pub struct BurnArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    #[command(flatten)]
    pub write: WriteControlArgs,
    #[arg(long)]
    pub amount: String,
}

#[derive(Args)]
pub struct AuthorizeArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    #[command(flatten)]
    pub write: WriteControlArgs,
    #[arg(long)]
    pub account: String,
    #[arg(long)]
    pub authorized: bool,
}

#[derive(Args)]
pub struct AdminArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    #[command(flatten)]
    pub write: WriteControlArgs,
    #[arg(long)]
    pub new_admin: String,
}

#[derive(Args)]
pub struct BatchArgs {
    #[command(flatten)]
    pub common: CommonTokenArgs,
    /// Batch manifest JSON path
    pub manifest: PathBuf,
    /// Submit operations instead of simulate-only (default)
    #[arg(long)]
    pub apply: bool,
}

#[derive(Args)]
pub struct WriteControlArgs {
    /// Source wallet name or public key
    #[arg(long)]
    pub from: String,
    /// Simulate without submitting (default)
    #[arg(long)]
    pub simulate: bool,
    /// Skip confirmation prompts for privileged operations
    #[arg(long, short = 'y')]
    pub yes: bool,
}

pub fn is_machine_readable(cmd: &TokenCommands) -> bool {
    match cmd {
        TokenCommands::Inspect(a) => a.common.format == "json",
        TokenCommands::Balance(a) => a.common.format == "json",
        TokenCommands::Allowance(a) => a.common.format == "json",
        TokenCommands::Transfer(a) => a.common.format == "json",
        TokenCommands::Approve(a) => a.common.format == "json",
        TokenCommands::Mint(a) => a.common.format == "json",
        TokenCommands::Burn(a) => a.common.format == "json",
        TokenCommands::Authorize(a) => a.common.format == "json",
        TokenCommands::Admin(a) => a.common.format == "json",
        TokenCommands::Batch(a) => a.common.format == "json",
    }
}

pub fn handle(cmd: TokenCommands) -> Result<()> {
    match cmd {
        TokenCommands::Inspect(args) => inspect(args),
        TokenCommands::Balance(args) => balance(args),
        TokenCommands::Allowance(args) => allowance(args),
        TokenCommands::Transfer(args) => transfer(args),
        TokenCommands::Approve(args) => approve(args),
        TokenCommands::Mint(args) => mint(args),
        TokenCommands::Burn(args) => burn(args),
        TokenCommands::Authorize(args) => authorize(args),
        TokenCommands::Admin(args) => admin(args),
        TokenCommands::Batch(args) => batch(args),
    }
}

fn engine(common: &CommonTokenArgs) -> TokenEngine {
    if common.mock {
        TokenEngine::mock(builtin_test_token_spec())
    } else {
        TokenEngine::live(common.timeout_ms)
    }
}

fn read_options(common: &CommonTokenArgs) -> ReadOptions {
    ReadOptions {
        network: common.network.clone(),
        contract_id: common.id.clone(),
        timeout_ms: common.timeout_ms,
    }
}

fn write_options(common: &CommonTokenArgs, write: &WriteControlArgs) -> WriteOptions {
    WriteOptions {
        network: common.network.clone(),
        contract_id: common.id.clone(),
        source_wallet: write.from.clone(),
        simulate_only: true,
        yes: write.yes,
        timeout_ms: common.timeout_ms,
        expiration_ledger: None,
    }
}

fn inspect(args: InspectArgs) -> Result<()> {
    let engine = engine(&args.common);
    let report = engine.inspect(&read_options(&args.common))?;
    output::render_inspect(&report, &args.common.format)
}

fn balance(args: BalanceArgs) -> Result<()> {
    let engine = engine(&args.common);
    let inspect = engine.inspect(&read_options(&args.common))?;
    let balance = engine.balance(
        &read_options(&args.common),
        &args.account,
        inspect.metadata.decimals,
    )?;
    output::render_balance(&balance, &args.common.format)
}

fn allowance(args: AllowanceArgs) -> Result<()> {
    let engine = engine(&args.common);
    let inspect = engine.inspect(&read_options(&args.common))?;
    let state = engine.allowance(
        &read_options(&args.common),
        &args.owner,
        &args.spender,
        inspect.metadata.decimals,
    )?;
    output::render_allowance(&state, &args.common.format)
}

fn transfer(args: TransferArgs) -> Result<()> {
    let engine = engine(&args.common);
    let mut opts = write_options(&args.common, &args.write);
    opts.expiration_ledger = None;
    let receipt = engine.transfer(&opts, &args.to, &args.amount)?;
    output::render_receipt(&receipt, &args.common.format)
}

fn approve(args: ApproveArgs) -> Result<()> {
    let engine = engine(&args.common);
    let mut opts = write_options(&args.common, &args.write);
    opts.expiration_ledger = args.expiration_ledger;
    let receipt = engine.approve(&opts, &args.spender, &args.amount)?;
    output::render_receipt(&receipt, &args.common.format)
}

fn mint(args: MintArgs) -> Result<()> {
    let engine = engine(&args.common);
    let opts = write_options(&args.common, &args.write);
    let receipt = engine.mint(&opts, &args.to, &args.amount)?;
    output::render_receipt(&receipt, &args.common.format)
}

fn burn(args: BurnArgs) -> Result<()> {
    let engine = engine(&args.common);
    let opts = write_options(&args.common, &args.write);
    let receipt = engine.burn(&opts, &args.amount)?;
    output::render_receipt(&receipt, &args.common.format)
}

fn authorize(args: AuthorizeArgs) -> Result<()> {
    let engine = engine(&args.common);
    let opts = write_options(&args.common, &args.write);
    let receipt = engine.authorize(&opts, &args.account, args.authorized)?;
    output::render_receipt(&receipt, &args.common.format)
}

fn admin(args: AdminArgs) -> Result<()> {
    let engine = engine(&args.common);
    let opts = write_options(&args.common, &args.write);
    let receipt = engine.admin(&opts, &args.new_admin)?;
    output::render_receipt(&receipt, &args.common.format)
}

fn batch(args: BatchArgs) -> Result<()> {
    let engine = engine(&args.common);
    let manifest = load_manifest(&args.manifest)?;
    let report = engine.execute_batch(&manifest, !args.apply)?;
    output::render_batch(&report, &args.common.format)
}
