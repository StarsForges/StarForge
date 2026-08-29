//! `starforge interop stellar` subcommands.

use crate::commands::interop::output;
use crate::interop::domain::*;
use crate::interop::stellar::StellarInteropEngine;
use anyhow::Result;
use clap::{Args, Subcommand};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum StellarInteropCommands {
    /// Discover StarForge and Stellar CLI configuration without modifying files
    Discover(DiscoverArgs),
    /// Dry-run diff between configuration stores with conflict classification
    Diff(DiffArgs),
    /// Import Stellar CLI configuration into StarForge
    Import(SyncArgs),
    /// Export StarForge configuration to Stellar CLI layout
    Export(ExportArgs),
    /// Synchronize configuration bidirectionally with explicit precedence
    Sync(SyncArgs),
    /// Run interoperability health checks and permission validation
    Doctor(DoctorArgs),
}

#[derive(Args)]
pub struct DiscoverArgs {
    /// Stellar CLI config directory override
    #[arg(long)]
    pub stellar_config_dir: Option<PathBuf>,
    /// Include legacy ~/.config/soroban paths
    #[arg(long, default_value = "true")]
    pub include_legacy: bool,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Which store to report: starforge, stellar, or both
    #[arg(long, default_value = "both", value_parser = ["starforge", "stellar", "both"])]
    pub target: String,
}

#[derive(Args)]
pub struct DiffArgs {
    #[command(flatten)]
    pub common: CommonInteropArgs,
    /// Sync direction used to orient source/target in the diff
    #[arg(long, default_value = "import", value_parser = ["import", "export", "bidirectional"])]
    pub direction: String,
}

#[derive(Args)]
pub struct SyncArgs {
    #[command(flatten)]
    pub common: CommonInteropArgs,
    /// Apply changes (default is dry-run)
    #[arg(long)]
    pub apply: bool,
    /// Confirm overwrites of existing Stellar CLI files on export
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Sync direction
    #[arg(long, default_value = "import", value_parser = ["import", "export", "bidirectional"])]
    pub direction: String,
}

#[derive(Args)]
pub struct ExportArgs {
    #[command(flatten)]
    pub common: CommonInteropArgs,
    /// Export bundle destination (stdout when omitted)
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Configuration source to export
    #[arg(long, default_value = "starforge", value_parser = ["starforge", "stellar"])]
    pub source: String,
    /// Redact secrets from exported bundle
    #[arg(long, default_value = "true")]
    pub redact: bool,
}

#[derive(Args)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub common: CommonInteropArgs,
}

#[derive(Args)]
pub struct CommonInteropArgs {
    /// Stellar CLI config directory override
    #[arg(long)]
    pub stellar_config_dir: Option<PathBuf>,
    /// Include legacy ~/.config/soroban paths during discovery
    #[arg(long, default_value = "true")]
    pub include_legacy: bool,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Conflict resolution policy
    #[arg(long, default_value = "fail_on_conflict", value_parser = [
        "starforge_wins", "stellar_cli_wins", "newest_fingerprint", "additive_only", "fail_on_conflict"
    ])]
    pub precedence: String,
    /// Include secret key migration (requires secure permissions)
    #[arg(long)]
    pub include_secrets: bool,
    /// Limit to categories (repeatable): network, identity, contract_alias
    #[arg(long, value_parser = ["network", "identity", "contract_alias"])]
    pub category: Vec<String>,
    /// Limit to specific record names
    #[arg(long)]
    pub name: Vec<String>,
}

pub fn is_machine_readable(cmd: &StellarInteropCommands) -> bool {
    match cmd {
        StellarInteropCommands::Discover(args) => args.format == "json",
        StellarInteropCommands::Diff(args) => args.common.format == "json",
        StellarInteropCommands::Import(args) => args.common.format == "json",
        StellarInteropCommands::Export(args) => args.common.format == "json",
        StellarInteropCommands::Sync(args) => args.common.format == "json",
        StellarInteropCommands::Doctor(args) => args.common.format == "json",
    }
}

pub fn handle(cmd: StellarInteropCommands) -> Result<()> {
    match cmd {
        StellarInteropCommands::Discover(args) => discover(args),
        StellarInteropCommands::Diff(args) => diff(args),
        StellarInteropCommands::Import(args) => sync(args, SyncDirection::ImportToStarforge),
        StellarInteropCommands::Export(args) => export_bundle(args),
        StellarInteropCommands::Sync(args) => {
            let direction = parse_direction(&args.direction)?;
            sync(args, direction)
        }
        StellarInteropCommands::Doctor(args) => doctor(args),
    }
}

fn discover(args: DiscoverArgs) -> Result<()> {
    let engine = build_engine(&CommonInteropArgs {
        stellar_config_dir: args.stellar_config_dir,
        include_legacy: args.include_legacy,
        format: args.format.clone(),
        precedence: "fail_on_conflict".into(),
        include_secrets: false,
        category: vec![],
        name: vec![],
    });
    let (starforge, stellar) = engine.discover_all()?;
    match args.target.as_str() {
        "starforge" => output::render_discovery(&starforge, &args.format)?,
        "stellar" => output::render_discovery(&stellar, &args.format)?,
        "both" => {
            if args.format == "json" {
                let combined = serde_json::json!({
                    "schema_version": INTEROP_SCHEMA_VERSION,
                    "starforge": starforge,
                    "stellar_cli": stellar,
                });
                println!("{}", serde_json::to_string_pretty(&combined)?);
            } else {
                output::render_discovery(&starforge, "human")?;
                println!();
                output::render_discovery(&stellar, "human")?;
            }
        }
        other => anyhow::bail!("unknown discover target '{other}'"),
    }
    Ok(())
}

fn diff(args: DiffArgs) -> Result<()> {
    let direction = parse_direction(&args.direction)?;
    let mut engine = build_engine(&args.common);
    engine.sync.direction = direction;
    engine.sync.dry_run = true;
    let report = engine.diff()?;
    output::render_diff(&report, &args.common.format)?;
    if report.has_blocking_conflicts() {
        std::process::exit(2);
    }
    Ok(())
}

fn sync(args: SyncArgs, direction: SyncDirection) -> Result<()> {
    let mut engine = build_engine(&args.common);
    engine.sync.direction = direction;
    engine.sync.dry_run = !args.apply;
    engine.sync.confirm_overwrites = args.yes;
    let report = engine.sync()?;
    output::render_sync(&report, &args.common.format)?;
    if report
        .actions
        .iter()
        .any(|a| !a.success && a.action == SyncAction::Rejected)
    {
        std::process::exit(2);
    }
    Ok(())
}

fn export_bundle(args: ExportArgs) -> Result<()> {
    let engine = build_engine(&args.common);
    let source = match args.source.as_str() {
        "starforge" => ConfigSource::StarForge,
        "stellar" => ConfigSource::StellarCli,
        other => anyhow::bail!("unknown export source '{other}'"),
    };
    let bundle = engine.export(source, args.redact)?;
    output::render_export(&bundle, &args.common.format, args.output.as_deref())?;
    Ok(())
}

fn doctor(args: DoctorArgs) -> Result<()> {
    let engine = build_engine(&args.common);
    let report = engine.doctor()?;
    output::render_doctor(&report, &args.common.format)?;
    if matches!(report.overall, DoctorSeverity::Error) {
        std::process::exit(2);
    }
    Ok(())
}

fn build_engine(common: &CommonInteropArgs) -> StellarInteropEngine {
    let discovery = DiscoveryOptions {
        stellar_config_dir: common.stellar_config_dir.clone(),
        include_legacy_soroban: common.include_legacy,
        follow_symlinks: false,
        max_file_bytes: 1024 * 1024,
    };
    let categories = parse_categories(&common.category);
    let mut names = BTreeSet::new();
    for name in &common.name {
        names.insert(name.to_ascii_lowercase());
    }
    let sync = SyncOptions {
        direction: SyncDirection::ImportToStarforge,
        precedence: parse_precedence(&common.precedence),
        dry_run: true,
        include_secrets: common.include_secrets,
        categories,
        names,
        require_secure_permissions: true,
        confirm_overwrites: false,
    };
    StellarInteropEngine::default()
        .with_discovery(discovery)
        .with_sync(sync)
}

fn parse_direction(value: &str) -> Result<SyncDirection> {
    match value {
        "import" => Ok(SyncDirection::ImportToStarforge),
        "export" => Ok(SyncDirection::ExportToStellarCli),
        "bidirectional" => Ok(SyncDirection::Bidirectional),
        other => anyhow::bail!("unknown direction '{other}'"),
    }
}

fn parse_precedence(value: &str) -> PrecedencePolicy {
    match value {
        "starforge_wins" => PrecedencePolicy::StarforgeWins,
        "stellar_cli_wins" => PrecedencePolicy::StellarCliWins,
        "newest_fingerprint" => PrecedencePolicy::NewestFingerprint,
        "additive_only" => PrecedencePolicy::AdditiveOnly,
        _ => PrecedencePolicy::FailOnConflict,
    }
}

fn parse_categories(values: &[String]) -> BTreeSet<DiffCategory> {
    if values.is_empty() {
        return [
            DiffCategory::Network,
            DiffCategory::Identity,
            DiffCategory::ContractAlias,
        ]
        .into_iter()
        .collect();
    }
    values
        .iter()
        .filter_map(|v| match v.as_str() {
            "network" => Some(DiffCategory::Network),
            "identity" => Some(DiffCategory::Identity),
            "contract_alias" => Some(DiffCategory::ContractAlias),
            _ => None,
        })
        .collect()
}
