//! `starforge compliance` — configurable regulatory-compliance checking for
//! Soroban contracts (issue #49 / AI-016).
//!
//! The built-in control catalog (`starforge compliance profile show`) is an
//! illustrative baseline for teams to adapt — not legal advice, and not an
//! authoritative interpretation of any jurisdiction's law.

use crate::utils::compliance::{
    ai_assist::{self, OpenAiExplainer},
    evidence::{self, EvidenceRecord},
    framework,
    metadata::{self, DeploymentMetadata},
    report::ComplianceReport,
    scanner::{self, OperationalContext, WasmFacts},
    waiver::{apply_waivers, FindingOutcome, Waiver},
    ComplianceProfile,
};
use crate::utils::{config, print as p};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use clap::{Args, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ComplianceCommands {
    /// Manage the local compliance profile (enabled jurisdictions, waivers)
    #[command(subcommand)]
    Profile(ProfileCommands),
    /// Run a deterministic compliance check against a contract artifact
    Check(CheckArgs),
    /// Record or list supporting evidence for a control
    #[command(subcommand)]
    Evidence(EvidenceCommands),
    /// Manage waivers for failing or evidence-pending controls
    #[command(subcommand)]
    Waiver(WaiverCommands),
    /// Export an audit-ready compliance report to a file
    #[command(subcommand)]
    Report(ReportCommands),
}

#[derive(Subcommand)]
pub enum ProfileCommands {
    /// Initialize a local compliance profile with the given jurisdictions
    Init {
        /// Jurisdiction/baseline slugs to enable (repeatable). Defaults to `global-baseline`.
        #[arg(long = "jurisdiction")]
        jurisdictions: Vec<String>,
        /// Overwrite an existing profile (waivers on the existing profile are preserved)
        #[arg(long, default_value = "false")]
        force: bool,
    },
    /// Show the current compliance profile and available jurisdictions
    Show,
}

#[derive(Args)]
pub struct CheckArgs {
    /// Path to the compiled Soroban `.wasm` artifact (omit to skip wasm-based checks)
    #[arg(long)]
    pub wasm: Option<PathBuf>,
    /// Path to a deployment metadata TOML file describing signer/operational policy
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Attach an AI-assisted plain-language explanation to each non-passing
    /// finding. Additive only — never changes a finding's status. Requires
    /// OPENAI_API_KEY or STARFORGE_AI_API_KEY.
    #[arg(long, default_value = "false")]
    pub explain: bool,
    /// Model to use for --explain
    #[arg(long, default_value = "gpt-4")]
    pub model: String,
    /// Include full, unredacted secret-shaped values in JSON output
    #[arg(long, default_value = "false")]
    pub reveal_secrets: bool,
}

#[derive(Subcommand)]
pub enum EvidenceCommands {
    /// Record supporting evidence for a control
    Record {
        /// Control ID this evidence supports (e.g. AC-1)
        #[arg(long)]
        control: String,
        /// Description of the evidence
        #[arg(long)]
        description: String,
        /// Optional path or URL reference to the supporting document
        #[arg(long)]
        file: Option<String>,
        /// Name of the reviewer recording this evidence
        #[arg(long)]
        reviewer: Option<String>,
    },
    /// List recorded evidence
    List {
        /// Filter to a single control ID
        #[arg(long)]
        control: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum WaiverCommands {
    /// Add a time-boxed waiver for a control
    Add {
        /// Control ID this waiver applies to (e.g. AC-1)
        #[arg(long)]
        control: String,
        /// Reason for the waiver
        #[arg(long)]
        reason: String,
        /// Number of days until the waiver expires (omit for no expiry)
        #[arg(long)]
        expires_in_days: Option<i64>,
        /// Name of the person approving this waiver
        #[arg(long)]
        approved_by: Option<String>,
    },
    /// List waivers on the current profile
    List {
        /// Include expired waivers in the listing
        #[arg(long, default_value = "false")]
        include_expired: bool,
    },
    /// Revoke a waiver by ID
    Revoke {
        /// Waiver ID to remove
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ReportCommands {
    /// Run a check and export the resulting report to a file
    Export(ExportArgs),
}

#[derive(Args)]
pub struct ExportArgs {
    /// Path to the compiled Soroban `.wasm` artifact (omit to skip wasm-based checks)
    #[arg(long)]
    pub wasm: Option<PathBuf>,
    /// Path to a deployment metadata TOML file describing signer/operational policy
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Output file path
    #[arg(long)]
    pub output: PathBuf,
    /// Export format
    #[arg(long, default_value = "json", value_parser = ["json", "markdown"])]
    pub format: String,
    /// Include full, unredacted secret-shaped values in the export
    #[arg(long, default_value = "false")]
    pub reveal_secrets: bool,
}

pub fn handle(cmd: ComplianceCommands) -> Result<()> {
    match cmd {
        ComplianceCommands::Profile(cmd) => profile(cmd),
        ComplianceCommands::Check(args) => check(args),
        ComplianceCommands::Evidence(cmd) => evidence_cmd(cmd),
        ComplianceCommands::Waiver(cmd) => waiver_cmd(cmd),
        ComplianceCommands::Report(cmd) => report_cmd(cmd),
    }
}

// ── Profile ──────────────────────────────────────────────────────────────────

fn profile(cmd: ProfileCommands) -> Result<()> {
    match cmd {
        ProfileCommands::Init {
            jurisdictions,
            force,
        } => profile_init(jurisdictions, force),
        ProfileCommands::Show => profile_show(),
    }
}

fn profile_init(jurisdictions: Vec<String>, force: bool) -> Result<()> {
    if crate::utils::compliance::profile_exists() && !force {
        anyhow::bail!(
            "A compliance profile already exists at {}. Use --force to re-initialize (existing waivers are preserved).",
            crate::utils::compliance::profile_path().display()
        );
    }

    let jurisdictions = if jurisdictions.is_empty() {
        vec!["global-baseline".to_string()]
    } else {
        jurisdictions
    };

    let known = framework::jurisdiction_slugs();
    for slug in &jurisdictions {
        if !known.contains(slug) {
            anyhow::bail!(
                "Unknown jurisdiction '{}'. Available: {}",
                slug,
                known.join(", ")
            );
        }
    }

    let existing_waivers = crate::utils::compliance::load_profile()
        .map(|p| p.waivers)
        .unwrap_or_default();

    let profile = ComplianceProfile {
        version: crate::utils::compliance::CURRENT_PROFILE_VERSION.to_string(),
        enabled_jurisdictions: jurisdictions.clone(),
        waivers: existing_waivers,
    };
    crate::utils::compliance::save_profile(&profile)?;

    p::success(&format!(
        "Compliance profile initialized with jurisdiction(s): {}",
        jurisdictions.join(", ")
    ));
    p::info(&format!(
        "Profile saved to {}",
        crate::utils::compliance::profile_path().display()
    ));
    Ok(())
}

fn profile_show() -> Result<()> {
    let profile = crate::utils::compliance::load_profile()?;
    p::header("Compliance Profile");
    p::separator();
    p::kv("Schema version", &profile.version);
    p::kv(
        "Enabled jurisdictions",
        &profile.enabled_jurisdictions.join(", "),
    );
    p::kv(
        "Active waivers",
        &profile
            .waivers
            .iter()
            .filter(|w| w.is_active(Utc::now()))
            .count()
            .to_string(),
    );

    println!();
    p::header("Available Jurisdictions");
    for j in framework::all_jurisdictions() {
        let marker = if profile.enabled_jurisdictions.contains(&j.slug) {
            "✓".green().to_string()
        } else {
            "•".dimmed().to_string()
        };
        println!(
            "  {} {} — {}",
            marker,
            j.slug.cyan().bold(),
            j.summary.dimmed()
        );
    }

    let controls = framework::controls_for_jurisdictions(&profile.enabled_jurisdictions);
    println!();
    p::kv("Controls in scope", &controls.len().to_string());
    p::info("This is a configurable baseline, not legal advice — adapt it with qualified review.");
    Ok(())
}

// ── Check ────────────────────────────────────────────────────────────────────

fn load_wasm_facts(path: Option<&PathBuf>) -> Result<Option<WasmFacts>> {
    let Some(path) = path else { return Ok(None) };
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let facts = scanner::analyze_wasm(&bytes)
        .with_context(|| format!("Failed to analyze wasm at {}", path.display()))?;
    Ok(Some(facts))
}

fn build_report(
    wasm_path: Option<&PathBuf>,
    metadata_path: Option<&PathBuf>,
    explain: bool,
    model: &str,
) -> Result<ComplianceReport> {
    let profile = crate::utils::compliance::load_profile()?;
    let controls = framework::controls_for_jurisdictions(&profile.enabled_jurisdictions);

    let wasm_facts = load_wasm_facts(wasm_path)?;
    let metadata = match metadata_path {
        Some(path) => metadata::load_metadata(path)?,
        None => DeploymentMetadata::default(),
    };

    let telemetry_enabled = config::load()
        .map(|c| c.telemetry_enabled.unwrap_or(false))
        .unwrap_or(false);
    let evidence_records = evidence::load_all()?;
    let now = Utc::now();
    let evidence_recent =
        |control_id: &str| evidence::has_recent_evidence(&evidence_records, control_id, 90, now);

    let ctx = OperationalContext {
        telemetry_enabled,
        evidence_recent: &evidence_recent,
    };

    let findings = scanner::evaluate(&controls, wasm_facts.as_ref(), &metadata, &ctx);
    let outcomes: Vec<FindingOutcome> = apply_waivers(findings, &profile.waivers, now);
    let mut report = ComplianceReport::new(profile.enabled_jurisdictions.clone(), outcomes);

    if explain {
        let explainer = OpenAiExplainer::from_env(model)?;
        let findings_for_explain: Vec<_> =
            report.outcomes.iter().map(|o| o.finding.clone()).collect();
        let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
        report.ai_explanations = rt.block_on(ai_assist::explain_findings(
            &explainer,
            &findings_for_explain,
        ))?;
    }

    Ok(report)
}

fn check(args: CheckArgs) -> Result<()> {
    let report = build_report(
        args.wasm.as_ref(),
        args.metadata.as_ref(),
        args.explain,
        &args.model,
    )?;

    if args.format == "json" {
        if args.reveal_secrets {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("{}", report.to_json_redacted()?);
        }
    } else {
        println!("{}", report.render_human());
    }

    if report.summary.fail > 0 {
        anyhow::bail!(
            "Compliance check found {} failing control(s). See details above.",
            report.summary.fail
        );
    }
    Ok(())
}

// ── Evidence ─────────────────────────────────────────────────────────────────

fn evidence_cmd(cmd: EvidenceCommands) -> Result<()> {
    match cmd {
        EvidenceCommands::Record {
            control,
            description,
            file,
            reviewer,
        } => {
            let entry = EvidenceRecord::new(control.clone(), description, file, reviewer);
            evidence::record(&entry)?;
            p::success(&format!("Evidence recorded for control {}", control));
            Ok(())
        }
        EvidenceCommands::List { control } => {
            let records = evidence::load_all()?;
            let records: Vec<_> = match &control {
                Some(id) => records
                    .into_iter()
                    .filter(|r| &r.control_id == id)
                    .collect(),
                None => records,
            };

            if records.is_empty() {
                p::info("No evidence recorded yet.");
                return Ok(());
            }

            p::header("Compliance Evidence");
            p::separator();
            for record in &records {
                println!(
                    "  {} {} — {}",
                    record.recorded_at.to_rfc3339().dimmed(),
                    record.control_id.cyan().bold(),
                    record.description
                );
                if let Some(reviewer) = &record.reviewer {
                    println!("    reviewer: {}", reviewer.dimmed());
                }
                if let Some(file_ref) = &record.file_reference {
                    println!(
                        "    reference: {}",
                        crate::utils::compliance::redact::redact_home_path(file_ref).dimmed()
                    );
                }
            }
            Ok(())
        }
    }
}

// ── Waivers ──────────────────────────────────────────────────────────────────

fn waiver_cmd(cmd: WaiverCommands) -> Result<()> {
    match cmd {
        WaiverCommands::Add {
            control,
            reason,
            expires_in_days,
            approved_by,
        } => waiver_add(control, reason, expires_in_days, approved_by),
        WaiverCommands::List { include_expired } => waiver_list(include_expired),
        WaiverCommands::Revoke { id } => waiver_revoke(id),
    }
}

fn waiver_add(
    control: String,
    reason: String,
    expires_in_days: Option<i64>,
    approved_by: Option<String>,
) -> Result<()> {
    let known_controls = framework::built_in_controls();
    if framework::find_control(&control, &known_controls).is_none() {
        p::warn(&format!(
            "'{}' is not a built-in control ID. The waiver will still be recorded, in case this is a custom control.",
            control
        ));
    }

    let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));
    let mut waiver = Waiver::new(control.clone(), reason, expires_at);
    waiver.approved_by = approved_by;

    let mut profile = crate::utils::compliance::load_profile()?;
    let waiver_id = waiver.id.clone();
    profile.waivers.push(waiver);
    crate::utils::compliance::save_profile(&profile)?;

    p::success(&format!(
        "Waiver {} added for control {}",
        waiver_id, control
    ));
    Ok(())
}

fn waiver_list(include_expired: bool) -> Result<()> {
    let profile = crate::utils::compliance::load_profile()?;
    let now = Utc::now();
    let waivers: Vec<_> = profile
        .waivers
        .iter()
        .filter(|w| include_expired || w.is_active(now))
        .collect();

    if waivers.is_empty() {
        p::info("No waivers on file.");
        return Ok(());
    }

    p::header("Compliance Waivers");
    p::separator();
    for waiver in waivers {
        let status = if waiver.is_active(now) {
            "active".green().to_string()
        } else {
            "expired".red().to_string()
        };
        println!(
            "  {} {} [{}] — {}",
            waiver.id.dimmed(),
            waiver.control_id.cyan().bold(),
            status,
            waiver.reason
        );
        if let Some(expires_at) = waiver.expires_at {
            println!("    expires: {}", expires_at.to_rfc3339().dimmed());
        }
        if let Some(approved_by) = &waiver.approved_by {
            println!("    approved by: {}", approved_by.dimmed());
        }
    }
    Ok(())
}

fn waiver_revoke(id: String) -> Result<()> {
    let mut profile = crate::utils::compliance::load_profile()?;
    let before = profile.waivers.len();
    profile.waivers.retain(|w| w.id != id);
    if profile.waivers.len() == before {
        anyhow::bail!("No waiver found with ID '{}'", id);
    }
    crate::utils::compliance::save_profile(&profile)?;
    p::success(&format!("Waiver {} revoked", id));
    Ok(())
}

// ── Report export ────────────────────────────────────────────────────────────

fn report_cmd(cmd: ReportCommands) -> Result<()> {
    match cmd {
        ReportCommands::Export(args) => report_export(args),
    }
}

fn report_export(args: ExportArgs) -> Result<()> {
    let report = build_report(args.wasm.as_ref(), args.metadata.as_ref(), false, "gpt-4")?;

    let rendered = match args.format.as_str() {
        "markdown" if args.reveal_secrets => report.render_markdown_unredacted(),
        "markdown" => report.render_markdown(),
        _ if args.reveal_secrets => serde_json::to_string_pretty(&report)?,
        _ => report.to_json_redacted()?,
    };

    std::fs::write(&args.output, rendered)
        .with_context(|| format!("Failed to write report to {}", args.output.display()))?;

    p::success(&format!(
        "Compliance report exported to {}",
        args.output.display()
    ));
    if report.summary.fail > 0 || report.summary.needs_evidence > 0 {
        p::warn(&format!(
            "{} failing and {} needs-evidence control(s) in this report.",
            report.summary.fail, report.summary.needs_evidence
        ));
    }
    Ok(())
}
