//! `starforge ai recovery` — AI-assisted disaster recovery and backup for Soroban contracts.

pub mod ai_client;
pub mod backup;
pub mod crypto;
pub mod inventory;
pub mod migrations;
pub mod model;
pub mod persistence;
pub mod report;
pub mod restore_sim;
pub mod scorer;
pub mod verify;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;

use crate::commands::ai::impact::redactor::redact_text;
use model::{validate_policy, BackupPolicy, RiskLevel};

// ── CLI surface ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum RecoveryCommands {
    /// Inventory artifacts and compute a risk-scored recovery plan.
    Plan {
        /// Write a default backup policy file if none exists.
        #[arg(long)]
        init_policy: bool,
        /// Network name from StarForge config.
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Output format: human or json.
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
        /// Write the recovery plan to this file.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Skip AI provider call; use offline heuristics only.
        #[arg(long)]
        deterministic: bool,
        /// AI model to use.
        #[arg(long, default_value = "gpt-4")]
        model: String,
        /// Exit non-zero if risk level meets or exceeds this level.
        #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
        fail_on: Option<String>,
    },
    /// Create a versioned, encrypted backup of contract artifacts.
    Backup {
        /// Network name from StarForge config.
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Print what would be backed up without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Output format: human or json.
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
        /// Skip confirmation prompts.
        #[arg(long)]
        yes: bool,
    },
    /// Verify integrity of backup archives.
    Verify {
        /// Verify only this specific archive file.
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Exit non-zero if any archive fails verification.
        #[arg(long)]
        fail_on_any: bool,
        /// Output format: human or json.
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },
    /// Simulate a full restore without writing any files.
    RestoreDryRun {
        /// Simulate restore from this specific archive.
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Output format: human or json.
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
        /// Treat validation warnings as failures.
        #[arg(long)]
        fail_on_warning: bool,
    },
    /// Generate a structured recovery report.
    Report {
        /// Output format: markdown or json.
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
        /// Write the report to this file.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Skip AI provider call.
        #[arg(long)]
        deterministic: bool,
        /// AI model to use.
        #[arg(long, default_value = "gpt-4")]
        model: String,
    },
}

/// Top-level entry point — routes to the appropriate subcommand handler.
pub async fn handle(cmd: RecoveryCommands) -> Result<()> {
    match cmd {
        RecoveryCommands::Plan {
            init_policy,
            network,
            format,
            output,
            deterministic,
            model,
            fail_on,
        } => {
            cmd_plan(
                init_policy,
                &network,
                &format,
                output.as_deref(),
                deterministic,
                &model,
                fail_on.as_deref(),
            )
            .await
        }
        RecoveryCommands::Backup {
            network: _,
            dry_run,
            format,
            yes,
        } => cmd_backup(dry_run, &format, yes).await,
        RecoveryCommands::Verify {
            archive,
            fail_on_any,
            format,
        } => cmd_verify(archive.as_deref(), fail_on_any, &format),
        RecoveryCommands::RestoreDryRun {
            archive,
            format,
            fail_on_warning,
        } => cmd_restore_dry_run(archive.as_deref(), &format, fail_on_warning),
        RecoveryCommands::Report {
            format,
            output,
            deterministic,
            model,
        } => cmd_report(&format, output.as_deref(), deterministic, &model).await,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn starforge_home() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".starforge")
}

fn backup_store(home: &Path) -> PathBuf {
    home.join("data").join("recovery").join("backups")
}

fn latest_archive(store: &Path) -> Option<PathBuf> {
    let Ok(entries) = std::fs::read_dir(store) else {
        return None;
    };
    let mut archives: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".tar.gz"))
                .unwrap_or(false)
        })
        .collect();
    archives.sort();
    archives.into_iter().last()
}

fn risk_level_from_str(s: &str) -> RiskLevel {
    match s {
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Low,
    }
}

// ── plan ──────────────────────────────────────────────────────────────────────

async fn cmd_plan(
    init_policy: bool,
    network: &str,
    format: &str,
    output: Option<&Path>,
    deterministic: bool,
    model: &str,
    fail_on: Option<&str>,
) -> Result<()> {
    let home = starforge_home();

    if init_policy && persistence::load_policy(&home)?.is_none() {
        persistence::save_policy(&home, &BackupPolicy::default())
            .context("Failed to write default policy")?;
        if format != "json" {
            eprintln!("Wrote default backup policy to ~/.starforge/data/recovery/policy.json");
        }
    }

    let policy = persistence::load_policy(&home)?.unwrap_or_default();
    validate_policy(&policy)?;

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if format != "json" {
        eprintln!("Scanning artifacts...");
    }
    let artifacts = inventory::scan(&project_root, &home).context("Artifact inventory failed")?;

    let store = backup_store(&home);
    let last_backup_ts = latest_archive(&store).and_then(|p| {
        p.metadata().ok().and_then(|m| m.modified().ok()).map(|t| {
            let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                .unwrap_or_else(chrono::Utc::now)
        })
    });

    let (risk_score, risk_level, risk_factors) =
        scorer::score_offline(&artifacts, &policy, last_backup_ts);

    let mut ai_narrative: Option<String> = None;
    if !deterministic {
        if let Ok(api_key) =
            std::env::var("OPENAI_API_KEY").or_else(|_| std::env::var("STARFORGE_AI_API_KEY"))
        {
            let client = async_openai::Client::with_config(
                async_openai::config::OpenAIConfig::new().with_api_key(api_key),
            );
            match ai_client::request_narrative(
                &client,
                &model::RecoveryPlan {
                    schema_version: 1,
                    generated_at: chrono::Utc::now(),
                    network: network.to_string(),
                    artifacts: artifacts.clone(),
                    risk_score,
                    risk_level: risk_level.clone(),
                    risk_factors: risk_factors.clone(),
                    ai_narrative: None,
                },
                model,
            )
            .await
            {
                Ok(n) => ai_narrative = Some(n),
                Err(e) => eprintln!(
                    "warning: AI scoring unavailable: {}",
                    redact_text(&e.to_string())
                ),
            }
        }
    }

    let plan = model::RecoveryPlan {
        schema_version: 1,
        generated_at: chrono::Utc::now(),
        network: network.to_string(),
        artifacts,
        risk_score,
        risk_level: risk_level.clone(),
        risk_factors,
        ai_narrative,
    };

    persistence::save_plan(&home, &plan).context("Failed to save recovery plan")?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("Recovery Plan");
        println!("  Network:     {}", plan.network);
        println!("  Artifacts:   {}", plan.artifacts.len());
        println!(
            "  Risk Score:  {} ({})",
            plan.risk_score,
            plan.risk_level.as_str()
        );
        for f in &plan.risk_factors {
            println!("    - {} (+{})", f.description, f.points);
        }
        if let Some(ref n) = plan.ai_narrative {
            println!("\nAI Analysis:\n{}", n);
        }
    }

    if let Some(out_path) = output {
        let bytes = serde_json::to_vec_pretty(&plan)?;
        std::fs::write(out_path, &bytes)
            .with_context(|| format!("Failed to write plan to {}", out_path.display()))?;
        println!("Plan written to {}", out_path.display());
    }

    if let Some(level_str) = fail_on {
        let threshold = risk_level_from_str(level_str);
        if risk_level >= threshold {
            eprintln!(
                "Risk level '{}' meets or exceeds threshold '{}'",
                risk_level.as_str(),
                level_str
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

// ── backup ────────────────────────────────────────────────────────────────────

async fn cmd_backup(dry_run: bool, format: &str, yes: bool) -> Result<()> {
    let home = starforge_home();
    let policy = persistence::load_policy(&home)?.unwrap_or_default();
    validate_policy(&policy)?;

    if !yes && !dry_run && policy.encryption == model::EncryptionMode::None {
        eprintln!("warning: encryption is disabled. The backup will contain sensitive metadata in plain text.");
        eprintln!("Pass --yes to confirm, or set encryption to aes-256-gcm in the policy.");
    }

    let passphrase = crypto::passphrase_from_env_or_prompt()?;
    let store = backup_store(&home);
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let artifacts = inventory::scan(&project_root, &home).context("Artifact inventory failed")?;

    let result = backup::run_backup(&artifacts, &policy, &store, &passphrase, dry_run)
        .context("Backup failed")?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if !dry_run {
        println!("Backup complete");
        println!("  Archive:   {}", result.archive_path);
        println!("  Artifacts: {}", result.artifact_count);
        println!("  Size:      {} bytes", result.size_bytes);
        println!("  Digest:    {}", result.integrity_digest);
    }

    Ok(())
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(archive: Option<&Path>, fail_on_any: bool, format: &str) -> Result<()> {
    let home = starforge_home();
    let store = backup_store(&home);
    let passphrase = std::env::var("STARFORGE_RECOVERY_PASSPHRASE").ok();
    let pass = passphrase.as_deref();

    let results = if let Some(a) = archive {
        vec![verify::verify_one(a, pass).context("Verify failed")?]
    } else {
        verify::verify_all(&store, pass).context("Verify failed")?
    };

    persistence::save_verify_results(&home, &results).context("Failed to save verify results")?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for r in &results {
            println!("[{}] {}", r.status_str(), r.archive_path);
        }
    }

    if fail_on_any && results.iter().any(|r| r.status != model::VerifyStatus::Ok) {
        std::process::exit(1);
    }

    Ok(())
}

// ── restore-dry-run ───────────────────────────────────────────────────────────

fn cmd_restore_dry_run(archive: Option<&Path>, format: &str, fail_on_warning: bool) -> Result<()> {
    let home = starforge_home();
    let store = backup_store(&home);
    let passphrase = std::env::var("STARFORGE_RECOVERY_PASSPHRASE").ok();
    let pass = passphrase.as_deref();

    let archive_path: PathBuf = if let Some(a) = archive {
        a.to_path_buf()
    } else {
        latest_archive(&store)
            .ok_or_else(|| anyhow::anyhow!("No backup archives found in {}", store.display()))?
    };

    let sim = restore_sim::simulate(&archive_path, pass).context("Restore simulation failed")?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&sim)?);
    } else {
        println!(
            "Restore Dry-Run: {}",
            if sim.simulation_passed {
                "PASSED"
            } else {
                "FAILED"
            }
        );
        println!("  Archive:    {}", sim.archive_path);
        println!("  Artifacts:  {}", sim.artifact_count);
        println!("  Est. time:  {}ms", sim.simulated_restore_duration_ms);
        for v in &sim.validation_results {
            if !v.passed {
                println!("  FAIL [{}]: {}", v.artifact_id, v.issues.join("; "));
            }
        }
    }

    let should_fail = !sim.simulation_passed
        || (fail_on_warning && sim.validation_results.iter().any(|v| !v.issues.is_empty()));

    if should_fail {
        std::process::exit(1);
    }

    Ok(())
}

// ── report ────────────────────────────────────────────────────────────────────

async fn cmd_report(
    format: &str,
    output: Option<&Path>,
    deterministic: bool,
    model: &str,
) -> Result<()> {
    let home = starforge_home();

    let plan = persistence::load_plan(&home)?.ok_or_else(|| {
        anyhow::anyhow!("No recovery plan found. Run `starforge ai recovery plan` first.")
    })?;

    let verify_results = persistence::load_verify_results(&home)?;

    let mut ai_narrative: Option<String> = None;
    if !deterministic {
        if let Ok(api_key) =
            std::env::var("OPENAI_API_KEY").or_else(|_| std::env::var("STARFORGE_AI_API_KEY"))
        {
            let client = async_openai::Client::with_config(
                async_openai::config::OpenAIConfig::new().with_api_key(api_key),
            );
            let tmp_report = report::build(&plan, verify_results.as_deref(), None);
            match ai_client::request_remediation(&client, &tmp_report, model).await {
                Ok(n) => ai_narrative = Some(n),
                Err(e) => eprintln!(
                    "warning: AI narrative unavailable: {}",
                    redact_text(&e.to_string())
                ),
            }
        }
    }

    let recovery_report = report::build(&plan, verify_results.as_deref(), ai_narrative.as_deref());

    let artifact_count = recovery_report.plan.artifacts.len();
    let recommendation_count = recovery_report.recommendations.len();
    let risk_level = recovery_report.plan.risk_level.as_str().to_string();
    let ai_used = ai_narrative.is_some();

    let rendered = if format == "json" {
        report::to_json(&recovery_report)?
    } else {
        report::to_markdown(&recovery_report)
    };

    if let Some(out_path) = output {
        std::fs::write(out_path, &rendered)
            .with_context(|| format!("Failed to write report to {}", out_path.display()))?;
        println!("Report written to {}", out_path.display());
    } else {
        println!("{}", rendered);
    }

    // Telemetry
    let _ = crate::utils::ai_telemetry::track_ai_event(crate::utils::ai_telemetry::AiCallOutcome {
        provider: "recovery",
        model,
        feature: "recovery_report",
        input_tokens: artifact_count as u32,
        output_tokens: recommendation_count as u32,
        duration_ms: 0,
        success: true,
        error_type: None,
    });
    let _ = (risk_level, ai_used); // suppress unused warnings

    Ok(())
}
