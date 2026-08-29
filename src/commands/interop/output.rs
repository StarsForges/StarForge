//! Human and JSON rendering for interoperability reports.

use crate::interop::domain::*;
use crate::utils::print as p;
use anyhow::Result;
use colored::Colorize;
use std::io::Write;

pub fn render_discovery(snapshot: &ConfigSnapshot, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(snapshot)?);
        return Ok(());
    }
    p::header("Configuration Discovery");
    p::kv("Source", &snapshot.source.to_string());
    p::kv("Root", &snapshot.root_path.display().to_string());
    p::kv("Networks", &snapshot.network_count().to_string());
    p::kv("Identities", &snapshot.identity_count().to_string());
    p::kv(
        "Contract aliases",
        &snapshot.contract_alias_count().to_string(),
    );
    p::kv("Fingerprint", &snapshot.aggregate_fingerprint);
    if !snapshot.warnings.is_empty() {
        println!();
        p::header("Warnings");
        for warning in &snapshot.warnings {
            p::warn(&format!("[{}] {}", warning.code, warning.message));
        }
    }
    Ok(())
}

pub fn render_diff(report: &DiffReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    p::header("Configuration Diff");
    p::kv("Source", &report.source.to_string());
    p::kv("Target", &report.target.to_string());
    p::kv("Direction", &format!("{:?}", report.direction));
    p::kv("Precedence", &format!("{:?}", report.precedence));
    p::kv("Dry run", &report.dry_run.to_string());
    println!();
    p::header("Summary");
    p::kv("Total entries", &report.summary.total.to_string());
    p::kv("Equivalent", &report.summary.equivalent.to_string());
    p::kv(
        "Missing in target",
        &report.summary.missing_in_target.to_string(),
    );
    p::kv(
        "Missing in source",
        &report.summary.missing_in_source.to_string(),
    );
    p::kv("Mismatches", &report.summary.mismatches.to_string());
    p::kv("Blocking", &report.summary.blocking.to_string());
    if !report.entries.is_empty() {
        println!();
        p::header("Entries");
        for entry in &report.entries {
            let icon = if entry.blocking {
                "✗".red()
            } else if entry.kind == ConflictKind::Equivalent {
                "✓".green()
            } else {
                "•".yellow()
            };
            println!(
                "  {} [{:?}] {} — {}",
                icon, entry.kind, entry.name, entry.message
            );
        }
    }
    Ok(())
}

pub fn render_sync(report: &SyncReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    render_diff(&report.diff, "human")?;
    println!();
    p::header("Sync Actions");
    for action in &report.actions {
        let status = if action.success {
            "ok".green()
        } else {
            "fail".red()
        };
        println!(
            "  {} [{:?}] {} — {}",
            status, action.action, action.name, action.message
        );
    }
    Ok(())
}

pub fn render_doctor(report: &DoctorReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    p::header("Stellar CLI Interoperability Doctor");
    p::kv("Overall", &format!("{:?}", report.overall));
    p::kv(
        "StarForge root",
        &report.starforge_root.display().to_string(),
    );
    p::kv(
        "Stellar CLI root",
        &report.stellar_cli_root.display().to_string(),
    );
    println!();
    for finding in &report.findings {
        let label = match finding.severity {
            DoctorSeverity::Ok => "OK".green(),
            DoctorSeverity::Info => "INFO".cyan(),
            DoctorSeverity::Warning => "WARN".yellow(),
            DoctorSeverity::Error => "ERROR".red(),
        };
        println!("  [{}] {} — {}", label, finding.code, finding.message);
        println!("      → {}", finding.remediation);
    }
    Ok(())
}

pub fn render_export(
    bundle: &InteropExportBundle,
    format: &str,
    output: Option<&std::path::Path>,
) -> Result<()> {
    let json = serde_json::to_string_pretty(bundle)?;
    if let Some(path) = output {
        crate::signer_rotation::write_private_text_atomic(path, &json)?;
        if format != "json" {
            eprintln!("Exported interoperability bundle to {}", path.display());
        }
    } else {
        stdout_write_json(&json)?;
    }
    Ok(())
}

fn stdout_write_json(json: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes())?;
    stdout.write_all(b"\n")?;
    Ok(())
}
