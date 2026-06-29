use crate::utils::{config, print as p, telemetry};
use anyhow::Result;
use clap::Subcommand;
use colored::*;

#[derive(Subcommand)]
pub enum TelemetryCommands {
    /// Enable telemetry collection
    Enable,
    /// Disable telemetry collection
    Disable,
    /// Show current telemetry status and log stats
    Status,
    /// Pretty-print the last N telemetry events
    Show {
        /// Number of recent events to display (default: 20)
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Wipe the telemetry log
    Clear {
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

pub fn handle(cmd: TelemetryCommands) -> Result<()> {
    match cmd {
        TelemetryCommands::Enable => {
            telemetry::set_telemetry_enabled(true)?;
            p::success("Telemetry collection enabled.");
        }
        TelemetryCommands::Disable => {
            telemetry::set_telemetry_enabled(false)?;
            p::success("Telemetry collection disabled.");
        }
        TelemetryCommands::Status => handle_status()?,
        TelemetryCommands::Show { limit } => handle_show(limit)?,
        TelemetryCommands::Clear { yes } => handle_clear(yes)?,
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

fn handle_status() -> Result<()> {
    let cfg = config::load()?;
    let enabled = cfg.telemetry_enabled.unwrap_or(true);
    let env_override = std::env::var("STARFORGE_TELEMETRY").ok();
    let count = telemetry::event_count()?;
    let size = telemetry::log_size_bytes()?;

    p::header("Telemetry Status");
    p::separator();
    p::kv(
        "Collection",
        if enabled { "enabled" } else { "disabled" },
    );
    p::kv("Schema Version", &telemetry::TELEMETRY_SCHEMA_VERSION.to_string());
    p::kv("Events Stored", &count.to_string());
    p::kv("Log Size", &format!("{:.1} KB", size as f64 / 1024.0));
    p::kv(
        "Limits",
        &format!(
            "{} entries / 5 MB",
            telemetry::MAX_ENTRIES
        ),
    );
    if let Some(val) = env_override {
        p::kv("Env Override (STARFORGE_TELEMETRY)", &val);
    }
    p::separator();
    p::info("Use `starforge telemetry show` to inspect stored events.");
    p::info("Use `starforge telemetry clear` to wipe the log.");
    Ok(())
}

fn handle_show(limit: usize) -> Result<()> {
    let events = telemetry::read_events(limit)?;

    if events.is_empty() {
        p::info("No telemetry events recorded yet.");
        return Ok(());
    }

    p::header(&format!("Last {} Telemetry Events", events.len()));
    p::separator();
    println!(
        "  {:<26}  {:<18}  {:<8}  {:<6}  {}",
        "Timestamp (UTC)".dimmed(),
        "Command".dimmed(),
        "Duration".dimmed(),
        "Status".dimmed(),
        "Schema".dimmed(),
    );
    println!("  {}", "─".repeat(72).dimmed());

    for ev in &events {
        let ts = ev
            .timestamp
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let status = if ev.success {
            "✓ ok".green().to_string()
        } else {
            "✗ fail".red().to_string()
        };
        let duration = format!("{}ms", ev.duration_ms);

        println!(
            "  {:<26}  {:<18}  {:<8}  {:<6}  v{}",
            ts.dimmed(),
            ev.command.cyan(),
            duration.white(),
            status,
            ev.schema_version,
        );
    }

    println!("  {}", "─".repeat(72).dimmed());
    println!(
        "\n  {} {} total events stored. Use {} to see more.\n",
        "ℹ".cyan(),
        telemetry::event_count()?.to_string().white(),
        "--limit N".cyan(),
    );
    Ok(())
}

fn handle_clear(yes: bool) -> Result<()> {
    let count = telemetry::event_count()?;

    if count == 0 {
        p::info("Telemetry log is already empty.");
        return Ok(());
    }

    if !yes {
        println!();
        print!(
            "  This will delete {} telemetry events. Proceed? [y/N] ",
            count
        );
        use std::io::BufRead;
        let line = std::io::stdin()
            .lock()
            .lines()
            .next()
            .unwrap_or(Ok(String::new()))?;
        if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
            p::info("Clear cancelled.");
            return Ok(());
        }
    }

    telemetry::clear_log()?;
    p::success(&format!("Telemetry log cleared ({} events removed).", count));
    Ok(())
}
