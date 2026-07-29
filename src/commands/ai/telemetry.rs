use crate::utils::{ai_telemetry, config, print as p};
use anyhow::Result;
use clap::Subcommand;
use colored::*;

#[derive(Subcommand)]
pub enum AiTelemetryCommands {
    /// Enable AI usage telemetry collection
    Enable,
    /// Disable AI usage telemetry collection
    Disable,
    /// Show current AI telemetry status and log stats
    Status,
    /// Pretty-print the last N AI usage events
    Show {
        /// Number of recent events to display (default: 20)
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Show a cost and usage report across all stored events
    Cost,
    /// Wipe the AI telemetry log
    Clear {
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

pub fn handle(cmd: AiTelemetryCommands) -> Result<()> {
    match cmd {
        AiTelemetryCommands::Enable => {
            ai_telemetry::set_ai_telemetry_enabled(true)?;
            p::success("AI telemetry collection enabled.");
        }
        AiTelemetryCommands::Disable => {
            ai_telemetry::set_ai_telemetry_enabled(false)?;
            p::success("AI telemetry collection disabled.");
        }
        AiTelemetryCommands::Status => handle_status()?,
        AiTelemetryCommands::Show { limit } => handle_show(limit)?,
        AiTelemetryCommands::Cost => handle_cost()?,
        AiTelemetryCommands::Clear { yes } => handle_clear(yes)?,
    }
    Ok(())
}

fn handle_status() -> Result<()> {
    let cfg = config::load()?;
    let enabled = cfg.ai_telemetry_enabled.unwrap_or(true);
    let env_override = std::env::var("STARFORGE_AI_TELEMETRY").ok();
    let count = ai_telemetry::event_count()?;
    let size = ai_telemetry::log_size_bytes()?;

    p::header("AI Telemetry Status");
    p::separator();
    p::kv("Collection", if enabled { "enabled" } else { "disabled" });
    p::kv(
        "Schema Version",
        &ai_telemetry::AI_TELEMETRY_SCHEMA_VERSION.to_string(),
    );
    p::kv("Events Stored", &count.to_string());
    p::kv("Log Size", &format!("{:.1} KB", size as f64 / 1024.0));
    p::kv(
        "Limits",
        &format!("{} entries / 5 MB", ai_telemetry::MAX_ENTRIES),
    );
    if let Some(val) = env_override {
        p::kv("Env Override (STARFORGE_AI_TELEMETRY)", &val);
    }
    p::separator();
    p::info("Stores per-call: provider, model, feature, token counts, duration, success, estimated cost.");
    p::info("No prompts, generated code, or file contents are ever recorded.");
    p::info("Use `starforge ai telemetry show` to inspect stored events.");
    p::info("Use `starforge ai telemetry cost` for a usage/cost report.");
    p::info("Use `starforge ai telemetry disable` to opt out.");
    Ok(())
}

fn handle_show(limit: usize) -> Result<()> {
    let events = ai_telemetry::read_events(limit)?;

    if events.is_empty() {
        p::info("No AI telemetry events recorded yet.");
        return Ok(());
    }

    p::header(&format!("Last {} AI Usage Events", events.len()));
    p::separator();
    println!(
        "  {:<20}  {:<14}  {:<16}  {:<12}  {:<8}  {:<6}  {}",
        "Timestamp (UTC)".dimmed(),
        "Feature".dimmed(),
        "Model".dimmed(),
        "Tokens".dimmed(),
        "Latency".dimmed(),
        "Status".dimmed(),
        "Cost".dimmed(),
    );
    println!("  {}", "─".repeat(90).dimmed());

    for ev in &events {
        let ts = ev.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let status = if ev.success {
            "✓ ok".green().to_string()
        } else {
            "✗ fail".red().to_string()
        };
        let tokens = format!("{}in/{}out", ev.input_tokens, ev.output_tokens);
        let latency = format!("{}ms", ev.duration_ms);
        let cost = format!("${:.4}", ev.estimated_cost_usd);

        println!(
            "  {:<20}  {:<14}  {:<16}  {:<12}  {:<8}  {:<6}  {}",
            ts.dimmed(),
            ev.feature.cyan(),
            ev.model.white(),
            tokens.white(),
            latency.white(),
            status,
            cost.yellow(),
        );
    }

    println!("  {}", "─".repeat(90).dimmed());
    println!(
        "\n  {} {} total events stored. Use {} to see more.\n",
        "ℹ".cyan(),
        ai_telemetry::event_count()?.to_string().white(),
        "--limit N".cyan(),
    );
    Ok(())
}

fn handle_cost() -> Result<()> {
    let events = ai_telemetry::read_all_events()?;
    if events.is_empty() {
        p::info("No AI telemetry events recorded yet.");
        return Ok(());
    }

    let summary = ai_telemetry::summarize(&events);

    p::header("AI Usage & Cost Report");
    p::separator();
    p::kv("Total Calls", &summary.total_calls.to_string());
    p::kv(
        "Success Rate",
        &format!(
            "{:.1}% ({} ok / {} failed)",
            if summary.total_calls > 0 {
                summary.successful_calls as f64 / summary.total_calls as f64 * 100.0
            } else {
                0.0
            },
            summary.successful_calls,
            summary.failed_calls,
        ),
    );
    p::kv(
        "Total Tokens",
        &format!(
            "{} in / {} out",
            summary.total_input_tokens, summary.total_output_tokens
        ),
    );
    p::kv_accent(
        "Estimated Total Cost",
        &format!("${:.4}", summary.total_cost_usd),
    );
    p::kv(
        "Latency (p50/p95/p99)",
        &format!(
            "{}ms / {}ms / {}ms",
            summary.latency_p50_ms, summary.latency_p95_ms, summary.latency_p99_ms
        ),
    );

    println!();
    p::header("By Feature");
    for (feature, count) in &summary.by_feature {
        p::kv(feature, &count.to_string());
    }

    println!();
    p::header("By Model");
    for (model, count) in &summary.by_model {
        p::kv(model, &count.to_string());
    }

    if !summary.error_types.is_empty() {
        println!();
        p::header("Errors By Type");
        for (err, count) in &summary.error_types {
            p::kv(err, &count.to_string());
        }
    }

    p::separator();
    p::info("Cost estimates use static per-model list pricing and are approximate.");
    Ok(())
}

fn handle_clear(yes: bool) -> Result<()> {
    let count = ai_telemetry::event_count()?;

    if count == 0 {
        p::info("AI telemetry log is already empty.");
        return Ok(());
    }

    if !yes {
        println!();
        print!(
            "  This will delete {} AI telemetry events. Proceed? [y/N] ",
            count
        );
        use std::io::{BufRead, Write};
        std::io::stdout().flush()?;
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

    ai_telemetry::clear_log()?;
    p::success(&format!(
        "AI telemetry log cleared ({} events removed).",
        count
    ));
    Ok(())
}
