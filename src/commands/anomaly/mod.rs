//! Real-time AI anomaly detection for Soroban contract monitoring.
//!
//! Ingests contract events, transaction outcomes, and fee/resource metrics
//! (live via RPC/Horizon, or replayed from fixtures for deterministic
//! testing), evaluates them against a versioned per-contract [`baseline`],
//! and raises [`model::Alert`]s through five detectors in [`detectors`].
//! Alerts persist to deduplicated history in [`alerts`], and can be
//! summarized into an incident report ([`report`]) with an optional
//! AI-generated narrative ([`explain`]) that always falls back to a
//! deterministic explanation.
//!
//! CLI surface: `monitor`, `baseline` (update/show/list/reset), `alert-test`,
//! `export`, and `report`.

pub mod alerts;
pub mod baseline;
pub mod detectors;
pub mod explain;
pub mod ingest;
pub mod migrations;
pub mod model;
pub mod report;

use crate::commands::ai::impact::redactor::redact_text;
use crate::utils::{config, notifications, print as p, stream::EventStreamFilters};
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use model::Severity;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Subcommand)]
pub enum AnomalyCommands {
    /// Evaluate a contract's recent activity for anomalies (single pass, or
    /// continuous with --follow)
    Monitor {
        /// Contract ID to monitor
        #[arg(long)]
        contract: String,
        /// Network to use (overrides config)
        #[arg(long)]
        network: Option<String>,
        /// Replay events from a fixture file instead of polling RPC live
        /// (JSON array of Soroban event objects, e.g. a getEvents `result.events`)
        #[arg(long)]
        events_file: Option<PathBuf>,
        /// Replay transaction outcomes from a fixture file instead of Horizon
        /// (JSON array of Horizon transaction record objects)
        #[arg(long)]
        transactions_file: Option<PathBuf>,
        /// Stream continuously until Ctrl+C (live mode only; incompatible
        /// with --events-file/--transactions-file)
        #[arg(long)]
        follow: bool,
        /// Poll interval in seconds when --follow is set
        #[arg(long, default_value = "10")]
        interval: u64,
        /// Stop after this many windows when --follow is set (mainly for tests)
        #[arg(long)]
        max_iterations: Option<u64>,
        /// Fold this window's metrics into the persisted baseline after evaluating it
        #[arg(long)]
        update_baseline: bool,
        /// Skip persisting detected alerts to history
        #[arg(long)]
        no_persist: bool,
        /// Minimum seconds between repeat alerts for the same condition
        #[arg(long, default_value_t = alerts::DEFAULT_DEDUP_COOLDOWN_SECS)]
        cooldown_secs: i64,
        /// Skip AI narrative generation and use only the deterministic explanation
        #[arg(long)]
        deterministic: bool,
        /// Model to use for the AI narrative (default: gpt-4)
        #[arg(long, default_value = "gpt-4")]
        model: String,
        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
        /// Exit with a non-zero status if any alert meets or exceeds this severity
        #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
        fail_on: Option<String>,
    },

    /// Manage per-contract anomaly baselines
    #[command(subcommand)]
    Baseline(BaselineCommands),

    /// Inject a synthetic observation window to deterministically test
    /// detectors and alerting, without any network access
    AlertTest {
        /// Contract ID the synthetic window belongs to
        #[arg(long)]
        contract: String,
        /// Network to use (overrides config)
        #[arg(long)]
        network: Option<String>,
        /// Path to a JSON WindowMetrics fixture (see
        /// tests/fixtures/anomaly/ for examples)
        #[arg(long)]
        metrics_file: PathBuf,
        /// Persist any resulting alerts to history
        #[arg(long)]
        persist: bool,
        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
        /// Exit with a non-zero status if any alert meets or exceeds this severity
        #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
        fail_on: Option<String>,
    },

    /// Export alert history for a contract as JSON or CSV
    Export {
        #[arg(long)]
        contract: String,
        #[arg(long)]
        network: Option<String>,
        #[arg(long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Generate an incident report from recent alert history
    Report {
        #[arg(long)]
        contract: String,
        #[arg(long)]
        network: Option<String>,
        /// Only include alerts from the last N hours
        #[arg(long, default_value_t = 24)]
        since_hours: i64,
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Skip AI narrative generation and use only the deterministic explanation
        #[arg(long)]
        deterministic: bool,
        #[arg(long, default_value = "gpt-4")]
        model: String,
    },
}

#[derive(Subcommand)]
pub enum BaselineCommands {
    /// Fold one observation window into the persisted baseline
    Update {
        #[arg(long)]
        contract: String,
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        events_file: Option<PathBuf>,
        #[arg(long)]
        transactions_file: Option<PathBuf>,
        /// Discard any existing baseline before folding in this window
        #[arg(long)]
        reset: bool,
    },
    /// Show the current baseline for a contract
    Show {
        #[arg(long)]
        contract: String,
        #[arg(long)]
        network: Option<String>,
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },
    /// List every contract/network pair with a saved baseline
    List {
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },
    /// Delete the baseline for a contract, starting fresh
    Reset {
        #[arg(long)]
        contract: String,
        #[arg(long)]
        network: Option<String>,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

pub async fn handle(cmd: AnomalyCommands) -> Result<()> {
    match cmd {
        AnomalyCommands::Monitor {
            contract,
            network,
            events_file,
            transactions_file,
            follow,
            interval,
            max_iterations,
            update_baseline,
            no_persist,
            cooldown_secs,
            deterministic,
            model,
            format,
            fail_on,
        } => {
            monitor(MonitorArgs {
                contract,
                network,
                events_file,
                transactions_file,
                follow,
                interval,
                max_iterations,
                update_baseline,
                no_persist,
                cooldown_secs,
                deterministic,
                model,
                format,
                fail_on,
            })
            .await
        }
        AnomalyCommands::Baseline(cmd) => handle_baseline(cmd),
        AnomalyCommands::AlertTest {
            contract,
            network,
            metrics_file,
            persist,
            format,
            fail_on,
        } => alert_test(&contract, network, &metrics_file, persist, &format, fail_on),
        AnomalyCommands::Export {
            contract,
            network,
            format,
            output,
        } => export(&contract, network, &format, output),
        AnomalyCommands::Report {
            contract,
            network,
            since_hours,
            format,
            output,
            deterministic,
            model,
        } => {
            report(
                &contract,
                network,
                since_hours,
                &format,
                output,
                deterministic,
                &model,
            )
            .await
        }
    }
}

struct MonitorArgs {
    contract: String,
    network: Option<String>,
    events_file: Option<PathBuf>,
    transactions_file: Option<PathBuf>,
    follow: bool,
    interval: u64,
    max_iterations: Option<u64>,
    update_baseline: bool,
    no_persist: bool,
    cooldown_secs: i64,
    deterministic: bool,
    model: String,
    format: String,
    fail_on: Option<String>,
}

fn resolve_network(network: Option<String>) -> Result<String> {
    let cfg = config::load().unwrap_or_default();
    let network = network.unwrap_or(cfg.network);
    config::validate_network(&network)?;
    Ok(network)
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        _ => Severity::Critical,
    }
}

async fn monitor(args: MonitorArgs) -> Result<()> {
    config::validate_contract_id(&args.contract)?;
    let network = resolve_network(args.network.clone())?;
    let offline = args.events_file.is_some() || args.transactions_file.is_some();
    if args.follow && offline {
        anyhow::bail!(
            "--follow streams live data and cannot be combined with --events-file/--transactions-file"
        );
    }

    if !args.follow {
        return monitor_once(&args, &network).await;
    }

    p::header("Real-Time Anomaly Monitoring");
    p::kv("Contract", &args.contract);
    p::kv("Network", &network);
    println!();

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })?;
    }

    let mut iterations: u64 = 0;
    while running.load(Ordering::SeqCst) {
        if let Err(e) = monitor_once(&args, &network).await {
            notifications::warn(&format!("Monitoring window failed: {}. Retrying…", e));
        }
        iterations += 1;
        if let Some(max) = args.max_iterations {
            if iterations >= max {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(args.interval.max(1)));
    }
    Ok(())
}

async fn monitor_once(args: &MonitorArgs, network: &str) -> Result<()> {
    let window = collect_window(args, network)?;
    let mut current_baseline = baseline::load_or_create(&args.contract, network)?;
    let detected = detectors::detect_all(
        &window,
        &current_baseline,
        &detectors::ThresholdConfig::default(),
    );

    if args.update_baseline {
        current_baseline.observe(&window);
        baseline::save(&current_baseline)?;
    }

    let save_outcomes = if args.no_persist || detected.is_empty() {
        Vec::new()
    } else {
        alerts::save_all(&detected, args.cooldown_secs)?
    };

    let explanation = if args.deterministic || detected.is_empty() {
        explain::deterministic_explanation(&detected)
    } else {
        match explain::maybe_generate_ai_narrative(&detected, &args.model).await {
            Ok(Some(narrative)) => format!(
                "{}\n\n---\n\nAI narrative:\n\n{}",
                explain::deterministic_explanation(&detected),
                narrative
            ),
            Ok(None) => explain::deterministic_explanation(&detected),
            Err(e) => {
                notifications::warn(&format!(
                    "AI narrative generation failed: {}. Falling back to deterministic explanation.",
                    e
                ));
                explain::deterministic_explanation(&detected)
            }
        }
    };

    render_monitor_result(
        &window,
        &detected,
        &save_outcomes,
        &explanation,
        &args.format,
    );

    if let Some(threshold) = args.fail_on.as_deref() {
        let min_severity = parse_severity(threshold);
        if detected.iter().any(|a| a.severity >= min_severity) {
            anyhow::bail!(
                "Detected {} alert(s) at or above severity '{}'",
                detected
                    .iter()
                    .filter(|a| a.severity >= min_severity)
                    .count(),
                threshold
            );
        }
    }
    Ok(())
}

fn collect_window(args: &MonitorArgs, network: &str) -> Result<model::WindowMetrics> {
    if args.events_file.is_some() || args.transactions_file.is_some() {
        let now = chrono::Utc::now();
        let events = match &args.events_file {
            Some(path) => load_events_fixture(path)?,
            None => Vec::new(),
        };
        let mut window = ingest::events_to_window(&events, now, now);
        if let Some(path) = &args.transactions_file {
            let txs = load_transactions_fixture(path)?;
            ingest::merge_transaction_outcomes(&mut window, &txs);
        }
        Ok(window)
    } else {
        let rpc_url = ingest::rpc_url_for(network)?;
        ingest::collect_live_window(&rpc_url, &args.contract, EventStreamFilters::default())
    }
}

fn load_events_fixture(path: &PathBuf) -> Result<Vec<crate::utils::stream::SorobanEvent>> {
    config::validate_file_path(path, Some("json"))?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read events fixture {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "Failed to parse events fixture {} as a JSON event array",
            path.display()
        )
    })
}

fn load_transactions_fixture(
    path: &PathBuf,
) -> Result<Vec<crate::utils::horizon::TransactionRecord>> {
    config::validate_file_path(path, Some("json"))?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read transactions fixture {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "Failed to parse transactions fixture {} as a JSON transaction-record array",
            path.display()
        )
    })
}

fn render_monitor_result(
    window: &model::WindowMetrics,
    detected: &[model::Alert],
    save_outcomes: &[alerts::SaveOutcome],
    explanation: &str,
    format: &str,
) {
    if format == "json" {
        let payload = serde_json::json!({
            "window": window,
            "alerts": detected,
            "explanation": explanation,
        });
        println!(
            "{}",
            redact_text(&serde_json::to_string_pretty(&payload).unwrap_or_default())
        );
        return;
    }

    p::kv("Events observed", &window.event_count.to_string());
    p::kv("Unique callers", &window.unique_callers.len().to_string());
    p::kv(
        "Error rate",
        &format!("{:.1}%", window.error_rate() * 100.0),
    );
    println!();

    if detected.is_empty() {
        p::success("No anomalies detected in this window.");
        return;
    }

    let suppressed = save_outcomes
        .iter()
        .filter(|o| matches!(o, alerts::SaveOutcome::Deduplicated { .. }))
        .count();

    for alert in detected {
        let label = match alert.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow().bold(),
            Severity::Low => "LOW".dimmed(),
        };
        println!("  [{}] {} — {}", label, alert.kind.as_str(), alert.message);
    }
    if suppressed > 0 {
        println!(
            "  {} {} alert(s) suppressed by dedup cooldown (already firing).",
            "•".dimmed(),
            suppressed
        );
    }
    println!();
    println!("{}", "Explanation".bold());
    println!("{}", redact_text(explanation));
}

fn handle_baseline(cmd: BaselineCommands) -> Result<()> {
    match cmd {
        BaselineCommands::Update {
            contract,
            network,
            events_file,
            transactions_file,
            reset,
        } => baseline_update(&contract, network, events_file, transactions_file, reset),
        BaselineCommands::Show {
            contract,
            network,
            format,
        } => baseline_show(&contract, network, &format),
        BaselineCommands::List { format } => baseline_list(&format),
        BaselineCommands::Reset {
            contract,
            network,
            yes,
        } => baseline_reset(&contract, network, yes),
    }
}

fn baseline_update(
    contract: &str,
    network: Option<String>,
    events_file: Option<PathBuf>,
    transactions_file: Option<PathBuf>,
    reset: bool,
) -> Result<()> {
    config::validate_contract_id(contract)?;
    let network = resolve_network(network)?;

    let now = chrono::Utc::now();
    let events = match &events_file {
        Some(path) => load_events_fixture(path)?,
        None => Vec::new(),
    };
    let mut window = ingest::events_to_window(&events, now, now);
    if let Some(path) = &transactions_file {
        let txs = load_transactions_fixture(path)?;
        ingest::merge_transaction_outcomes(&mut window, &txs);
    }

    let mut current = if reset {
        model::Baseline::new(contract, &network)
    } else {
        baseline::load_or_create(contract, &network)?
    };
    current.observe(&window);
    let path = baseline::save(&current)?;

    p::success(&format!(
        "Baseline updated ({} sample{}, {} known caller{}). Saved to {}",
        current.sample_count,
        if current.sample_count == 1 { "" } else { "s" },
        current.known_callers.len(),
        if current.known_callers.len() == 1 {
            ""
        } else {
            "s"
        },
        redact_text(&path.display().to_string())
    ));
    Ok(())
}

fn baseline_show(contract: &str, network: Option<String>, format: &str) -> Result<()> {
    config::validate_contract_id(contract)?;
    let network = resolve_network(network)?;
    let current = baseline::load(contract, &network)?
        .with_context(|| format!("No baseline found for {} on {}", contract, network))?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&current)?);
        return Ok(());
    }

    p::header("Anomaly Baseline");
    p::kv("Contract", &current.contract_id);
    p::kv("Network", &current.network);
    p::kv("Samples", &current.sample_count.to_string());
    p::kv(
        "Mature",
        if current.is_mature() {
            "yes"
        } else {
            "no (warming up)"
        },
    );
    p::kv("Known callers", &current.known_callers.len().to_string());
    println!();
    for (name, stats) in &current.metrics {
        println!(
            "  {:<20} mean={:<12.2} stddev={:<12.2} min={:<12.2} max={:<12.2}",
            name,
            stats.mean,
            stats.stddev(),
            stats.min,
            stats.max
        );
    }
    Ok(())
}

fn baseline_list(format: &str) -> Result<()> {
    let all = baseline::list_all()?;
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&all)?);
        return Ok(());
    }
    if all.is_empty() {
        notifications::info("No anomaly baselines saved yet.");
        return Ok(());
    }
    p::header("Anomaly Baselines");
    for b in &all {
        println!(
            "  {} ({}) — {} sample(s), {} known caller(s){}",
            b.contract_id,
            b.network,
            b.sample_count,
            b.known_callers.len(),
            if b.is_mature() { "" } else { " [warming up]" }
        );
    }
    Ok(())
}

fn baseline_reset(contract: &str, network: Option<String>, yes: bool) -> Result<()> {
    config::validate_contract_id(contract)?;
    let network = resolve_network(network)?;
    if !yes {
        anyhow::bail!("This will permanently delete the baseline. Re-run with --yes to confirm.");
    }
    let removed = baseline::reset(contract, &network)?;
    if removed {
        p::success(&format!("Baseline for {} on {} reset.", contract, network));
    } else {
        notifications::info("No baseline existed for that contract/network; nothing to reset.");
    }
    Ok(())
}

fn alert_test(
    contract: &str,
    network: Option<String>,
    metrics_file: &PathBuf,
    persist: bool,
    format: &str,
    fail_on: Option<String>,
) -> Result<()> {
    config::validate_contract_id(contract)?;
    let network = resolve_network(network)?;
    config::validate_file_path(metrics_file, Some("json"))?;

    let raw = fs::read_to_string(metrics_file)
        .with_context(|| format!("Failed to read metrics fixture {}", metrics_file.display()))?;
    let window: model::WindowMetrics = serde_json::from_str(&raw).with_context(|| {
        format!(
            "Failed to parse {} as a WindowMetrics fixture",
            metrics_file.display()
        )
    })?;

    let current_baseline = baseline::load_or_create(contract, &network)?;
    let detected = detectors::detect_all(
        &window,
        &current_baseline,
        &detectors::ThresholdConfig::default(),
    );

    let save_outcomes = if persist && !detected.is_empty() {
        alerts::save_all(&detected, alerts::DEFAULT_DEDUP_COOLDOWN_SECS)?
    } else {
        Vec::new()
    };

    if format == "json" {
        let payload = serde_json::json!({
            "window": window,
            "alerts": detected,
            "persisted": persist,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else if detected.is_empty() {
        p::success("alert-test: no anomalies detected for this synthetic window.");
    } else {
        p::header("alert-test results");
        for alert in &detected {
            println!(
                "  [{}] {} — {}",
                alert.severity,
                alert.kind.as_str(),
                alert.message
            );
        }
        if persist {
            let saved = save_outcomes
                .iter()
                .filter(|o| matches!(o, alerts::SaveOutcome::Saved(_)))
                .count();
            p::kv("Persisted", &saved.to_string());
        }
    }

    if let Some(threshold) = fail_on.as_deref() {
        let min_severity = parse_severity(threshold);
        if detected.iter().any(|a| a.severity >= min_severity) {
            anyhow::bail!(
                "alert-test: {} alert(s) at or above severity '{}'",
                detected
                    .iter()
                    .filter(|a| a.severity >= min_severity)
                    .count(),
                threshold
            );
        }
    }
    Ok(())
}

fn export(
    contract: &str,
    network: Option<String>,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    config::validate_contract_id(contract)?;
    let network = resolve_network(network)?;
    let rendered = redact_text(&alerts::export(contract, &network, format)?);
    match output {
        Some(path) => {
            fs::write(&path, &rendered)
                .with_context(|| format!("Failed to write export to {}", path.display()))?;
            p::success(&format!("Alert history exported to {}", path.display()));
        }
        None => println!("{}", rendered),
    }
    Ok(())
}

async fn report(
    contract: &str,
    network: Option<String>,
    since_hours: i64,
    format: &str,
    output: Option<PathBuf>,
    deterministic: bool,
    model: &str,
) -> Result<()> {
    config::validate_contract_id(contract)?;
    let network = resolve_network(network)?;
    if since_hours <= 0 {
        anyhow::bail!("--since-hours must be a positive number of hours");
    }

    let recent = alerts::load_recent(contract, &network, since_hours)?;
    let deterministic_explanation = explain::deterministic_explanation(&recent);
    let ai_narrative = if deterministic {
        None
    } else {
        match explain::maybe_generate_ai_narrative(&recent, model).await {
            Ok(narrative) => narrative,
            Err(e) => {
                notifications::warn(&format!("AI narrative generation failed: {}", e));
                None
            }
        }
    };

    let incident_report = report::IncidentReport::build(
        contract,
        &network,
        since_hours,
        recent,
        deterministic_explanation,
        ai_narrative,
    );

    let rendered = redact_text(&if format == "json" {
        incident_report.to_json()?
    } else {
        incident_report.to_markdown()
    });

    match output {
        Some(path) => {
            fs::write(&path, &rendered)
                .with_context(|| format!("Failed to write report to {}", path.display()))?;
            p::success(&format!("Incident report written to {}", path.display()));
        }
        None => println!("{}", rendered),
    }
    Ok(())
}
