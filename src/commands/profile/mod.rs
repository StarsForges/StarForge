//! AI-assisted performance profiling and optimization for Soroban contracts.
//!
//! Subcommands:
//! - `run`              — Profile a contract from a simulation file or manual params.
//! - `compare`          — Compare two profiles or a profile against a saved baseline.
//! - `budget`           — Check the latest profile against configured thresholds.
//! - `export`           — Export profile history as JSON or CSV.
//! - `check-regression` — CI gate: fail if any metric regressed beyond the threshold.
//! - `flame`            — Print a flame-style CPU summary for a saved baseline.
//! - `list`             — List all saved baselines.

use crate::utils::performance::{
    baseline as bl, flame::FlameSummary, metrics::*, optimizer, report as rpt,
};
use crate::utils::{print as p};
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use std::fs;
use std::path::PathBuf;

const DEFAULT_LABEL: &str = "default";
const DEFAULT_REGRESSION_THRESHOLD: f64 = 10.0;

#[derive(Subcommand)]
pub enum ProfileCommands {
    /// Profile a contract from a simulation file or manual resource parameters
    Run {
        /// Logical label for this contract or operation (used for baseline tracking)
        #[arg(long, default_value = DEFAULT_LABEL)]
        label: String,

        /// Network context used for utilization heuristics
        #[arg(long, default_value = "testnet")]
        network: String,

        /// Path to a raw Soroban RPC simulateTransaction JSON response/fixture
        #[arg(long)]
        simulation_file: Option<PathBuf>,

        /// Manual CPU instruction count
        #[arg(long)]
        cpu_insns: Option<u64>,

        /// Manual peak memory usage in bytes
        #[arg(long)]
        mem_bytes: Option<u64>,

        /// Manual ledger entries read
        #[arg(long)]
        read_entries: Option<u32>,

        /// Manual ledger entries written
        #[arg(long)]
        write_entries: Option<u32>,

        /// Manual bytes read from ledger
        #[arg(long)]
        read_bytes: Option<u64>,

        /// Manual bytes written to ledger
        #[arg(long)]
        write_bytes: Option<u64>,

        /// Manual number of events emitted
        #[arg(long)]
        event_count: Option<u32>,

        /// Manual total bytes of emitted events
        #[arg(long)]
        event_bytes: Option<u64>,

        /// Manual simulation fee in stroops
        #[arg(long)]
        fee_stroops: Option<u64>,

        /// Save the profile as a new baseline snapshot
        #[arg(long)]
        save: bool,

        /// Description to attach to the saved baseline
        #[arg(long)]
        description: Option<String>,

        /// Compare against the latest saved baseline for this label
        #[arg(long)]
        compare_baseline: bool,

        /// Regression threshold percent (used with --compare-baseline)
        #[arg(long, default_value_t = DEFAULT_REGRESSION_THRESHOLD)]
        regression_threshold: f64,

        /// Show flame-style CPU summary
        #[arg(long)]
        flame: bool,

        /// Use AI to generate an optimization narrative (requires OPENAI_API_KEY)
        #[arg(long)]
        ai: bool,

        /// AI model to use for optimization narrative
        #[arg(long, default_value = "gpt-4")]
        model: String,

        /// Output format: human (default) or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,

        /// Write output to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Compare two profiles or a profile against a saved baseline
    Compare {
        /// Label to load from the baseline store (most recent two snapshots)
        #[arg(long, default_value = DEFAULT_LABEL)]
        label: String,

        /// Path to a baseline snapshot JSON file (overrides --label store lookup)
        #[arg(long)]
        baseline_file: Option<PathBuf>,

        /// Path to a candidate snapshot or simulation-result JSON to compare against baseline
        #[arg(long)]
        candidate_file: Option<PathBuf>,

        /// Regression threshold percent
        #[arg(long, default_value_t = DEFAULT_REGRESSION_THRESHOLD)]
        regression_threshold: f64,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,

        /// Write output to file
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Check the latest profile against absolute resource budgets
    Budget {
        /// Label to load the latest baseline for
        #[arg(long, default_value = DEFAULT_LABEL)]
        label: String,

        /// Path to a simulation-result JSON file to check (overrides stored baseline)
        #[arg(long)]
        simulation_file: Option<PathBuf>,

        /// Maximum allowed CPU instructions
        #[arg(long)]
        max_cpu_insns: Option<u64>,

        /// Maximum allowed peak memory bytes
        #[arg(long)]
        max_mem_bytes: Option<u64>,

        /// Maximum allowed simulation fee in stroops
        #[arg(long)]
        max_fee_stroops: Option<u64>,

        /// Maximum allowed ledger write entries
        #[arg(long)]
        max_write_entries: Option<u32>,

        /// Maximum allowed events per invocation
        #[arg(long)]
        max_events: Option<u32>,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,

        /// Write output to file
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Export profile history as JSON or CSV
    Export {
        /// Label to export history for
        #[arg(long, default_value = DEFAULT_LABEL)]
        label: String,

        /// Export format: json or csv
        #[arg(long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,

        /// Write output to file
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// CI gate: fail with exit code 1 if any metric regressed beyond threshold
    CheckRegression {
        /// Label to check for regressions
        #[arg(long, default_value = DEFAULT_LABEL)]
        label: String,

        /// Regression threshold percent (default: 10%)
        #[arg(long, default_value_t = DEFAULT_REGRESSION_THRESHOLD)]
        threshold: f64,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },

    /// Print a flame-style CPU breakdown for a saved baseline
    Flame {
        /// Label to show the latest flame summary for
        #[arg(long, default_value = DEFAULT_LABEL)]
        label: String,

        /// Path to a specific baseline snapshot JSON file
        #[arg(long)]
        baseline_file: Option<PathBuf>,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },

    /// List all saved baseline labels
    List {
        /// Label to list snapshots for (omit to show all labels)
        #[arg(long)]
        label: Option<String>,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },
}

/// Generate an AI-assisted optimization narrative.
/// Returns `Ok(None)` when `OPENAI_API_KEY` is not set.
async fn generate_ai_narrative(
    report: &optimizer::OptimizationReport,
    model: &str,
) -> Result<Option<String>> {
    use crate::commands::ai::impact::redactor::redact_text;
    use async_openai::{
        config::OpenAIConfig,
        types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role},
        Client,
    };

    let api_key = match std::env::var("OPENAI_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())
    {
        Some(k) => k,
        None => return Ok(None),
    };

    let recs_text = if report.recommendations.is_empty() {
        "No specific issues found — the contract profile looks healthy.".to_string()
    } else {
        report
            .recommendations
            .iter()
            .map(|r| {
                format!(
                    "[{}][{}] {}: {}  Before: {}  After: {}",
                    r.severity.as_str().to_uppercase(),
                    r.category.as_str(),
                    r.title,
                    r.rationale,
                    r.before,
                    r.after
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let prompt = redact_text(&format!(
        "You are a Soroban smart contract performance engineer. A static profiling tool \
         analyzed contract '{}' and produced the following recommendations:\n\n{}\n\n\
         Deterministic summary: {}\n\n\
         Write a concise, actionable optimization report in Markdown with:\n\
         1. EXECUTIVE SUMMARY: High-level performance health assessment.\n\
         2. CRITICAL FINDINGS: Prioritized action items with engineering rationale.\n\
         3. QUICK WINS: Changes with the highest impact-to-effort ratio.\n\
         4. LONG-TERM IMPROVEMENTS: Architectural changes for sustained gains.\n\
         Keep it practical and specific to Soroban/Stellar constraints.",
        report.contract_label, recs_text, report.deterministic_summary
    ));

    let config = OpenAIConfig::new().with_api_key(api_key);
    let client = Client::with_config(config);
    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(
                "You are an expert Soroban smart contract performance auditor. \
                 Provide actionable, engineering-grade optimization guidance."
                    .to_string(),
            ),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(prompt),
            name: None,
            function_call: None,
        },
    ];
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response =
        crate::commands::ai::execute_chat(&client, "perf_profile_optimize", model, request)
            .await
            .context("AI optimization narrative request failed")?;

    let text = response
        .choices
        .first()
        .and_then(|c| c.message.content.as_deref())
        .unwrap_or("No narrative generated.")
        .trim();

    Ok(Some(redact_text(text)))
}

pub async fn handle(cmd: ProfileCommands) -> Result<()> {
    match cmd {
        ProfileCommands::Run {
            label,
            network,
            simulation_file,
            cpu_insns,
            mem_bytes,
            read_entries,
            write_entries,
            read_bytes,
            write_bytes,
            event_count,
            event_bytes,
            fee_stroops,
            save,
            description,
            compare_baseline,
            regression_threshold,
            flame,
            ai,
            model,
            format,
            output,
        } => {
            handle_run(
                &label,
                &network,
                simulation_file.as_deref(),
                cpu_insns,
                mem_bytes,
                read_entries,
                write_entries,
                read_bytes,
                write_bytes,
                event_count,
                event_bytes,
                fee_stroops,
                save,
                description.as_deref(),
                compare_baseline,
                regression_threshold,
                flame,
                ai,
                &model,
                &format,
                output.as_deref(),
            )
            .await
        }
        ProfileCommands::Compare {
            label,
            baseline_file,
            candidate_file,
            regression_threshold,
            format,
            output,
        } => handle_compare(
            &label,
            baseline_file.as_deref(),
            candidate_file.as_deref(),
            regression_threshold,
            &format,
            output.as_deref(),
        ),
        ProfileCommands::Budget {
            label,
            simulation_file,
            max_cpu_insns,
            max_mem_bytes,
            max_fee_stroops,
            max_write_entries,
            max_events,
            format,
            output,
        } => handle_budget(
            &label,
            simulation_file.as_deref(),
            max_cpu_insns,
            max_mem_bytes,
            max_fee_stroops,
            max_write_entries,
            max_events,
            &format,
            output.as_deref(),
        ),
        ProfileCommands::Export {
            label,
            format,
            output,
        } => handle_export(&label, &format, output.as_deref()),
        ProfileCommands::CheckRegression {
            label,
            threshold,
            format,
        } => handle_check_regression(&label, threshold, &format),
        ProfileCommands::Flame {
            label,
            baseline_file,
            format,
        } => handle_flame(&label, baseline_file.as_deref(), &format),
        ProfileCommands::List { label, format } => handle_list(label.as_deref(), &format),
    }
}

// ── Subcommand implementations ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_run(
    label: &str,
    network: &str,
    simulation_file: Option<&std::path::Path>,
    cpu_insns: Option<u64>,
    mem_bytes: Option<u64>,
    read_entries: Option<u32>,
    write_entries: Option<u32>,
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
    event_count: Option<u32>,
    event_bytes: Option<u64>,
    fee_stroops: Option<u64>,
    save: bool,
    description: Option<&str>,
    compare_baseline: bool,
    regression_threshold: f64,
    show_flame: bool,
    ai: bool,
    model: &str,
    format: &str,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    // Build metrics from simulation file or manual params
    let mut metrics = if let Some(path) = simulation_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read simulation file {}", path.display()))?;
        let envelope: serde_json::Value =
            serde_json::from_str(&raw).context("Failed to parse simulation file as JSON")?;
        ProfileMetrics::from_rpc_envelope(&envelope, label, network)
            .context("Failed to parse simulation envelope into profile metrics")?
    } else {
        build_manual_metrics(
            label,
            network,
            cpu_insns,
            mem_bytes,
            read_entries,
            write_entries,
            read_bytes,
            write_bytes,
            event_count,
            event_bytes,
            fee_stroops,
        )
    };

    // Validate: warn if completely empty
    if metrics.is_empty() {
        metrics
            .notes
            .push("No resource data supplied. Use --simulation-file or manual parameters."
                .to_string());
    }

    // Run optimizer
    let mut opt_report = optimizer::analyze(&metrics);

    // Optional AI narrative
    if ai {
        match generate_ai_narrative(&opt_report, model).await {
            Ok(Some(narrative)) => opt_report.ai_narrative = Some(narrative),
            Ok(None) => {
                p::warn("OPENAI_API_KEY not set — skipping AI narrative.");
            }
            Err(e) => {
                p::warn(&format!("AI narrative failed (using deterministic output): {}", e));
            }
        }
    }

    // Flame summary
    let flame_summary = if show_flame {
        Some(FlameSummary::from_metrics(&metrics))
    } else {
        None
    };

    // Baseline comparison
    let baseline_cmp = if compare_baseline {
        match bl::load_latest_baseline(label)? {
            Some(snap) => {
                let delta = ProfileDelta::compute(&snap.metrics, &metrics, regression_threshold);
                Some(rpt::BaselineComparison {
                    baseline_label: snap.label.clone(),
                    baseline_timestamp: snap.timestamp.to_rfc3339(),
                    delta,
                })
            }
            None => {
                p::warn(&format!(
                    "No baseline found for label '{}'. Run with --save first.",
                    label
                ));
                None
            }
        }
    } else {
        None
    };

    // Save baseline
    if save {
        let path = bl::save_baseline(label, &metrics, description)?;
        p::success(&format!("Baseline saved: {}", path.display()));
    }

    // Render output
    let run_output = rpt::ProfileRunOutput {
        metrics: metrics.clone(),
        optimization_report: opt_report,
        flame: flame_summary,
        baseline_comparison: baseline_cmp,
    };

    let out_str = match format {
        "json" => serde_json::to_string_pretty(&run_output)
            .context("Failed to serialize profile output as JSON")?,
        _ => {
            rpt::print_profile_run(&run_output, show_flame, false);
            return write_if_requested(
                &serde_json::to_string_pretty(&run_output)
                    .unwrap_or_default(),
                output_path,
                "profile run",
            );
        }
    };

    write_or_print(&out_str, output_path, "profile run")
}

fn handle_compare(
    label: &str,
    baseline_file: Option<&std::path::Path>,
    candidate_file: Option<&std::path::Path>,
    regression_threshold: f64,
    format: &str,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    let baseline_metrics = if let Some(path) = baseline_file {
        let snap = bl::load_baseline_from_file(path)?;
        snap.metrics
    } else {
        let snaps = bl::load_baselines(label)?;
        if snaps.len() < 2 {
            anyhow::bail!(
                "Need at least 2 saved baselines for label '{}' to compare. \
                 Use 'profile run --save' to build history, or supply --baseline-file.",
                label
            );
        }
        snaps[snaps.len() - 2].metrics.clone()
    };

    let candidate_metrics = if let Some(path) = candidate_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read candidate file {}", path.display()))?;
        // Try to parse as a full envelope first, fall back to BaselineSnapshot
        let v: serde_json::Value =
            serde_json::from_str(&raw).context("Failed to parse candidate file as JSON")?;
        if v.get("jsonrpc").is_some() || v.get("result").is_some() {
            ProfileMetrics::from_rpc_envelope(&v, label, "testnet")?
        } else {
            // Assume it's a BaselineSnapshot
            let snap: bl::BaselineSnapshot =
                serde_json::from_value(v).context("Failed to parse candidate as baseline snapshot")?;
            snap.metrics
        }
    } else {
        // Use the latest saved baseline
        bl::load_latest_baseline(label)?
            .map(|s| s.metrics)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No saved baseline for label '{}'. Use --candidate-file or run 'profile run --save'.",
                    label
                )
            })?
    };

    let delta = ProfileDelta::compute(&baseline_metrics, &candidate_metrics, regression_threshold);
    let cmp = rpt::BaselineComparison {
        baseline_label: label.to_string(),
        baseline_timestamp: chrono::Utc::now().to_rfc3339(),
        delta: delta.clone(),
    };

    match format {
        "json" => {
            let out = serde_json::to_string_pretty(&serde_json::json!({
                "comparison": cmp,
                "baseline_metrics": baseline_metrics,
                "candidate_metrics": candidate_metrics,
            }))
            .context("Failed to serialize comparison")?;
            write_or_print(&out, output_path, "compare")
        }
        _ => {
            rpt::print_comparison(&cmp);
            write_if_requested(
                &serde_json::to_string_pretty(&cmp).unwrap_or_default(),
                output_path,
                "compare",
            )
        }
    }
}

fn handle_budget(
    label: &str,
    simulation_file: Option<&std::path::Path>,
    max_cpu_insns: Option<u64>,
    max_mem_bytes: Option<u64>,
    max_fee_stroops: Option<u64>,
    max_write_entries: Option<u32>,
    max_events: Option<u32>,
    format: &str,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    let metrics = if let Some(path) = simulation_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read simulation file {}", path.display()))?;
        let v: serde_json::Value =
            serde_json::from_str(&raw).context("Failed to parse simulation file as JSON")?;
        ProfileMetrics::from_rpc_envelope(&v, label, "testnet")?
    } else {
        bl::load_latest_baseline(label)?
            .map(|s| s.metrics)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No saved baseline for label '{}' and no --simulation-file provided.",
                    label
                )
            })?
    };

    let budget = ProfileBudget {
        max_cpu_insns,
        max_mem_bytes,
        max_fee_stroops,
        max_write_entries,
        max_events,
        ..Default::default()
    };

    let result = BudgetCheckResult::check(&metrics, &budget);
    let passed = result.passed;

    match format {
        "json" => {
            let out = serde_json::to_string_pretty(&serde_json::json!({
                "passed": result.passed,
                "violations": result.violations,
                "metrics": metrics,
                "budget": budget,
            }))
            .context("Failed to serialize budget check")?;
            write_or_print(&out, output_path, "budget")?;
        }
        _ => {
            rpt::print_budget_check(&metrics, &result);
            write_if_requested(
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
                output_path,
                "budget",
            )?;
        }
    }

    if !passed {
        std::process::exit(1);
    }
    Ok(())
}

fn handle_export(
    label: &str,
    format: &str,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    let content = bl::export_baselines(label, format)
        .with_context(|| format!("Failed to export baselines for label '{}'", label))?;
    write_or_print(&content, output_path, "export")
}

fn handle_check_regression(label: &str, threshold: f64, format: &str) -> Result<()> {
    let snaps = bl::load_baselines(label)?;

    if snaps.len() < 2 {
        match format {
            "json" => {
                println!(
                    "{}",
                    serde_json::json!({
                        "label": label,
                        "status": "no_baseline",
                        "message": "No previous baseline to compare against — first run is always green."
                    })
                );
            }
            _ => {
                p::info(&format!(
                    "No previous baseline for '{}' — first run is always green.",
                    label
                ));
            }
        }
        return Ok(());
    }

    let baseline = &snaps[snaps.len() - 2];
    let candidate = &snaps[snaps.len() - 1];
    let delta = ProfileDelta::compute(&baseline.metrics, &candidate.metrics, threshold);

    match format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "label": label,
                    "threshold_pct": threshold,
                    "regressed": delta.regressed,
                    "regression_details": delta.regression_details,
                    "delta": delta,
                    "baseline_timestamp": baseline.timestamp,
                    "candidate_timestamp": candidate.timestamp,
                }))
                .context("Failed to serialize regression check")?
            );
        }
        _ => {
            let cmp = rpt::BaselineComparison {
                baseline_label: label.to_string(),
                baseline_timestamp: baseline.timestamp.to_rfc3339(),
                delta: delta.clone(),
            };
            rpt::print_comparison(&cmp);
        }
    }

    if delta.regressed {
        eprintln!(
            "\n  {} Regression check FAILED for label '{}'",
            "✗".red().bold(),
            label
        );
        std::process::exit(1);
    }
    Ok(())
}

fn handle_flame(
    label: &str,
    baseline_file: Option<&std::path::Path>,
    format: &str,
) -> Result<()> {
    let metrics = if let Some(path) = baseline_file {
        let snap = bl::load_baseline_from_file(path)?;
        snap.metrics
    } else {
        bl::load_latest_baseline(label)?
            .map(|s| s.metrics)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No saved baseline for label '{}'. Run 'profile run --save' first.",
                    label
                )
            })?
    };

    let summary = FlameSummary::from_metrics(&metrics);
    match format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).context("Failed to serialize flame summary")?
            );
        }
        _ => {
            println!("\n{}", "  Flame CPU Summary".bright_white().bold());
            println!("  {}", "─".repeat(60).dimmed());
            for line in summary.text.lines() {
                println!("  {}", line);
            }
        }
    }
    Ok(())
}

fn handle_list(label: Option<&str>, format: &str) -> Result<()> {
    if let Some(lbl) = label {
        let snaps = bl::load_baselines(lbl)?;
        match format {
            "json" => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&snaps)
                        .context("Failed to serialize baseline list")?
                );
            }
            _ => rpt::print_baseline_list(lbl, &snaps),
        }
    } else {
        let labels = bl::list_labels()?;
        match format {
            "json" => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&labels)
                        .context("Failed to serialize label list")?
                );
            }
            _ => {
                println!(
                    "\n{}",
                    "  Saved Profile Labels".bright_white().bold()
                );
                println!("  {}", "─".repeat(40).dimmed());
                if labels.is_empty() {
                    println!("  (no profiles saved yet)");
                } else {
                    for lbl in &labels {
                        println!("  • {}", lbl.cyan());
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_manual_metrics(
    label: &str,
    network: &str,
    cpu_insns: Option<u64>,
    mem_bytes: Option<u64>,
    read_entries: Option<u32>,
    write_entries: Option<u32>,
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
    event_count: Option<u32>,
    event_bytes: Option<u64>,
    fee_stroops: Option<u64>,
) -> ProfileMetrics {
    let ev_count = event_count.unwrap_or(0);
    let ev_bytes = event_bytes.unwrap_or(0);
    let avg_ev = if ev_count > 0 {
        ev_bytes as f64 / ev_count as f64
    } else {
        0.0
    };
    let has_oversized = avg_ev > 512.0;

    let rw_keys = write_entries.unwrap_or(0);
    let ro_keys = read_entries.unwrap_or(0);
    let cpu = cpu_insns.unwrap_or(0);
    let mem = mem_bytes.unwrap_or(0);
    let ro_bytes = read_bytes.unwrap_or(0);
    let rw_bytes = write_bytes.unwrap_or(0);

    let storage = StorageProfile {
        read_only_keys: ro_keys,
        read_write_keys: rw_keys,
        total_read_bytes: ro_bytes,
        total_write_bytes: rw_bytes,
        persistent_entry_count: rw_keys,
        temporary_entry_count: 0,
        has_archived_entries: false,
    };
    let events = EventProfile {
        event_count: ev_count,
        total_event_bytes: ev_bytes,
        has_oversized_events: has_oversized,
        avg_event_bytes: avg_ev,
    };

    let hot_spots = Vec::new(); // will be overwritten below

    let mut m = ProfileMetrics {
        contract_label: label.to_string(),
        network: network.to_string(),
        cpu_insns: cpu,
        mem_bytes: mem,
        sim_fee_stroops: fee_stroops.unwrap_or(0),
        storage,
        events,
        hot_spots,
        ..Default::default()
    };

    // Re-derive hot spots from the actual values using the parsed storage profile
    m.hot_spots = crate::utils::performance::metrics::derive_hot_spots_pub(
        cpu,
        mem,
        &m.storage,
        &m.events,
    );

    m
}

fn write_or_print(
    content: &str,
    output_path: Option<&std::path::Path>,
    label: &str,
) -> Result<()> {
    if let Some(path) = output_path {
        fs::write(path, content)
            .with_context(|| format!("Failed to write {} output to {}", label, path.display()))?;
        p::success(&format!("Output written to {}", path.display()));
    } else {
        println!("{}", content);
    }
    Ok(())
}

fn write_if_requested(
    content: &str,
    output_path: Option<&std::path::Path>,
    label: &str,
) -> Result<()> {
    if let Some(path) = output_path {
        fs::write(path, content)
            .with_context(|| format!("Failed to write {} output to {}", label, path.display()))?;
        p::success(&format!("Output written to {}", path.display()));
    }
    Ok(())
}
