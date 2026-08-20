//! AI-assisted cost estimation and economic analysis for Soroban operations.
//!
//! Provides a deterministic cost model (see [`model`]) fed either by manual
//! parameters or by normalizing real Soroban RPC simulation responses (see
//! [`adapter`]), an optional AI narrative layer with a deterministic fallback
//! (see [`explain`]), and versioned historical persistence enabling
//! regression-threshold checks in CI (see [`history`]).

pub mod adapter;
pub mod explain;
pub mod history;
pub mod model;

use crate::commands::ai::impact::redactor::redact_text;
use crate::utils::{config, print as p};
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use model::{estimate_cost, OperationKind, ResourceUsage};
use std::fs;
use std::path::PathBuf;

const DEFAULT_HISTORY_LABEL: &str = "default";

#[derive(Subcommand)]
pub enum CostCommands {
    /// Estimate the fee/resource cost of a single Soroban operation
    Estimate {
        /// Operation kind: deploy, invoke, storage-write, storage-read, archival, event, batch
        operation: String,

        /// Network context used for base-fee heuristics (default: config network)
        #[arg(long)]
        network: Option<String>,

        /// Path to a raw Soroban RPC simulateTransaction JSON response/fixture
        /// to normalize into resource usage (see tests/fixtures/soroban_rpc/)
        #[arg(long)]
        simulation_file: Option<PathBuf>,

        /// Manual CPU instruction count (overrides simulation file if both given)
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
        /// Manual bytes read from the ledger
        #[arg(long)]
        read_bytes: Option<u64>,
        /// Manual bytes written to the ledger
        #[arg(long)]
        write_bytes: Option<u64>,
        /// Manual number of contract events emitted
        #[arg(long)]
        event_count: Option<u32>,
        /// Manual total bytes of emitted event data
        #[arg(long)]
        event_bytes: Option<u64>,

        /// Number of items for a batch operation (amortizes the base fee)
        #[arg(long, default_value_t = 1)]
        batch_size: u32,

        /// Ledgers remaining until the targeted entry's TTL expires (negative/zero if already archived)
        #[arg(long)]
        ledgers_until_expiry: Option<i64>,

        /// History label to persist this estimate under when --save is passed
        #[arg(long)]
        label: Option<String>,

        /// Persist this estimate to versioned history for later comparison/regression checks
        #[arg(long)]
        save: bool,

        /// Skip AI narrative generation and use only the deterministic explanation
        #[arg(long)]
        deterministic: bool,

        /// Model to use for the AI narrative (default: gpt-4)
        #[arg(long, default_value = "gpt-4")]
        model: String,

        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,

        /// Optional path to write the report instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Compare two cost estimates (explicit snapshot files, or the two most
    /// recent entries in a label's history)
    Compare {
        /// History label to compare the two most recent snapshots for
        #[arg(long, conflicts_with_all = ["baseline", "candidate"])]
        label: Option<String>,

        /// Path to the baseline snapshot JSON (as produced by `estimate --save`)
        #[arg(long, requires = "candidate")]
        baseline: Option<PathBuf>,

        /// Path to the candidate snapshot JSON
        #[arg(long, requires = "baseline")]
        candidate: Option<PathBuf>,

        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },

    /// Check the latest estimate for a label against a fee budget
    Budget {
        /// History label to check
        #[arg(long, default_value = "default")]
        label: String,

        /// Maximum acceptable fee, in stroops
        #[arg(long)]
        max_fee_stroops: u64,

        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },

    /// Export historical estimates for a label as JSON or CSV
    Export {
        /// History label to export
        #[arg(long, default_value = "default")]
        label: String,

        /// Export format: json or csv
        #[arg(long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,

        /// Optional path to write the export instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Fail if the latest estimate for a label regressed beyond a threshold
    /// versus the previous one — intended for CI cost-regression gates
    CheckRegression {
        /// History label to check
        #[arg(long, default_value = "default")]
        label: String,

        /// Maximum acceptable percentage fee increase versus the previous estimate
        #[arg(long, default_value_t = 10.0)]
        threshold_percent: f64,

        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },
}

pub async fn handle(cmd: CostCommands) -> Result<()> {
    match cmd {
        CostCommands::Estimate {
            operation,
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
            batch_size,
            ledgers_until_expiry,
            label,
            save,
            deterministic,
            model,
            format,
            output,
        } => {
            estimate(
                &operation,
                network,
                simulation_file,
                ManualOverrides {
                    cpu_insns,
                    mem_bytes,
                    read_entries,
                    write_entries,
                    read_bytes,
                    write_bytes,
                    event_count,
                    event_bytes,
                },
                batch_size,
                ledgers_until_expiry,
                label,
                save,
                deterministic,
                &model,
                &format,
                output,
            )
            .await
        }
        CostCommands::Compare {
            label,
            baseline,
            candidate,
            format,
        } => compare(label, baseline, candidate, &format),
        CostCommands::Budget {
            label,
            max_fee_stroops,
            format,
        } => budget(&label, max_fee_stroops, &format),
        CostCommands::Export {
            label,
            format,
            output,
        } => export(&label, &format, output),
        CostCommands::CheckRegression {
            label,
            threshold_percent,
            format,
        } => check_regression(&label, threshold_percent, &format),
    }
}

#[derive(Default)]
struct ManualOverrides {
    cpu_insns: Option<u64>,
    mem_bytes: Option<u64>,
    read_entries: Option<u32>,
    write_entries: Option<u32>,
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
    event_count: Option<u32>,
    event_bytes: Option<u64>,
}

impl ManualOverrides {
    fn apply(self, mut usage: ResourceUsage) -> ResourceUsage {
        if let Some(v) = self.cpu_insns {
            usage.cpu_insns = v;
        }
        if let Some(v) = self.mem_bytes {
            usage.mem_bytes = v;
        }
        if let Some(v) = self.read_entries {
            usage.read_entries = v;
        }
        if let Some(v) = self.write_entries {
            usage.write_entries = v;
        }
        if let Some(v) = self.read_bytes {
            usage.read_bytes = v;
        }
        if let Some(v) = self.write_bytes {
            usage.write_bytes = v;
        }
        if let Some(v) = self.event_count {
            usage.event_count = v;
        }
        if let Some(v) = self.event_bytes {
            usage.event_bytes = v;
        }
        usage
    }
}

#[allow(clippy::too_many_arguments)]
async fn estimate(
    operation: &str,
    network: Option<String>,
    simulation_file: Option<PathBuf>,
    overrides: ManualOverrides,
    batch_size: u32,
    ledgers_until_expiry: Option<i64>,
    label: Option<String>,
    save: bool,
    deterministic: bool,
    model: &str,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let op = OperationKind::parse(operation)?;
    let cfg = config::load().unwrap_or_default();
    let network = network.unwrap_or(cfg.network);
    config::validate_network(&network)?;

    let base_usage = match &simulation_file {
        Some(path) => {
            config::validate_file_path(path, Some("json"))?;
            let contents = fs::read_to_string(path)
                .with_context(|| format!("Failed to read simulation file {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&contents).with_context(|| {
                format!("Failed to parse simulation file {} as JSON", path.display())
            })?;
            adapter::normalize_from_rpc_envelope(&value).with_context(|| {
                format!("Failed to normalize simulation file {}", path.display())
            })?
        }
        None => ResourceUsage::default(),
    };
    let usage = overrides.apply(base_usage);

    let mut cost_estimate = estimate_cost(&usage, op, &network, batch_size, ledgers_until_expiry);

    p::header("Soroban Cost Estimate");
    p::kv("Operation", op.as_str());
    p::kv("Network", &network);

    let explanation = if deterministic {
        println!(
            "{} Using deterministic cost engine (AI assistance disabled).",
            "📊".cyan()
        );
        explain::deterministic_explanation(&cost_estimate)
    } else {
        match explain::maybe_generate_ai_narrative(&cost_estimate, model).await {
            Ok(Some(narrative)) => format!(
                "{}\n\n---\n\nAI narrative:\n\n{}",
                explain::deterministic_explanation(&cost_estimate),
                narrative
            ),
            Ok(None) => {
                println!(
                    "{} Using deterministic cost engine (AI assistance unavailable/unconfigured).",
                    "📊".cyan()
                );
                explain::deterministic_explanation(&cost_estimate)
            }
            Err(e) => {
                eprintln!(
                    "{} Warning: AI narrative generation failed: {}. Falling back to deterministic explanation.",
                    "⚠".yellow().bold(),
                    e
                );
                explain::deterministic_explanation(&cost_estimate)
            }
        }
    };

    if save {
        let label = label.unwrap_or_else(|| DEFAULT_HISTORY_LABEL.to_string());
        let path = history::save_snapshot(&label, &cost_estimate)?;
        p::success(&format!("Saved snapshot to {}", path.display()));
        cost_estimate.label = Some(label);
    }

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&cost_estimate)?
    } else {
        format_estimate_markdown(&cost_estimate, Some(&explanation))
    };
    let rendered = redact_text(&rendered);

    write_or_print(&rendered, output)
}

fn compare(
    label: Option<String>,
    baseline_path: Option<PathBuf>,
    candidate_path: Option<PathBuf>,
    format: &str,
) -> Result<()> {
    let (baseline, candidate) = if let Some(label) = label {
        let snapshots = history::load_all_snapshots(&label)?;
        if snapshots.len() < 2 {
            anyhow::bail!(
                "Need at least 2 saved estimates for label '{}' to compare; found {}",
                label,
                snapshots.len()
            );
        }
        let candidate = snapshots[snapshots.len() - 1].estimate.clone();
        let baseline = snapshots[snapshots.len() - 2].estimate.clone();
        (baseline, candidate)
    } else {
        let baseline_path =
            baseline_path.context("--baseline is required when --label is not given")?;
        let candidate_path =
            candidate_path.context("--candidate is required when --label is not given")?;
        (
            load_estimate_file(&baseline_path)?,
            load_estimate_file(&candidate_path)?,
        )
    };

    let delta = candidate.total_fee_stroops as i64 - baseline.total_fee_stroops as i64;
    let pct = if baseline.total_fee_stroops == 0 {
        0.0
    } else {
        (delta as f64 / baseline.total_fee_stroops as f64) * 100.0
    };

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&serde_json::json!({
            "baseline": baseline,
            "candidate": candidate,
            "delta_stroops": delta,
            "delta_percent": pct,
        }))?
    } else {
        let mut md = String::new();
        md.push_str("# Cost Comparison\n\n");
        md.push_str("| Metric | Baseline | Candidate | Delta |\n|---|---|---|---|\n");
        md.push_str(&format!(
            "| Total fee (stroops) | {} | {} | {} ({:+.2}%) |\n",
            baseline.total_fee_stroops,
            candidate.total_fee_stroops,
            if delta >= 0 {
                format!("+{}", delta)
            } else {
                delta.to_string()
            },
            pct
        ));
        md
    };

    write_or_print(&redact_text(&rendered), None)
}

fn budget(label: &str, max_fee_stroops: u64, format: &str) -> Result<()> {
    let latest = history::load_latest(label)?
        .with_context(|| format!("No cost history found for label '{}'", label))?;
    let over_budget = latest.estimate.total_fee_stroops > max_fee_stroops;

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&serde_json::json!({
            "label": label,
            "max_fee_stroops": max_fee_stroops,
            "actual_fee_stroops": latest.estimate.total_fee_stroops,
            "over_budget": over_budget,
        }))?
    } else {
        format!(
            "Budget check for '{}': {} stroops actual vs {} stroops budget — {}",
            label,
            latest.estimate.total_fee_stroops,
            max_fee_stroops,
            if over_budget {
                "OVER BUDGET".red().bold().to_string()
            } else {
                "within budget".green().to_string()
            }
        )
    };

    println!("{}", redact_text(&rendered));
    if over_budget {
        anyhow::bail!(
            "Estimate for '{}' ({} stroops) exceeds budget of {} stroops",
            label,
            latest.estimate.total_fee_stroops,
            max_fee_stroops
        );
    }
    Ok(())
}

fn export(label: &str, format: &str, output: Option<PathBuf>) -> Result<()> {
    let rendered = history::export_history(label, format)?;
    write_or_print(&redact_text(&rendered), output)
}

fn check_regression(label: &str, threshold_percent: f64, format: &str) -> Result<()> {
    let result = history::check_regression(label, threshold_percent)?;

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&result)?
    } else {
        format!(
            "Regression check for '{}': candidate {} stroops, baseline {}, delta {:+.2}% (threshold {:.2}%) — {}",
            label,
            result.candidate_fee_stroops,
            result
                .baseline_fee_stroops
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a (first run)".to_string()),
            result.delta_percent,
            threshold_percent,
            if result.regressed {
                "REGRESSED".red().bold().to_string()
            } else {
                "OK".green().to_string()
            }
        )
    };

    println!("{}", redact_text(&rendered));
    if result.regressed {
        anyhow::bail!(
            "Cost regression detected for '{}': +{:.2}% exceeds threshold of {:.2}%",
            label,
            result.delta_percent,
            threshold_percent
        );
    }
    Ok(())
}

fn load_estimate_file(path: &PathBuf) -> Result<model::CostEstimate> {
    config::validate_file_path(path, Some("json"))?;
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read estimate file {}", path.display()))?;
    if let Ok(snapshot) = serde_json::from_str::<history::HistorySnapshot>(&contents) {
        return Ok(snapshot.estimate);
    }
    serde_json::from_str(&contents).with_context(|| {
        format!(
            "Failed to parse {} as a cost estimate or snapshot",
            path.display()
        )
    })
}

fn format_estimate_markdown(estimate: &model::CostEstimate, explanation: Option<&str>) -> String {
    let mut md = String::new();
    md.push_str("# Soroban Cost Estimate\n\n");
    md.push_str(&format!(
        "**Operation:** `{}`\n",
        estimate.operation.as_str()
    ));
    md.push_str(&format!("**Network:** `{}`\n", estimate.network));
    md.push_str(&format!("**Batch size:** {}\n\n", estimate.batch_size));

    md.push_str("## Breakdown\n\n");
    md.push_str("| Component | Stroops |\n|---|---|\n");
    for (name, amount) in estimate.breakdown.ranked_components() {
        md.push_str(&format!("| {} | {} |\n", name, amount));
    }
    md.push_str(&format!(
        "| **Total** | **{} ({:.7} XLM)** |\n\n",
        estimate.total_fee_stroops, estimate.total_fee_xlm
    ));

    if !estimate.notes.is_empty() {
        md.push_str("## Notes\n\n");
        for note in &estimate.notes {
            md.push_str(&format!("- {}\n", note));
        }
        md.push('\n');
    }

    if let Some(explanation) = explanation {
        md.push_str("## Explanation\n\n");
        md.push_str(explanation);
        md.push('\n');
    }

    md
}

fn write_or_print(rendered: &str, output: Option<PathBuf>) -> Result<()> {
    match output {
        Some(path) => {
            fs::write(&path, rendered)
                .with_context(|| format!("Failed to write output to {}", path.display()))?;
            p::success(&format!("Report written to {}", path.display()));
        }
        None => println!("\n{}", rendered),
    }
    Ok(())
}
