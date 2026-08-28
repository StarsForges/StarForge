//! `starforge budget` — CLI surface for enforceable transaction fee and
//! Soroban resource budgets (issue #100).
//!
//! This module owns terminal rendering, argument parsing, and file I/O
//! orchestration; all decision logic lives in `crate::utils::budget` and is
//! unit-tested there without a terminal or network in the loop. See
//! `docs/budgets.md` for the user-facing guide.

use crate::commands::ai::impact::redactor::redact_text;
use crate::commands::cost::adapter;
use crate::utils::budget::audit::{self, AuditRecord};
use crate::utils::budget::baseline;
use crate::utils::budget::enforce::{self, Decision, EnforcementReport, Severity};
use crate::utils::budget::metrics::{BudgetMetrics, MetricKind};
use crate::utils::budget::policy::{self, BudgetPolicyDocument, Scope};
use crate::utils::{config, print as p};
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum BudgetCommands {
    /// Create a starting budget policy file with sensible default limits
    Init {
        /// Where to write the policy (default: <data_dir>/budget/policy.json,
        /// or $STARFORGE_BUDGET_POLICY when set)
        #[arg(long)]
        path: Option<PathBuf>,
        /// Overwrite an existing policy file
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Evaluate a single operation's metrics against the resolved policy
    Check {
        /// Command scope to resolve limits for (e.g. deploy, invoke, batch-pay, tx-send)
        #[arg(long)]
        command: String,
        /// Network scope (default: config network)
        #[arg(long)]
        network: Option<String>,
        /// Contract-level scope (contract ID/address)
        #[arg(long)]
        contract: Option<String>,
        /// Function-level scope (function name)
        #[arg(long)]
        function: Option<String>,

        /// Path to a raw Soroban RPC simulateTransaction JSON response/fixture
        #[arg(long)]
        simulation_file: Option<PathBuf>,

        /// Manual classic transaction fee, in stroops
        #[arg(long, default_value_t = 0)]
        classic_fee_stroops: u64,
        /// Manual Soroban resource fee, in stroops
        #[arg(long, default_value_t = 0)]
        resource_fee_stroops: u64,
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
        /// Manual total bytes of emitted event data
        #[arg(long)]
        event_bytes: Option<u64>,
        /// Manual transaction envelope size in bytes
        #[arg(long, default_value_t = 0)]
        tx_size_bytes: u64,

        /// Explicit one-time override reason if a hard limit is expected to be exceeded
        #[arg(long)]
        budget_override_reason: Option<String>,

        /// Explicit policy file path (default: resolved via env/data dir)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },

    /// Capture the current metrics for a label as a baseline snapshot
    Baseline {
        /// Baseline label to capture under
        #[arg(long, default_value = "default")]
        label: String,

        /// Path to a raw Soroban RPC simulateTransaction JSON response/fixture
        #[arg(long)]
        simulation_file: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        classic_fee_stroops: u64,
        #[arg(long, default_value_t = 0)]
        resource_fee_stroops: u64,
        #[arg(long)]
        cpu_insns: Option<u64>,
        #[arg(long)]
        mem_bytes: Option<u64>,
        #[arg(long)]
        read_entries: Option<u32>,
        #[arg(long)]
        write_entries: Option<u32>,
        #[arg(long)]
        read_bytes: Option<u64>,
        #[arg(long)]
        write_bytes: Option<u64>,
        #[arg(long)]
        event_bytes: Option<u64>,
        #[arg(long, default_value_t = 0)]
        tx_size_bytes: u64,
    },

    /// Compare the two most recent baseline captures for a label and fail on regression
    Diff {
        /// Baseline label to diff
        #[arg(long, default_value = "default")]
        label: String,
        /// Maximum acceptable percentage increase per metric before it's a regression
        #[arg(long, default_value_t = 10.0)]
        threshold_percent: f64,
        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },

    /// Show the effective (resolved) limits for a given scope and which policy layers set them
    Explain {
        #[arg(long)]
        command: String,
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        contract: Option<String>,
        #[arg(long)]
        function: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },

    /// Show recent budget enforcement decisions from the audit log
    Audit {
        /// Only show records with this decision (allow, warn, block, override-allowed)
        #[arg(long)]
        decision: Option<String>,
        /// Only show records for this command scope
        #[arg(long)]
        command: Option<String>,
        /// Maximum number of records to show (0 = unlimited), most recent first
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,
    },
}

pub fn handle(cmd: BudgetCommands) -> Result<()> {
    match cmd {
        BudgetCommands::Init { path, force } => init(path, force),
        BudgetCommands::Check {
            command,
            network,
            contract,
            function,
            simulation_file,
            classic_fee_stroops,
            resource_fee_stroops,
            cpu_insns,
            mem_bytes,
            read_entries,
            write_entries,
            read_bytes,
            write_bytes,
            event_bytes,
            tx_size_bytes,
            budget_override_reason,
            policy,
            format,
        } => check(CheckParams {
            command,
            network,
            contract,
            function,
            simulation_file,
            classic_fee_stroops,
            resource_fee_stroops,
            manual: ManualOverrides {
                cpu_insns,
                mem_bytes,
                read_entries,
                write_entries,
                read_bytes,
                write_bytes,
                event_bytes,
            },
            tx_size_bytes,
            budget_override_reason,
            policy,
            format,
        }),
        BudgetCommands::Baseline {
            label,
            simulation_file,
            classic_fee_stroops,
            resource_fee_stroops,
            cpu_insns,
            mem_bytes,
            read_entries,
            write_entries,
            read_bytes,
            write_bytes,
            event_bytes,
            tx_size_bytes,
        } => capture_baseline(
            &label,
            simulation_file,
            classic_fee_stroops,
            resource_fee_stroops,
            ManualOverrides {
                cpu_insns,
                mem_bytes,
                read_entries,
                write_entries,
                read_bytes,
                write_bytes,
                event_bytes,
            },
            tx_size_bytes,
        ),
        BudgetCommands::Diff {
            label,
            threshold_percent,
            format,
        } => diff(&label, threshold_percent, &format),
        BudgetCommands::Explain {
            command,
            network,
            contract,
            function,
            policy,
            format,
        } => explain(command, network, contract, function, policy, &format),
        BudgetCommands::Audit {
            decision,
            command,
            limit,
            format,
        } => audit_log(decision, command, limit, &format),
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
    event_bytes: Option<u64>,
}

impl ManualOverrides {
    fn apply(self, mut usage: adapter_types::ResourceUsage) -> adapter_types::ResourceUsage {
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
        if let Some(v) = self.event_bytes {
            usage.event_bytes = v;
        }
        usage
    }
}

/// Re-exported locally so `ManualOverrides` doesn't need to spell out the
/// full path at every use; `ResourceUsage` itself is owned by
/// `commands::cost::model` since it is the RPC-normalization shape shared
/// with `starforge cost`.
mod adapter_types {
    pub use crate::commands::cost::model::ResourceUsage;
}

fn load_usage(simulation_file: &Option<PathBuf>) -> Result<adapter_types::ResourceUsage> {
    match simulation_file {
        Some(path) => {
            config::validate_file_path(path, Some("json"))?;
            let contents = fs::read_to_string(path)
                .with_context(|| format!("Failed to read simulation file {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&contents).with_context(|| {
                format!("Failed to parse simulation file {} as JSON", path.display())
            })?;
            adapter::normalize_from_rpc_envelope(&value)
                .with_context(|| format!("Failed to normalize simulation file {}", path.display()))
        }
        None => Ok(adapter_types::ResourceUsage::default()),
    }
}

fn build_metrics(
    simulation_file: &Option<PathBuf>,
    classic_fee_stroops: u64,
    resource_fee_stroops: u64,
    manual: ManualOverrides,
    tx_size_bytes: u64,
) -> Result<BudgetMetrics> {
    let usage = manual.apply(load_usage(simulation_file)?);
    Ok(BudgetMetrics::from_parts(
        classic_fee_stroops,
        resource_fee_stroops,
        usage.cpu_insns,
        usage.mem_bytes,
        usage.read_entries,
        usage.write_entries,
        usage.read_bytes,
        usage.write_bytes,
        usage.event_bytes,
        tx_size_bytes,
    ))
}

fn init(path: Option<PathBuf>, force: bool) -> Result<()> {
    let path = policy::resolve_policy_path(path.as_deref())?;
    if path.exists() && !force {
        anyhow::bail!(
            "Budget policy already exists at {}. Use --force to overwrite.",
            path.display()
        );
    }
    let doc = BudgetPolicyDocument::default_policy();
    policy::save_policy(&path, &doc)?;
    p::header("Budget Policy Initialized");
    p::kv("Path", &path.display().to_string());
    p::kv("Schema version", &doc.schema_version.to_string());
    p::success("Default budget policy written. Edit the file to add network/command/contract/function overrides.");
    println!(
        "\n{} Run `starforge budget explain --command deploy` to see the effective limits.",
        "→".cyan()
    );
    Ok(())
}

struct CheckParams {
    command: String,
    network: Option<String>,
    contract: Option<String>,
    function: Option<String>,
    simulation_file: Option<PathBuf>,
    classic_fee_stroops: u64,
    resource_fee_stroops: u64,
    manual: ManualOverrides,
    tx_size_bytes: u64,
    budget_override_reason: Option<String>,
    policy: Option<PathBuf>,
    format: String,
}

fn check(params: CheckParams) -> Result<()> {
    let cfg = config::load().unwrap_or_default();
    let network = params.network.unwrap_or(cfg.network);
    config::validate_network(&network)?;

    let metrics = build_metrics(
        &params.simulation_file,
        params.classic_fee_stroops,
        params.resource_fee_stroops,
        params.manual,
        params.tx_size_bytes,
    )?;

    let policy_path = policy::resolve_policy_path(params.policy.as_deref())?;
    let document = policy::load_policy_if_present(&policy_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No budget policy found at {}. Run `starforge budget init` first.",
            policy_path.display()
        )
    })?;

    let scope = Scope {
        command: &params.command,
        network: &network,
        contract: params.contract.as_deref(),
        function: params.function.as_deref(),
    };
    let resolved = document.resolve(&scope);
    let report = enforce::evaluate(&scope, metrics, &resolved);
    // Redact before it reaches the audit log or `report.override_reason`: an
    // override reason is free text typed under time pressure and could
    // accidentally contain a secret (a pasted key, a local path).
    let redacted_override_reason = params.budget_override_reason.as_deref().map(redact_text);
    let report = enforce::apply_override(report, redacted_override_reason.as_deref())
        .map_err(anyhow::Error::msg)?;

    audit::append_record(&AuditRecord::from_report(&report))?;

    render_report(&report, &params.format)?;

    if report.decision.blocks() {
        anyhow::bail!(report.block_message());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn capture_baseline(
    label: &str,
    simulation_file: Option<PathBuf>,
    classic_fee_stroops: u64,
    resource_fee_stroops: u64,
    manual: ManualOverrides,
    tx_size_bytes: u64,
) -> Result<()> {
    let metrics = build_metrics(
        &simulation_file,
        classic_fee_stroops,
        resource_fee_stroops,
        manual,
        tx_size_bytes,
    )?;
    let path = baseline::save_snapshot(label, metrics)?;
    p::header("Budget Baseline Captured");
    p::kv("Label", label);
    p::kv("Snapshot", &path.display().to_string());
    for kind in MetricKind::ALL {
        let value = metrics.value_of(kind);
        if value > 0 {
            p::kv(kind.label(), &value.to_string());
        }
    }
    Ok(())
}

fn diff(label: &str, threshold_percent: f64, format: &str) -> Result<()> {
    let result = baseline::diff(label, threshold_percent)?;

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&result)?
    } else {
        let mut md = String::new();
        md.push_str(&format!("# Budget Diff: {}\n\n", label));
        md.push_str(&format!(
            "Baseline: {} → Candidate: {} (threshold {:.1}%)\n\n",
            result.baseline_timestamp, result.candidate_timestamp, threshold_percent
        ));
        md.push_str("| Metric | Baseline | Candidate | Delta | Status |\n|---|---|---|---|---|\n");
        for delta in &result.deltas {
            if delta.baseline == 0 && delta.candidate == 0 {
                continue;
            }
            md.push_str(&format!(
                "| {} | {} | {} | {:+} ({:+.1}%) | {} |\n",
                delta.metric.label(),
                delta.baseline,
                delta.candidate,
                delta.delta,
                delta.delta_percent,
                if delta.regressed {
                    "REGRESSED".red().bold().to_string()
                } else {
                    "ok".green().to_string()
                }
            ));
        }
        md
    };

    println!("{}", redact_text(&rendered));
    if result.regressed {
        anyhow::bail!(
            "Budget regression detected for '{}': one or more metrics increased beyond {:.1}%",
            label,
            threshold_percent
        );
    }
    Ok(())
}

fn explain(
    command: String,
    network: Option<String>,
    contract: Option<String>,
    function: Option<String>,
    policy_path: Option<PathBuf>,
    format: &str,
) -> Result<()> {
    let cfg = config::load().unwrap_or_default();
    let network = network.unwrap_or(cfg.network);
    let path = policy::resolve_policy_path(policy_path.as_deref())?;
    let document = policy::load_policy_if_present(&path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No budget policy found at {}. Run `starforge budget init` first.",
            path.display()
        )
    })?;

    let scope = Scope {
        command: &command,
        network: &network,
        contract: contract.as_deref(),
        function: function.as_deref(),
    };
    let resolved = document.resolve(&scope);

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&serde_json::json!({
            "policy_path": path,
            "policy_name": document.name,
            "scope": {
                "command": command,
                "network": network,
                "contract": contract,
                "function": function,
            },
            "contributing_layers": resolved.contributing_layers,
            "warning_threshold_percent": resolved.warning_threshold_percent,
            "limits": resolved.limits,
        }))?
    } else {
        let mut md = String::new();
        md.push_str("# Effective Budget Limits\n\n");
        md.push_str(&format!(
            "**Policy:** `{}` ({})\n",
            document.name,
            path.display()
        ));
        md.push_str(&format!(
            "**Scope:** command=`{}` network=`{}` contract=`{}` function=`{}`\n\n",
            command,
            network,
            contract.as_deref().unwrap_or("-"),
            function.as_deref().unwrap_or("-"),
        ));
        if resolved.contributing_layers.is_empty() {
            md.push_str("_No policy layer sets any limit for this scope._\n");
        } else {
            md.push_str(&format!(
                "**Contributing layers (narrowest wins):** {}\n\n",
                resolved.contributing_layers.join(" → ")
            ));
            md.push_str("| Metric | Limit |\n|---|---|\n");
            for kind in MetricKind::ALL {
                if let Some(limit) = resolved.limits.limit_of(kind) {
                    md.push_str(&format!("| {} | {} |\n", kind.label(), limit));
                }
            }
            md.push_str(&format!(
                "\nWarning threshold: {:.1}% of limit\n",
                resolved.warning_threshold_percent
            ));
        }
        md
    };

    println!("{}", redact_text(&rendered));
    Ok(())
}

fn audit_log(
    decision: Option<String>,
    command: Option<String>,
    limit: usize,
    format: &str,
) -> Result<()> {
    let parsed_decision = decision.map(|d| parse_decision(&d)).transpose()?;
    let records = audit::read_records()?;
    let filtered = audit::filter_records(records, parsed_decision, command.as_deref(), limit);

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&filtered)?
    } else if filtered.is_empty() {
        "No matching budget audit records found.".to_string()
    } else {
        let mut md = String::new();
        md.push_str("# Budget Audit Log\n\n");
        md.push_str("| Timestamp | Command | Network | Decision | Violations | Override Reason |\n|---|---|---|---|---|---|\n");
        for record in &filtered {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                record.timestamp.to_rfc3339(),
                record.command,
                record.network,
                decision_label(record.decision),
                record.violation_metrics.join(", "),
                record.override_reason.as_deref().unwrap_or("-"),
            ));
        }
        md
    };

    println!("{}", redact_text(&rendered));
    Ok(())
}

fn parse_decision(value: &str) -> Result<Decision> {
    match value {
        "allow" => Ok(Decision::Allow),
        "warn" => Ok(Decision::Warn),
        "block" => Ok(Decision::Block),
        "override-allowed" | "override" => Ok(Decision::OverrideAllowed),
        other => anyhow::bail!(
            "Unknown decision '{}'. Expected one of: allow, warn, block, override-allowed",
            other
        ),
    }
}

fn decision_label(decision: Decision) -> colored::ColoredString {
    match decision {
        Decision::Allow => "allow".green(),
        Decision::Warn => "warn".yellow(),
        Decision::Block => "block".red().bold(),
        Decision::OverrideAllowed => "override-allowed".magenta(),
    }
}

/// Renders a full enforcement report — used by both `starforge budget check`
/// and the pre-signing hooks in deploy/invoke/batch/tx so the two surfaces
/// stay visually consistent.
pub fn render_report(report: &EnforcementReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    p::header("Budget Check");
    p::kv("Command", &report.command);
    p::kv("Network", &report.network);
    if let Some(ref contract) = report.contract {
        p::kv("Contract", contract);
    }
    if let Some(ref function) = report.function {
        p::kv("Function", function);
    }
    if report.policy_layers.is_empty() {
        p::info("No policy layer applies to this scope; nothing was enforced.");
    } else {
        p::kv("Policy layers", &report.policy_layers.join(" → "));
    }

    for check in &report.checks {
        let line = format!(
            "{}: {} vs limit {} ({:.1}%)",
            check.metric.label(),
            check.actual,
            check.limit,
            check.ratio_percent
        );
        match check.severity {
            Severity::Violation => p::warn(&format!("VIOLATION — {}", line)),
            Severity::Warning => p::warn(&format!("warning — {}", line)),
        }
    }

    match report.decision {
        Decision::Allow => p::success("Within budget."),
        Decision::Warn => p::warn("Within hard limits, but approaching the warning threshold."),
        Decision::Block => p::error("Blocked: one or more hard limits were exceeded."),
        Decision::OverrideAllowed => p::warn(&format!(
            "Allowed via override: {}",
            report
                .override_reason
                .as_deref()
                .unwrap_or("(no reason recorded)")
        )),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decision_accepts_known_values() {
        assert_eq!(parse_decision("allow").unwrap(), Decision::Allow);
        assert_eq!(
            parse_decision("override").unwrap(),
            Decision::OverrideAllowed
        );
        assert!(parse_decision("nonsense").is_err());
    }
}
