//! Report rendering for the performance profiling system.
//!
//! Supports two output modes:
//! - `human`: Colored, tabular terminal output with severity badges and progress bars.
//! - `json`: Stable machine-readable JSON suitable for CI scripts and automation.

use crate::utils::performance::baseline::BaselineSnapshot;
use crate::utils::performance::flame::FlameSummary;
use crate::utils::performance::metrics::{BudgetCheckResult, ProfileDelta, ProfileMetrics};
use crate::utils::performance::optimizer::{OptimizationReport, Severity};
use colored::*;
use serde::{Deserialize, Serialize};

// ── Full profile run report ───────────────────────────────────────────────────

/// Machine-readable representation of a full profile run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRunOutput {
    pub metrics: ProfileMetrics,
    pub optimization_report: OptimizationReport,
    pub flame: Option<FlameSummary>,
    pub baseline_comparison: Option<BaselineComparison>,
}

/// Machine-readable representation of a comparison against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_label: String,
    pub baseline_timestamp: String,
    pub delta: ProfileDelta,
}

// ── Human rendering ───────────────────────────────────────────────────────────

/// Print a full profile run to stdout in human-readable format.
pub fn print_profile_run(output: &ProfileRunOutput, show_flame: bool, quiet: bool) {
    let m = &output.metrics;

    if !quiet {
        println!(
            "\n{}",
            format!("  Performance Profile — {}", m.contract_label)
                .bright_white()
                .bold()
                .underline()
        );
        println!("  {} {}", "Network:".dimmed(), m.network.cyan());
        println!(
            "  {} {}",
            "Timestamp:".dimmed(),
            m.timestamp.to_rfc3339().dimmed()
        );
        println!();
    }

    // Resource metrics table
    println!("{}", "  Resource Usage".bright_white().bold());
    println!("  {}", "─".repeat(60).dimmed());
    print_metric(
        "CPU Instructions",
        m.cpu_insns,
        util_badge(m.cpu_utilization()),
    );
    print_metric("Peak Memory", m.mem_bytes, util_badge(m.mem_utilization()));
    print_metric_plain("Sim Fee (stroops)", &m.sim_fee_stroops.to_string());
    print_metric_plain(
        "Storage Reads",
        &format!(
            "{} keys  ({} bytes)",
            m.storage.read_only_keys, m.storage.total_read_bytes
        ),
    );
    print_metric_plain(
        "Storage Writes",
        &format!(
            "{} keys  ({} bytes)",
            m.storage.read_write_keys, m.storage.total_write_bytes
        ),
    );
    print_metric_plain(
        "Events",
        &format!(
            "{}  ({} bytes total, {:.0} avg)",
            m.events.event_count, m.events.total_event_bytes, m.events.avg_event_bytes
        ),
    );

    if !m.simulation_errors.is_empty() {
        println!("\n  {} Simulation errors:", "✗".red().bold());
        for e in &m.simulation_errors {
            println!("    {}", e.red());
        }
    }

    if !m.notes.is_empty() {
        println!("\n  {} Notes:", "ℹ".cyan());
        for n in &m.notes {
            println!("    {}", n.dimmed());
        }
    }

    // Optimization recommendations
    println!();
    print_optimization_report(&output.optimization_report);

    // Baseline comparison
    if let Some(cmp) = &output.baseline_comparison {
        println!();
        print_comparison(cmp);
    }

    // Flame summary
    if show_flame {
        if let Some(flame) = &output.flame {
            println!();
            println!("{}", "  Flame Summary".bright_white().bold());
            println!("  {}", "─".repeat(60).dimmed());
            for line in flame.text.lines() {
                println!("  {}", line);
            }
        }
    }
}

fn print_metric(label: &str, value: u64, badge: ColoredString) {
    println!(
        "  {:<24} {:>14}  {}",
        label.dimmed(),
        value.to_string().bright_white(),
        badge
    );
}

fn print_metric_plain(label: &str, value: &str) {
    println!("  {:<24} {}", label.dimmed(), value.bright_white());
}

fn util_badge(util: f64) -> ColoredString {
    if util >= 0.80 {
        format!("[{:.1}% ⚠ CRITICAL]", util * 100.0).red().bold()
    } else if util >= 0.50 {
        format!("[{:.1}% ⚠ HIGH]", util * 100.0).yellow().bold()
    } else if util >= 0.20 {
        format!("[{:.1}%]", util * 100.0).cyan()
    } else {
        format!("[{:.1}%]", util * 100.0).green()
    }
}

/// Print an optimization report section.
pub fn print_optimization_report(report: &OptimizationReport) {
    let counts = &report.severity_counts;
    println!("{}", "  Optimization Recommendations".bright_white().bold());
    println!("  {}", "─".repeat(60).dimmed());

    if report.recommendations.is_empty() {
        println!(
            "  {} No issues found — contract profile looks healthy.",
            "✓".green().bold()
        );
        return;
    }

    println!(
        "  {} Critical  {} High  {} Medium  {} Low  {} Info",
        format!("{}", counts.critical).red().bold(),
        format!("{}", counts.high).yellow().bold(),
        format!("{}", counts.medium).cyan(),
        format!("{}", counts.low).white(),
        format!("{}", counts.info).dimmed(),
    );
    println!();

    for rec in &report.recommendations {
        let badge = severity_badge(&rec.severity);
        println!(
            "  {} {} [{}]",
            badge,
            rec.title.bright_white(),
            rec.category.as_str().dimmed()
        );
        println!("    {}", rec.rationale.dimmed());
        println!("    {} {}", "Before:".dimmed(), rec.before.yellow());
        println!("    {} {}", "After: ".dimmed(), rec.after.green());
        if !rec.estimated_savings.is_empty() && rec.estimated_savings != "N/A" {
            println!(
                "    {} {}",
                "Saves: ".dimmed(),
                rec.estimated_savings.cyan()
            );
        }
        println!();
    }

    if let Some(narrative) = &report.ai_narrative {
        println!(
            "  {} AI Optimization Narrative\n  {}\n",
            "✦".cyan(),
            "─".repeat(60).dimmed()
        );
        for line in narrative.lines() {
            println!("  {}", line);
        }
        println!();
    }
}

fn severity_badge(s: &Severity) -> ColoredString {
    match s {
        Severity::Critical => " CRIT ".on_red().white().bold(),
        Severity::High => " HIGH ".on_yellow().black().bold(),
        Severity::Medium => " MED  ".on_cyan().black(),
        Severity::Low => " LOW  ".on_white().black(),
        Severity::Info => " INFO ".on_bright_black().white(),
    }
}

/// Print a delta comparison section.
pub fn print_comparison(cmp: &BaselineComparison) {
    println!("{}", "  Baseline Comparison".bright_white().bold());
    println!("  {}", "─".repeat(60).dimmed());
    println!(
        "  {:<24} {}  ({})",
        "Baseline label:".dimmed(),
        cmp.baseline_label.cyan(),
        cmp.baseline_timestamp.dimmed()
    );
    let d = &cmp.delta;
    print_delta_row("CPU instructions", d.cpu_insns_delta, d.cpu_insns_pct);
    print_delta_row("Peak memory (bytes)", d.mem_bytes_delta, d.mem_bytes_pct);
    print_delta_row("Sim fee (stroops)", d.fee_stroops_delta, d.fee_stroops_pct);

    if d.regressed {
        println!(
            "\n  {} Regression detected — the following metrics exceeded the threshold:",
            "⚠".yellow().bold()
        );
        for detail in &d.regression_details {
            println!("    • {}", detail.red());
        }
    } else {
        println!("\n  {} No regressions detected.", "✓".green().bold());
    }
}

fn print_delta_row(label: &str, delta: i64, pct: f64) {
    let pct_str = if pct > 0.0 {
        format!("+{:.1}%", pct).red().to_string()
    } else if pct < 0.0 {
        format!("{:.1}%", pct).green().to_string()
    } else {
        "  0.0%".dimmed().to_string()
    };
    let delta_str = if delta > 0 {
        format!("+{}", delta).red().to_string()
    } else if delta < 0 {
        format!("{}", delta).green().to_string()
    } else {
        "0".dimmed().to_string()
    };
    println!(
        "  {:<24} delta: {:>12}  ({})",
        label.dimmed(),
        delta_str,
        pct_str
    );
}

/// Print a budget check result.
pub fn print_budget_check(metrics: &ProfileMetrics, result: &BudgetCheckResult) {
    println!("{}", "  Budget Check".bright_white().bold());
    println!("  {}", "─".repeat(60).dimmed());
    if result.passed {
        println!("  {} All budget thresholds passed.", "✓".green().bold());
    } else {
        println!(
            "  {} Budget violations detected ({}):",
            "✗".red().bold(),
            result.violations.len()
        );
        for v in &result.violations {
            println!("    • {}", v.red());
        }
    }
    println!(
        "  Contract: {}  CPU: {}  Mem: {}  Fee: {} stroops",
        metrics.contract_label.cyan(),
        metrics.cpu_insns.to_string().bright_white(),
        metrics.mem_bytes.to_string().bright_white(),
        metrics.sim_fee_stroops.to_string().bright_white(),
    );
}

/// Print a baseline listing.
pub fn print_baseline_list(label: &str, snapshots: &[BaselineSnapshot]) {
    println!(
        "{}\n  {}",
        format!("  Baselines for '{}'", label).bright_white().bold(),
        "─".repeat(60).dimmed()
    );
    if snapshots.is_empty() {
        println!("  (no baselines saved for this label)");
        return;
    }
    println!(
        "  {:<28} {:>16} {:>14} {:>12}",
        "Timestamp".dimmed(),
        "CPU insns".dimmed(),
        "Mem bytes".dimmed(),
        "Fee stroops".dimmed()
    );
    for s in snapshots {
        println!(
            "  {:<28} {:>16} {:>14} {:>12}",
            s.timestamp.to_rfc3339().dimmed(),
            s.metrics.cpu_insns.to_string().bright_white(),
            s.metrics.mem_bytes.to_string().bright_white(),
            s.metrics.sim_fee_stroops.to_string().bright_white(),
        );
    }
}
