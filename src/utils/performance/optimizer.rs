//! Deterministic optimization rule engine for Soroban contract profiles.
//!
//! Each rule evaluates a [`ProfileMetrics`] value and optionally emits a
//! [`Recommendation`] with severity, category, rationale, and before/after
//! guidance. Rules are pure functions with no external dependencies, enabling
//! deterministic behavior and unit testing without mocking.
//!
//! The AI layer in [`generate_ai_narrative`] wraps the deterministic
//! recommendations with an LLM-generated narrative and is optional — the
//! caller always receives the rule-based output even when no API key is set.

use crate::utils::performance::metrics::ProfileMetrics;
use serde::{Deserialize, Serialize};

// ── Recommendation types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    StorageLayout,
    ArgumentEncoding,
    Batching,
    EventUsage,
    AvoidableComputation,
    MemoryPressure,
    ArchivalRisk,
    General,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::StorageLayout => "storage-layout",
            Category::ArgumentEncoding => "argument-encoding",
            Category::Batching => "batching",
            Category::EventUsage => "event-usage",
            Category::AvoidableComputation => "avoidable-computation",
            Category::MemoryPressure => "memory-pressure",
            Category::ArchivalRisk => "archival-risk",
            Category::General => "general",
        }
    }
}

/// A single optimization recommendation produced by the rule engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub severity: Severity,
    pub category: Category,
    /// Rule identifier for deduplication and tracking.
    pub rule_id: String,
    /// Short human-readable title.
    pub title: String,
    /// Explanation of why this matters in this contract's context.
    pub rationale: String,
    /// Concrete "before" description of the current pattern.
    pub before: String,
    /// Concrete "after" description of the recommended improvement.
    pub after: String,
    /// Estimated savings description (e.g. "~20% CPU reduction").
    pub estimated_savings: String,
}

/// Full optimization report for a single profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub contract_label: String,
    pub recommendations: Vec<Recommendation>,
    /// AI-generated narrative, populated only when an OpenAI key is available.
    pub ai_narrative: Option<String>,
    /// Deterministic summary produced regardless of AI availability.
    pub deterministic_summary: String,
    /// Total recommendation count by severity.
    pub severity_counts: SeverityCounts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl SeverityCounts {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

// ── Rule engine ───────────────────────────────────────────────────────────────

/// Thresholds used by the rule engine.
mod thresholds {
    pub const CPU_HIGH_INSNS: u64 = 50_000_000; // 50M insns — expensive invocation
    pub const CPU_MEDIUM_INSNS: u64 = 10_000_000; // 10M insns — notable cost
    pub const MEM_HIGH_BYTES: u64 = 20 * 1024 * 1024; // 20 MiB — high pressure
    pub const MEM_MEDIUM_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB — notable usage
    pub const WRITE_ENTRIES_BATCHING_HINT: u32 = 5; // many writes suggest batch opportunity
    pub const EVENT_OVERSIZED_BYTES: u64 = 512; // per-event size warning threshold
    pub const EVENT_HIGH_COUNT: u32 = 10; // many events per invocation
    pub const READ_ENTRIES_LAYOUT_HINT: u32 = 8; // many reads suggest layout improvement
    pub const ARG_COMPLEX_BYTES: u64 = 2048; // large argument payload
    pub const CPU_UTIL_CRITICAL: f64 = 0.80; // 80 % of per-tx CPU limit
    pub const CPU_UTIL_HIGH: f64 = 0.50;
}

type RuleFn = fn(&ProfileMetrics) -> Option<Recommendation>;

static RULES: &[RuleFn] = &[
    rule_high_cpu_compute,
    rule_medium_cpu_compute,
    rule_high_memory,
    rule_medium_memory,
    rule_many_write_entries,
    rule_many_read_entries,
    rule_oversized_events,
    rule_many_events,
    rule_complex_arguments,
    rule_archived_entries,
    rule_high_cpu_utilization,
    rule_no_metrics,
];

/// Run all rules against `metrics` and return a populated [`OptimizationReport`].
pub fn analyze(metrics: &ProfileMetrics) -> OptimizationReport {
    let recommendations: Vec<Recommendation> = RULES
        .iter()
        .filter_map(|rule| rule(metrics))
        .collect();

    let severity_counts = count_severities(&recommendations);
    let summary = build_deterministic_summary(metrics, &recommendations, &severity_counts);

    OptimizationReport {
        contract_label: metrics.contract_label.clone(),
        recommendations,
        ai_narrative: None,
        deterministic_summary: summary,
        severity_counts,
    }
}

fn count_severities(recs: &[Recommendation]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for r in recs {
        match r.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    counts
}

fn build_deterministic_summary(
    metrics: &ProfileMetrics,
    recs: &[Recommendation],
    counts: &SeverityCounts,
) -> String {
    if metrics.is_empty() {
        return "No resource usage captured — supply a simulation file or resource parameters."
            .to_string();
    }
    if recs.is_empty() {
        return format!(
            "Contract '{}' looks healthy: no optimization opportunities found for this profile.",
            metrics.contract_label
        );
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "Contract '{}' has {} recommendation(s): {} critical, {} high, {} medium, {} low, {} info.",
        metrics.contract_label,
        counts.total(),
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info,
    ));

    if counts.critical > 0 || counts.high > 0 {
        let top = recs
            .iter()
            .filter(|r| r.severity == Severity::Critical || r.severity == Severity::High)
            .take(3)
            .map(|r| format!("  • [{}] {}", r.severity.as_str().to_uppercase(), r.title))
            .collect::<Vec<_>>()
            .join("\n");
        lines.push(format!("Top priorities:\n{}", top));
    }

    lines.join("\n")
}

// ── Individual rules ──────────────────────────────────────────────────────────

fn rule_high_cpu_compute(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.cpu_insns < thresholds::CPU_HIGH_INSNS {
        return None;
    }
    Some(Recommendation {
        severity: Severity::High,
        category: Category::AvoidableComputation,
        rule_id: "cpu-high-compute".to_string(),
        title: "Excessive CPU instruction count".to_string(),
        rationale: format!(
            "This invocation consumed {} CPU instructions (>= {}M threshold). \
             High instruction counts increase fees and risk hitting the per-transaction budget.",
            m.cpu_insns, thresholds::CPU_HIGH_INSNS / 1_000_000
        ),
        before: format!(
            "Current: {} CPU instructions",
            m.cpu_insns
        ),
        after: "Cache intermediate results, avoid redundant iteration, and move pure \
                computation off-chain where possible to reduce instruction count."
            .to_string(),
        estimated_savings: "Potential 20–60% CPU reduction depending on the hot path.".to_string(),
    })
}

fn rule_medium_cpu_compute(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.cpu_insns < thresholds::CPU_MEDIUM_INSNS || m.cpu_insns >= thresholds::CPU_HIGH_INSNS {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Medium,
        category: Category::AvoidableComputation,
        rule_id: "cpu-medium-compute".to_string(),
        title: "Notable CPU instruction usage".to_string(),
        rationale: format!(
            "This invocation consumed {} CPU instructions. While not critical, \
             consider profiling hot paths for further reduction.",
            m.cpu_insns
        ),
        before: format!("Current: {} CPU instructions", m.cpu_insns),
        after: "Review loop-heavy logic and expensive host-function calls for optimization \
                opportunities."
            .to_string(),
        estimated_savings: "Potential 5–20% CPU reduction.".to_string(),
    })
}

fn rule_high_memory(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.mem_bytes < thresholds::MEM_HIGH_BYTES {
        return None;
    }
    Some(Recommendation {
        severity: Severity::High,
        category: Category::MemoryPressure,
        rule_id: "mem-high-pressure".to_string(),
        title: "High peak memory usage".to_string(),
        rationale: format!(
            "Peak memory reached {} MiB (>= 20 MiB threshold). \
             Soroban has a hard per-transaction memory limit; approaching it risks \
             transaction failure under complex inputs.",
            m.mem_bytes / (1024 * 1024)
        ),
        before: format!("Current: {} bytes ({:.1} MiB) peak memory", m.mem_bytes, m.mem_bytes as f64 / (1024.0 * 1024.0)),
        after: "Stream large datasets instead of loading them fully into memory. \
                Avoid storing temporary collections with unbounded growth."
            .to_string(),
        estimated_savings: "Reduced memory pressure; lower risk of hitting per-tx limits."
            .to_string(),
    })
}

fn rule_medium_memory(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.mem_bytes < thresholds::MEM_MEDIUM_BYTES || m.mem_bytes >= thresholds::MEM_HIGH_BYTES {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Medium,
        category: Category::MemoryPressure,
        rule_id: "mem-medium-pressure".to_string(),
        title: "Notable memory usage".to_string(),
        rationale: format!(
            "Peak memory usage is {} bytes ({:.1} MiB). Review allocation-heavy paths.",
            m.mem_bytes, m.mem_bytes as f64 / (1024.0 * 1024.0)
        ),
        before: format!("Current: {} bytes peak memory", m.mem_bytes),
        after: "Prefer stack allocation and reuse buffers where feasible.".to_string(),
        estimated_savings: "Potential 10–30% memory reduction.".to_string(),
    })
}

fn rule_many_write_entries(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.storage.read_write_keys < thresholds::WRITE_ENTRIES_BATCHING_HINT {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Medium,
        category: Category::StorageLayout,
        rule_id: "storage-many-writes".to_string(),
        title: "Multiple ledger write entries — consider layout consolidation".to_string(),
        rationale: format!(
            "This invocation wrote to {} ledger entries. Each write entry incurs a \
             separate flat fee. Packing related data into fewer, larger entries reduces \
             both the per-entry fee and the footprint size.",
            m.storage.read_write_keys
        ),
        before: format!(
            "Current: {} separate write entries ({} bytes total)",
            m.storage.read_write_keys, m.storage.total_write_bytes
        ),
        after: "Consolidate related fields into a single struct stored under one ledger key \
                (e.g. a `ContractState` map). Use `Map` or `Vec` types to bundle logically \
                related values."
            .to_string(),
        estimated_savings: format!(
            "Each entry removed saves ~5,000 stroops in write fees; bundling {} entries \
             could save ~{} stroops.",
            m.storage.read_write_keys.saturating_sub(1),
            m.storage.read_write_keys.saturating_sub(1) as u64 * 5_000
        ),
    })
}

fn rule_many_read_entries(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.storage.read_only_keys < thresholds::READ_ENTRIES_LAYOUT_HINT {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Low,
        category: Category::StorageLayout,
        rule_id: "storage-many-reads".to_string(),
        title: "Many read-only ledger accesses — storage layout review suggested".to_string(),
        rationale: format!(
            "{} read-only ledger keys accessed. Fetching many small entries has higher \
             overhead than fewer larger entries due to per-entry read fees.",
            m.storage.read_only_keys
        ),
        before: format!("Current: {} read-only ledger accesses", m.storage.read_only_keys),
        after: "Group frequently co-accessed data under a shared key to reduce read count \
                per invocation."
            .to_string(),
        estimated_savings: "Each read entry removed saves ~1,000 stroops in read fees."
            .to_string(),
    })
}

fn rule_oversized_events(m: &ProfileMetrics) -> Option<Recommendation> {
    if !m.events.has_oversized_events {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Medium,
        category: Category::EventUsage,
        rule_id: "event-oversized".to_string(),
        title: "Oversized contract events detected (> 512 bytes each)".to_string(),
        rationale: format!(
            "One or more events exceeded the recommended 512-byte threshold \
             (avg {:.0} bytes). Large events increase event fees and indexer \
             processing overhead.",
            m.events.avg_event_bytes
        ),
        before: format!(
            "Current: {} events, {:.0} bytes average, {} bytes total",
            m.events.event_count,
            m.events.avg_event_bytes,
            m.events.total_event_bytes
        ),
        after: "Emit only identifiers (contract IDs, amounts, addresses) in events, not full \
                data payloads. Consumers can fetch state separately via RPC."
            .to_string(),
        estimated_savings: "Potential 30–70% reduction in event fee costs.".to_string(),
    })
}

fn rule_many_events(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.events.event_count < thresholds::EVENT_HIGH_COUNT {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Low,
        category: Category::EventUsage,
        rule_id: "event-high-count".to_string(),
        title: "High number of events emitted per invocation".to_string(),
        rationale: format!(
            "{} events emitted in a single invocation. Consider whether all events are \
             necessary — event emission has both CPU and byte-rate costs.",
            m.events.event_count
        ),
        before: format!(
            "Current: {} events ({} bytes total)",
            m.events.event_count, m.events.total_event_bytes
        ),
        after: "Aggregate events where possible (e.g. emit one summary event instead of \
                one event per item in a batch operation)."
            .to_string(),
        estimated_savings: "Potential 20–50% event fee reduction for batch-like patterns."
            .to_string(),
    })
}

fn rule_complex_arguments(m: &ProfileMetrics) -> Option<Recommendation> {
    if m.args.total_arg_bytes < thresholds::ARG_COMPLEX_BYTES && !m.args.has_complex_args {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Low,
        category: Category::ArgumentEncoding,
        rule_id: "args-complex-encoding".to_string(),
        title: "Complex or large argument payload".to_string(),
        rationale: format!(
            "Argument payload is {} bytes (>= 2 KiB threshold). \
             Large arguments increase serialization cost and XDR encoding overhead.",
            m.args.total_arg_bytes
        ),
        before: format!(
            "Current: {} args, {} bytes total",
            m.args.arg_count, m.args.total_arg_bytes
        ),
        after: "Break large compound arguments into multiple smaller invocations, or store \
                shared state in the ledger and reference it by key rather than passing it \
                as argument data."
            .to_string(),
        estimated_savings: "Reduced argument serialization overhead; simpler XDR encoding."
            .to_string(),
    })
}

fn rule_archived_entries(m: &ProfileMetrics) -> Option<Recommendation> {
    if !m.storage.has_archived_entries {
        return None;
    }
    Some(Recommendation {
        severity: Severity::High,
        category: Category::ArchivalRisk,
        rule_id: "storage-archived-entries".to_string(),
        title: "Archived ledger entries detected — restore fee will be charged".to_string(),
        rationale:
            "One or more ledger entries referenced by this contract are already archived \
             (TTL expired). Restoring archived entries incurs a significant one-time \
             fee (≈50,000 stroops) and adds latency to the transaction."
            .to_string(),
        before: "Archived entries require a restore operation before the invocation can proceed."
            .to_string(),
        after: "Proactively extend TTL via `bump_contract_data` before entries approach \
                expiry. Use `starforge cost estimate --ledgers-until-expiry` to monitor \
                archival risk."
            .to_string(),
        estimated_savings: "Avoids ~50,000 stroops restore penalty per archived entry."
            .to_string(),
    })
}

fn rule_high_cpu_utilization(m: &ProfileMetrics) -> Option<Recommendation> {
    let util = m.cpu_utilization();
    if util < thresholds::CPU_UTIL_HIGH {
        return None;
    }
    let severity = if util >= thresholds::CPU_UTIL_CRITICAL {
        Severity::Critical
    } else {
        Severity::High
    };
    Some(Recommendation {
        severity,
        category: Category::AvoidableComputation,
        rule_id: "cpu-near-limit".to_string(),
        title: format!(
            "CPU utilization at {:.1}% of per-transaction limit",
            util * 100.0
        ),
        rationale: format!(
            "At {:.1}% CPU utilization ({} of ~100M instructions), this contract is \
             close to the Soroban per-transaction CPU budget. Complex inputs could push \
             it over the limit, causing transaction failure.",
            util * 100.0, m.cpu_insns
        ),
        before: format!("{} CPU instructions ({:.1}% of limit)", m.cpu_insns, util * 100.0),
        after: "Reduce algorithmic complexity, avoid O(n²) patterns, and move non-essential \
                computation off-chain or to a separate invocation."
            .to_string(),
        estimated_savings: "Required to avoid transaction failure under production load."
            .to_string(),
    })
}

fn rule_no_metrics(m: &ProfileMetrics) -> Option<Recommendation> {
    if !m.is_empty() {
        return None;
    }
    Some(Recommendation {
        severity: Severity::Info,
        category: Category::General,
        rule_id: "no-metrics".to_string(),
        title: "No resource usage data captured".to_string(),
        rationale: "All resource metrics are zero. This profile was likely created without a \
                    simulation file or live RPC call."
            .to_string(),
        before: "No simulation data available.".to_string(),
        after: "Run `starforge profile run --simulation-file <path>` or provide resource \
                parameters via `--cpu-insns`, `--mem-bytes`, etc."
            .to_string(),
        estimated_savings: "N/A".to_string(),
    })
}

// ── AI narrative (async, optional) ───────────────────────────────────────────
// NOTE: AI narrative generation lives in `commands::profile` (the command
// layer) rather than here, because `utils` cannot reference `commands`.
// `OptimizationReport.ai_narrative` is populated by the caller after `analyze()`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::performance::metrics::{EventProfile, ProfileMetrics, StorageProfile};

    fn profile(cpu: u64, mem: u64) -> ProfileMetrics {
        ProfileMetrics {
            cpu_insns: cpu,
            mem_bytes: mem,
            ..Default::default()
        }
    }

    #[test]
    fn empty_profile_produces_no_metrics_info() {
        let report = analyze(&profile(0, 0));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.rule_id == "no-metrics"));
    }

    #[test]
    fn high_cpu_triggers_high_severity() {
        let report = analyze(&profile(60_000_000, 1024));
        let cpu_recs: Vec<_> = report
            .recommendations
            .iter()
            .filter(|r| r.category == Category::AvoidableComputation)
            .collect();
        assert!(!cpu_recs.is_empty());
        assert!(cpu_recs
            .iter()
            .any(|r| r.severity == Severity::High || r.severity == Severity::Critical));
    }

    #[test]
    fn near_cpu_limit_triggers_critical() {
        // 85M instructions => 85% of limit => Critical
        let report = analyze(&profile(85_000_000, 1024));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.rule_id == "cpu-near-limit" && r.severity == Severity::Critical));
    }

    #[test]
    fn many_write_entries_triggers_medium_recommendation() {
        let mut m = profile(1_000, 1024);
        m.storage = StorageProfile {
            read_write_keys: 6,
            ..Default::default()
        };
        let report = analyze(&m);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.rule_id == "storage-many-writes"));
    }

    #[test]
    fn oversized_event_triggers_medium_recommendation() {
        let mut m = profile(1_000, 1024);
        m.events = EventProfile {
            event_count: 1,
            total_event_bytes: 600,
            has_oversized_events: true,
            avg_event_bytes: 600.0,
        };
        let report = analyze(&m);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.rule_id == "event-oversized"));
    }

    #[test]
    fn archived_entry_triggers_high_recommendation() {
        let mut m = profile(5_000, 512);
        m.storage.has_archived_entries = true;
        let report = analyze(&m);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.rule_id == "storage-archived-entries" && r.severity == Severity::High));
    }

    #[test]
    fn healthy_low_usage_produces_no_critical_recs() {
        let m = profile(100_000, 512);
        let report = analyze(&m);
        assert_eq!(report.severity_counts.critical, 0);
        assert_eq!(report.severity_counts.high, 0);
    }

    #[test]
    fn severity_counts_sum_to_total() {
        let report = analyze(&profile(60_000_000, 20 * 1024 * 1024 + 1));
        let manual_sum = report.severity_counts.critical
            + report.severity_counts.high
            + report.severity_counts.medium
            + report.severity_counts.low
            + report.severity_counts.info;
        assert_eq!(manual_sum, report.severity_counts.total());
        assert_eq!(manual_sum, report.recommendations.len() as u32);
    }

    #[test]
    fn deterministic_summary_is_present() {
        let report = analyze(&profile(60_000_000, 1024));
        assert!(!report.deterministic_summary.is_empty());
    }

    #[test]
    fn recommendations_are_deterministic_across_runs() {
        let m = profile(50_001_000, 1024);
        let r1 = analyze(&m);
        let r2 = analyze(&m);
        assert_eq!(r1.recommendations.len(), r2.recommendations.len());
        for (a, b) in r1.recommendations.iter().zip(r2.recommendations.iter()) {
            assert_eq!(a.rule_id, b.rule_id);
        }
    }
}
