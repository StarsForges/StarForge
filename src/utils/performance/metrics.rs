//! Core profiling metrics collected from Soroban simulation responses.
//!
//! [`ProfileMetrics`] is the canonical data structure that flows through the
//! entire profiling pipeline — from simulation parsing through baseline
//! comparison, optimizer analysis, and report rendering. It is intentionally
//! a superset of [`crate::commands::cost::model::ResourceUsage`] so that the
//! two subsystems can interoperate without coupling their internal types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PROFILE_SCHEMA_VERSION: u8 = 1;

/// Per-function or per-invocation execution hot spot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HotSpot {
    /// Human-readable label for this segment (e.g. `"init"`, `"transfer"`, `"__compute"`).
    pub label: String,
    /// Share of the total CPU budget consumed by this segment (0.0–1.0).
    pub cpu_fraction: f64,
    /// Absolute instruction count attributed to this segment.
    pub cpu_insns: u64,
    /// Bytes of peak memory attributed to this segment.
    pub mem_bytes: u64,
}

/// Storage access patterns observed during simulation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StorageProfile {
    /// Number of distinct storage keys accessed in read-only mode.
    pub read_only_keys: u32,
    /// Number of distinct storage keys accessed in read-write mode.
    pub read_write_keys: u32,
    /// Total bytes read from the ledger.
    pub total_read_bytes: u64,
    /// Total bytes written to the ledger.
    pub total_write_bytes: u64,
    /// Estimated ledger entries that will grow over time (rent-bearing keys).
    pub persistent_entry_count: u32,
    /// Estimated ledger entries that are temporary (TTL-bounded).
    pub temporary_entry_count: u32,
    /// True when any ledger entry is already archived (TTL expired).
    pub has_archived_entries: bool,
}

/// Contract event emission profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EventProfile {
    /// Number of events emitted during this invocation.
    pub event_count: u32,
    /// Total bytes of all emitted events.
    pub total_event_bytes: u64,
    /// True when any event payload exceeds the recommended 512-byte size limit.
    pub has_oversized_events: bool,
    /// Estimated per-event average size in bytes.
    pub avg_event_bytes: f64,
}

/// Argument encoding metrics for an invocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ArgumentProfile {
    /// Number of top-level arguments supplied to the contract function.
    pub arg_count: u32,
    /// Estimated total bytes of serialized argument data.
    pub total_arg_bytes: u64,
    /// True when any argument appears to be a large nested structure.
    pub has_complex_args: bool,
}

/// Full performance profile for a single contract invocation or simulation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileMetrics {
    pub schema_version: u8,
    /// Wall-clock timestamp of when this profile was captured.
    pub timestamp: DateTime<Utc>,
    /// Logical label identifying the contract or operation being profiled.
    pub contract_label: String,
    /// Network context (testnet, mainnet, docker-testnet, …).
    pub network: String,
    /// Total CPU instructions consumed.
    pub cpu_insns: u64,
    /// Peak memory usage in bytes.
    pub mem_bytes: u64,
    /// Ledger fee in stroops returned by the simulation.
    pub sim_fee_stroops: u64,
    /// Execution hot spots parsed from the simulation or derived heuristically.
    pub hot_spots: Vec<HotSpot>,
    /// Storage access patterns.
    pub storage: StorageProfile,
    /// Event emission profile.
    pub events: EventProfile,
    /// Argument encoding metrics.
    pub args: ArgumentProfile,
    /// Simulation errors (if any). A non-empty list indicates a failed run.
    pub simulation_errors: Vec<String>,
    /// True when the simulation completed without errors.
    pub success: bool,
    /// Optional host function call counts, keyed by host-fn name.
    pub host_fn_counts: std::collections::BTreeMap<String, u32>,
    /// Arbitrary notes attached by the profiling pipeline.
    pub notes: Vec<String>,
}

impl Default for ProfileMetrics {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            timestamp: Utc::now(),
            contract_label: String::new(),
            network: "testnet".to_string(),
            cpu_insns: 0,
            mem_bytes: 0,
            sim_fee_stroops: 0,
            hot_spots: Vec::new(),
            storage: StorageProfile::default(),
            events: EventProfile::default(),
            args: ArgumentProfile::default(),
            simulation_errors: Vec::new(),
            success: true,
            host_fn_counts: std::collections::BTreeMap::new(),
            notes: Vec::new(),
        }
    }
}

impl ProfileMetrics {
    /// Builds a [`ProfileMetrics`] from a raw Soroban RPC simulation JSON envelope.
    pub fn from_rpc_envelope(
        envelope: &serde_json::Value,
        label: &str,
        network: &str,
    ) -> anyhow::Result<Self> {
        if let Some(error) = envelope.get("error") {
            anyhow::bail!("Soroban RPC response contains an error: {}", error);
        }
        let result = envelope
            .get("result")
            .ok_or_else(|| anyhow::anyhow!("Soroban RPC envelope missing 'result' field"))?;
        Ok(Self::from_result_value(result, label, network))
    }

    /// Parses the unwrapped `result` portion of a Soroban RPC simulation response.
    pub fn from_result_value(
        result: &serde_json::Value,
        label: &str,
        network: &str,
    ) -> Self {
        let cpu_insns = result
            .pointer("/cost/cpuInsns")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mem_bytes = result
            .pointer("/cost/memBytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let sim_fee = result
            .get("minResourceFee")
            .and_then(|v| v.as_u64())
            .or_else(|| result.get("fee").and_then(|v| v.as_u64()))
            .unwrap_or(0);

        // Parse footprint for storage profile
        let footprint = result
            .pointer("/transactionData/resources/footprint")
            .or_else(|| result.pointer("/transactionData/footprint"))
            .or_else(|| result.pointer("/footprint"));

        let (ro_keys, ro_bytes) = footprint
            .and_then(|f| f.get("readOnly").or_else(|| f.get("readOnlyKeys")))
            .map(count_and_bytes)
            .unwrap_or((0, 0));

        let (rw_keys, rw_bytes) = footprint
            .and_then(|f| f.get("readWrite").or_else(|| f.get("readWriteKeys")))
            .map(count_and_bytes)
            .unwrap_or((0, 0));

        let storage = StorageProfile {
            read_only_keys: ro_keys,
            read_write_keys: rw_keys,
            total_read_bytes: ro_bytes,
            total_write_bytes: rw_bytes,
            persistent_entry_count: rw_keys,
            temporary_entry_count: 0,
            has_archived_entries: false,
        };

        // Parse events
        let events_arr = result.get("events").and_then(|v| v.as_array());
        let event_count = events_arr.map(|e| e.len() as u32).unwrap_or(0);
        let total_event_bytes: u64 = events_arr
            .map(|e| {
                e.iter()
                    .map(|ev| ev.as_str().map(|s| s.len()).unwrap_or(0) as u64)
                    .sum()
            })
            .unwrap_or(0);
        let avg_event_bytes = if event_count > 0 {
            total_event_bytes as f64 / event_count as f64
        } else {
            0.0
        };
        let has_oversized_events = events_arr
            .map(|e| {
                e.iter()
                    .any(|ev| ev.as_str().map(|s| s.len()).unwrap_or(0) > 512)
            })
            .unwrap_or(false);

        let events = EventProfile {
            event_count,
            total_event_bytes,
            has_oversized_events,
            avg_event_bytes,
        };

        // Derive hot spots heuristically from cost breakdown
        let hot_spots = derive_hot_spots(cpu_insns, mem_bytes, &storage, &events);

        // Parse simulation errors
        let simulation_errors: Vec<String> = result
            .get("error")
            .and_then(|e| e.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();
        let success = simulation_errors.is_empty()
            && result
                .get("results")
                .and_then(|r| r.as_array())
                .map(|arr| !arr.is_empty())
                .unwrap_or(true);

        ProfileMetrics {
            schema_version: PROFILE_SCHEMA_VERSION,
            timestamp: Utc::now(),
            contract_label: label.to_string(),
            network: network.to_string(),
            cpu_insns,
            mem_bytes,
            sim_fee_stroops: sim_fee,
            hot_spots,
            storage,
            events,
            args: ArgumentProfile::default(),
            simulation_errors,
            success,
            host_fn_counts: std::collections::BTreeMap::new(),
            notes: Vec::new(),
        }
    }

    /// Returns true when no resource usage was captured (all-zero metrics).
    pub fn is_empty(&self) -> bool {
        self.cpu_insns == 0
            && self.mem_bytes == 0
            && self.storage.read_only_keys == 0
            && self.storage.read_write_keys == 0
            && self.events.event_count == 0
    }

    /// CPU utilization ratio relative to the Soroban per-transaction CPU limit.
    /// Returns a value in [0.0, 1.0+] where > 1.0 indicates over-budget.
    pub fn cpu_utilization(&self) -> f64 {
        // Soroban per-transaction CPU limit (approximation based on protocol docs)
        const MAX_CPU_INSNS: u64 = 100_000_000;
        self.cpu_insns as f64 / MAX_CPU_INSNS as f64
    }

    /// Memory utilization ratio relative to the Soroban per-transaction memory limit.
    pub fn mem_utilization(&self) -> f64 {
        // Soroban per-transaction memory limit (~40 MiB)
        const MAX_MEM_BYTES: u64 = 41_943_040;
        self.mem_bytes as f64 / MAX_MEM_BYTES as f64
    }
}

/// Derives heuristic hot spots from aggregate resource metrics.
pub(crate) fn derive_hot_spots_pub(
    cpu_insns: u64,
    mem_bytes: u64,
    storage: &StorageProfile,
    events: &EventProfile,
) -> Vec<HotSpot> {
    derive_hot_spots(cpu_insns, mem_bytes, storage, events)
}

/// Derives heuristic hot spots from aggregate resource metrics (private core).
fn derive_hot_spots(
    cpu_insns: u64,
    mem_bytes: u64,
    storage: &StorageProfile,
    events: &EventProfile,
) -> Vec<HotSpot> {
    if cpu_insns == 0 {
        return Vec::new();
    }

    // Attribute compute cost fractions based on rough Soroban rate ratios
    let cpu_base_fraction = 0.60_f64;
    let storage_cpu_fraction = if storage.read_write_keys > 0 {
        0.25_f64
    } else if storage.read_only_keys > 0 {
        0.10_f64
    } else {
        0.0
    };
    let event_cpu_fraction = if events.event_count > 0 { 0.05 } else { 0.0 };
    let remaining = (1.0
        - cpu_base_fraction
        - storage_cpu_fraction
        - event_cpu_fraction)
        .max(0.0);

    let mut spots = Vec::new();

    if cpu_base_fraction > 0.0 {
        spots.push(HotSpot {
            label: "computation".to_string(),
            cpu_fraction: cpu_base_fraction,
            cpu_insns: (cpu_insns as f64 * cpu_base_fraction) as u64,
            mem_bytes: (mem_bytes as f64 * 0.80) as u64,
        });
    }
    if storage_cpu_fraction > 0.0 {
        spots.push(HotSpot {
            label: "storage_io".to_string(),
            cpu_fraction: storage_cpu_fraction,
            cpu_insns: (cpu_insns as f64 * storage_cpu_fraction) as u64,
            mem_bytes: (mem_bytes as f64 * 0.15) as u64,
        });
    }
    if event_cpu_fraction > 0.0 {
        spots.push(HotSpot {
            label: "event_emission".to_string(),
            cpu_fraction: event_cpu_fraction,
            cpu_insns: (cpu_insns as f64 * event_cpu_fraction) as u64,
            mem_bytes: (mem_bytes as f64 * 0.03) as u64,
        });
    }
    if remaining > 0.0 {
        spots.push(HotSpot {
            label: "host_fns_and_encoding".to_string(),
            cpu_fraction: remaining,
            cpu_insns: (cpu_insns as f64 * remaining) as u64,
            mem_bytes: (mem_bytes as f64 * 0.02) as u64,
        });
    }

    // Sort descending by cpu_fraction so the hottest segment is first
    spots.sort_by(|a, b| b.cpu_fraction.partial_cmp(&a.cpu_fraction).unwrap());
    spots
}

fn count_and_bytes(keys: &serde_json::Value) -> (u32, u64) {
    let arr = match keys.as_array() {
        Some(a) => a,
        None => return (0, 0),
    };
    let count = arr.len() as u32;
    let bytes: u64 = arr
        .iter()
        .map(|k| {
            k.get("sizeHintBytes")
                .or_else(|| k.get("size_hint_bytes"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        })
        .sum();
    (count, bytes)
}

// ── Delta computations ────────────────────────────────────────────────────────

/// Summary of changes between a baseline and a candidate profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileDelta {
    pub cpu_insns_delta: i64,
    pub cpu_insns_pct: f64,
    pub mem_bytes_delta: i64,
    pub mem_bytes_pct: f64,
    pub fee_stroops_delta: i64,
    pub fee_stroops_pct: f64,
    pub read_keys_delta: i32,
    pub write_keys_delta: i32,
    pub event_count_delta: i32,
    pub event_bytes_delta: i64,
    /// True when any metric regressed beyond a threshold.
    pub regressed: bool,
    /// Which metrics regressed and by how much.
    pub regression_details: Vec<String>,
}

impl ProfileDelta {
    /// Compute the delta between `baseline` and `candidate`.
    /// `threshold_pct` is the maximum allowed regression before flagging.
    pub fn compute(
        baseline: &ProfileMetrics,
        candidate: &ProfileMetrics,
        threshold_pct: f64,
    ) -> Self {
        let cpu_delta = candidate.cpu_insns as i64 - baseline.cpu_insns as i64;
        let cpu_pct = pct_change(baseline.cpu_insns, candidate.cpu_insns);
        let mem_delta = candidate.mem_bytes as i64 - baseline.mem_bytes as i64;
        let mem_pct = pct_change(baseline.mem_bytes, candidate.mem_bytes);
        let fee_delta = candidate.sim_fee_stroops as i64 - baseline.sim_fee_stroops as i64;
        let fee_pct = pct_change(baseline.sim_fee_stroops, candidate.sim_fee_stroops);
        let read_delta = candidate.storage.read_only_keys as i32
            - baseline.storage.read_only_keys as i32;
        let write_delta = candidate.storage.read_write_keys as i32
            - baseline.storage.read_write_keys as i32;
        let ev_count_delta =
            candidate.events.event_count as i32 - baseline.events.event_count as i32;
        let ev_bytes_delta =
            candidate.events.total_event_bytes as i64 - baseline.events.total_event_bytes as i64;

        let mut regressions = Vec::new();
        if cpu_pct > threshold_pct {
            regressions.push(format!(
                "CPU instructions increased by {:.1}% ({} → {} insns)",
                cpu_pct, baseline.cpu_insns, candidate.cpu_insns
            ));
        }
        if mem_pct > threshold_pct {
            regressions.push(format!(
                "Memory increased by {:.1}% ({} → {} bytes)",
                mem_pct, baseline.mem_bytes, candidate.mem_bytes
            ));
        }
        if fee_pct > threshold_pct {
            regressions.push(format!(
                "Fee increased by {:.1}% ({} → {} stroops)",
                fee_pct, baseline.sim_fee_stroops, candidate.sim_fee_stroops
            ));
        }

        let regressed = !regressions.is_empty();

        ProfileDelta {
            cpu_insns_delta: cpu_delta,
            cpu_insns_pct: cpu_pct,
            mem_bytes_delta: mem_delta,
            mem_bytes_pct: mem_pct,
            fee_stroops_delta: fee_delta,
            fee_stroops_pct: fee_pct,
            read_keys_delta: read_delta,
            write_keys_delta: write_delta,
            event_count_delta: ev_count_delta,
            event_bytes_delta: ev_bytes_delta,
            regressed,
            regression_details: regressions,
        }
    }
}

fn pct_change(baseline: u64, candidate: u64) -> f64 {
    if baseline == 0 {
        return 0.0;
    }
    ((candidate as f64 - baseline as f64) / baseline as f64) * 100.0
}

// ── Budget thresholds ─────────────────────────────────────────────────────────

/// Named budget thresholds for CI gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileBudget {
    /// Max CPU instructions before failing the budget check.
    pub max_cpu_insns: Option<u64>,
    /// Max peak memory bytes before failing the budget check.
    pub max_mem_bytes: Option<u64>,
    /// Max simulation fee in stroops before failing the budget check.
    pub max_fee_stroops: Option<u64>,
    /// Max number of ledger write entries.
    pub max_write_entries: Option<u32>,
    /// Max number of events per invocation.
    pub max_events: Option<u32>,
    /// Max regression threshold (percent) vs stored baseline.
    pub regression_threshold_pct: f64,
}

impl Default for ProfileBudget {
    fn default() -> Self {
        Self {
            max_cpu_insns: None,
            max_mem_bytes: None,
            max_fee_stroops: None,
            max_write_entries: None,
            max_events: None,
            regression_threshold_pct: 10.0,
        }
    }
}

/// Result of checking a profile against a budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCheckResult {
    pub passed: bool,
    pub violations: Vec<String>,
}

impl BudgetCheckResult {
    pub fn check(metrics: &ProfileMetrics, budget: &ProfileBudget) -> Self {
        let mut violations = Vec::new();

        if let Some(max) = budget.max_cpu_insns {
            if metrics.cpu_insns > max {
                violations.push(format!(
                    "CPU instructions {} exceeds budget of {}",
                    metrics.cpu_insns, max
                ));
            }
        }
        if let Some(max) = budget.max_mem_bytes {
            if metrics.mem_bytes > max {
                violations.push(format!(
                    "Memory {} bytes exceeds budget of {} bytes",
                    metrics.mem_bytes, max
                ));
            }
        }
        if let Some(max) = budget.max_fee_stroops {
            if metrics.sim_fee_stroops > max {
                violations.push(format!(
                    "Fee {} stroops exceeds budget of {} stroops",
                    metrics.sim_fee_stroops, max
                ));
            }
        }
        if let Some(max) = budget.max_write_entries {
            if metrics.storage.read_write_keys > max {
                violations.push(format!(
                    "Write entries {} exceeds budget of {}",
                    metrics.storage.read_write_keys, max
                ));
            }
        }
        if let Some(max) = budget.max_events {
            if metrics.events.event_count > max {
                violations.push(format!(
                    "Event count {} exceeds budget of {}",
                    metrics.events.event_count, max
                ));
            }
        }

        BudgetCheckResult {
            passed: violations.is_empty(),
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_metrics(cpu: u64, mem: u64, fee: u64) -> ProfileMetrics {
        ProfileMetrics {
            cpu_insns: cpu,
            mem_bytes: mem,
            sim_fee_stroops: fee,
            ..Default::default()
        }
    }

    #[test]
    fn parses_rpc_envelope_into_metrics() {
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "cost": { "cpuInsns": 200000, "memBytes": 4096 },
                "minResourceFee": 500,
                "transactionData": {
                    "resources": {
                        "footprint": {
                            "readOnly": [{ "sizeHintBytes": 64 }],
                            "readWrite": [{ "sizeHintBytes": 128 }]
                        }
                    }
                },
                "events": ["AAAA", "BBBBBB"],
                "results": [{ "xdr": "AAAA", "auth": [] }]
            }
        });
        let m = ProfileMetrics::from_rpc_envelope(&envelope, "test-contract", "testnet").unwrap();
        assert_eq!(m.cpu_insns, 200_000);
        assert_eq!(m.mem_bytes, 4096);
        assert_eq!(m.sim_fee_stroops, 500);
        assert_eq!(m.storage.read_only_keys, 1);
        assert_eq!(m.storage.read_write_keys, 1);
        assert_eq!(m.events.event_count, 2);
        assert!(m.success);
        assert_eq!(m.contract_label, "test-contract");
    }

    #[test]
    fn rpc_error_envelope_returns_error() {
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32600, "message": "boom" }
        });
        assert!(
            ProfileMetrics::from_rpc_envelope(&envelope, "x", "testnet").is_err()
        );
    }

    #[test]
    fn empty_result_produces_default_metrics() {
        let result = json!({});
        let m = ProfileMetrics::from_result_value(&result, "empty", "testnet");
        assert!(m.is_empty());
        assert!(m.success);
    }

    #[test]
    fn hot_spots_derived_from_cpu_storage_events() {
        let spots = derive_hot_spots(
            1_000_000,
            8192,
            &StorageProfile {
                read_write_keys: 2,
                ..Default::default()
            },
            &EventProfile {
                event_count: 3,
                ..Default::default()
            },
        );
        assert!(!spots.is_empty());
        // Hottest spot should be computation
        assert_eq!(spots[0].label, "computation");
        // All fractions should sum to ≤ 1.0
        let total: f64 = spots.iter().map(|s| s.cpu_fraction).sum();
        assert!(total <= 1.01);
    }

    #[test]
    fn profile_delta_detects_regression() {
        let baseline = make_metrics(100_000, 1024, 500);
        let candidate = make_metrics(200_000, 1024, 500);
        let delta = ProfileDelta::compute(&baseline, &candidate, 5.0);
        assert!(delta.regressed);
        assert_eq!(delta.cpu_insns_pct, 100.0);
        assert!(!delta.regression_details.is_empty());
    }

    #[test]
    fn profile_delta_no_regression_within_threshold() {
        let baseline = make_metrics(100_000, 1024, 500);
        let candidate = make_metrics(104_000, 1024, 500);
        let delta = ProfileDelta::compute(&baseline, &candidate, 10.0);
        assert!(!delta.regressed);
    }

    #[test]
    fn budget_check_flags_violations() {
        let m = make_metrics(500_000, 2048, 1000);
        let budget = ProfileBudget {
            max_cpu_insns: Some(400_000),
            ..Default::default()
        };
        let result = BudgetCheckResult::check(&m, &budget);
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].contains("CPU"));
    }

    #[test]
    fn budget_check_passes_when_within_limits() {
        let m = make_metrics(100_000, 1024, 200);
        let budget = ProfileBudget {
            max_cpu_insns: Some(200_000),
            max_mem_bytes: Some(4096),
            ..Default::default()
        };
        let result = BudgetCheckResult::check(&m, &budget);
        assert!(result.passed);
    }

    #[test]
    fn cpu_utilization_ratio_is_reasonable() {
        let m = make_metrics(50_000_000, 0, 0);
        let util = m.cpu_utilization();
        assert!(util > 0.0 && util < 1.0);
    }
}
