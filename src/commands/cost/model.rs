//! Deterministic cost model for Soroban operations.
//!
//! Resource fee rates below are heuristic approximations of the Soroban fee
//! model (CPU instructions, memory, ledger read/write entries and bytes,
//! events, and archival/rent pressure), in the same spirit as the existing
//! `commands::gas` size-based heuristic. They are not a byte-for-byte replica
//! of validator fee computation, and are intended for relative comparison,
//! budgeting, and regression tracking rather than exact on-chain prediction.

use crate::utils::soroban::DEFAULT_ARCHIVAL_WARNING_LEDGERS;
use serde::{Deserialize, Serialize};

pub const COST_MODEL_SCHEMA_VERSION: u8 = 1;

/// Stroops per 10,000 CPU instructions.
const CPU_INSN_RATE_STROOPS_PER_10K: u64 = 25;
/// Stroops per KiB of high-water-mark memory used during simulation.
const MEM_BYTE_RATE_STROOPS_PER_KB: u64 = 4;
/// Flat per-entry fee for a ledger entry read.
const LEDGER_READ_ENTRY_FEE_STROOPS: u64 = 1_000;
/// Flat per-entry fee for a ledger entry write (writes are costlier than reads).
const LEDGER_WRITE_ENTRY_FEE_STROOPS: u64 = 5_000;
/// Stroops per byte written to the ledger (rent-bearing storage).
const LEDGER_WRITE_BYTE_RATE_STROOPS: u64 = 40;
/// Stroops per byte read from the ledger.
const LEDGER_READ_BYTE_RATE_STROOPS: u64 = 6;
/// Stroops per byte of emitted contract event data.
const EVENT_BYTE_RATE_STROOPS: u64 = 20;
/// Classic transaction base fee, in stroops.
const BASE_TRANSACTION_FEE_STROOPS: u64 = 100;
/// Flat penalty applied when an archived ledger entry must be restored before use.
const ARCHIVAL_RESTORE_PENALTY_STROOPS: u64 = 50_000;
/// One XLM in stroops.
const STROOPS_PER_XLM: f64 = 10_000_000.0;

/// Network congestion multiplier applied to the base fee component. This is a
/// coarse heuristic distinguishing quiet testnets from mainnet, not a live
/// surge-pricing feed.
fn network_base_fee_multiplier(network: &str) -> f64 {
    match network {
        "mainnet" => 1.5,
        "testnet" | "docker-testnet" => 1.0,
        _ => 1.0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    Deploy,
    Invoke,
    StorageWrite,
    StorageRead,
    Archival,
    Event,
    Batch,
}

impl OperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationKind::Deploy => "deploy",
            OperationKind::Invoke => "invoke",
            OperationKind::StorageWrite => "storage-write",
            OperationKind::StorageRead => "storage-read",
            OperationKind::Archival => "archival",
            OperationKind::Event => "event",
            OperationKind::Batch => "batch",
        }
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "deploy" => Ok(OperationKind::Deploy),
            "invoke" => Ok(OperationKind::Invoke),
            "storage-write" => Ok(OperationKind::StorageWrite),
            "storage-read" => Ok(OperationKind::StorageRead),
            "archival" => Ok(OperationKind::Archival),
            "event" => Ok(OperationKind::Event),
            "batch" => Ok(OperationKind::Batch),
            other => anyhow::bail!(
                "Unknown operation kind '{}'. Expected one of: deploy, invoke, storage-write, \
                 storage-read, archival, event, batch",
                other
            ),
        }
    }
}

/// Normalized resource usage for a single operation, independent of how it
/// was obtained (live RPC simulation, a fixture file, or manual parameters).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_insns: u64,
    pub mem_bytes: u64,
    pub read_entries: u32,
    pub write_entries: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub event_count: u32,
    pub event_bytes: u64,
}

impl ResourceUsage {
    pub fn is_empty(&self) -> bool {
        *self == ResourceUsage::default()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct CostBreakdown {
    pub cpu_fee_stroops: u64,
    pub mem_fee_stroops: u64,
    pub read_fee_stroops: u64,
    pub write_fee_stroops: u64,
    pub event_fee_stroops: u64,
    pub archival_fee_stroops: u64,
    pub base_fee_stroops: u64,
}

impl CostBreakdown {
    pub fn total_stroops(&self) -> u64 {
        self.cpu_fee_stroops
            + self.mem_fee_stroops
            + self.read_fee_stroops
            + self.write_fee_stroops
            + self.event_fee_stroops
            + self.archival_fee_stroops
            + self.base_fee_stroops
    }

    /// Returns each named component's share of the total, sorted descending,
    /// skipping zero-valued components. Used to identify the dominant cost driver.
    pub fn ranked_components(&self) -> Vec<(&'static str, u64)> {
        let mut parts = vec![
            ("cpu", self.cpu_fee_stroops),
            ("memory", self.mem_fee_stroops),
            ("ledger reads", self.read_fee_stroops),
            ("ledger writes", self.write_fee_stroops),
            ("events", self.event_fee_stroops),
            ("archival restore", self.archival_fee_stroops),
            ("base fee", self.base_fee_stroops),
        ];
        parts.retain(|(_, v)| *v > 0);
        parts.sort_by(|a, b| b.1.cmp(&a.1));
        parts
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostEstimate {
    pub schema_version: u8,
    pub operation: OperationKind,
    pub network: String,
    pub label: Option<String>,
    pub batch_size: u32,
    pub resource_usage: ResourceUsage,
    pub breakdown: CostBreakdown,
    pub total_fee_stroops: u64,
    pub total_fee_xlm: f64,
    pub per_item_fee_stroops: u64,
    pub archival_ledgers_until_expiry: Option<i64>,
    pub notes: Vec<String>,
}

impl CostEstimate {
    pub fn stroops_to_xlm(stroops: u64) -> f64 {
        stroops as f64 / STROOPS_PER_XLM
    }
}

/// Computes a full cost estimate from normalized resource usage.
///
/// `batch_size` scales per-item resource fees (cpu/mem/read/write/event) by
/// the item count while charging the base transaction fee only once, modeling
/// how batch operations amortize fixed overhead across many items.
/// `ledgers_until_expiry` (when known) drives archival-risk notes and, once
/// the entry is already archived (negative or zero), applies the restore
/// penalty to the breakdown.
pub fn estimate_cost(
    usage: &ResourceUsage,
    operation: OperationKind,
    network: &str,
    batch_size: u32,
    ledgers_until_expiry: Option<i64>,
) -> CostEstimate {
    let batch_size = batch_size.max(1);
    let multiplier = network_base_fee_multiplier(network);

    let cpu_fee = (usage.cpu_insns / 10_000) * CPU_INSN_RATE_STROOPS_PER_10K;
    let mem_fee = (usage.mem_bytes / 1024) * MEM_BYTE_RATE_STROOPS_PER_KB;
    let read_fee = (usage.read_entries as u64 * LEDGER_READ_ENTRY_FEE_STROOPS)
        + (usage.read_bytes * LEDGER_READ_BYTE_RATE_STROOPS);
    let write_fee = (usage.write_entries as u64 * LEDGER_WRITE_ENTRY_FEE_STROOPS)
        + (usage.write_bytes * LEDGER_WRITE_BYTE_RATE_STROOPS);
    let event_fee = usage.event_bytes * EVENT_BYTE_RATE_STROOPS;

    let is_archived = matches!(ledgers_until_expiry, Some(n) if n <= 0);
    let archival_fee = if is_archived {
        ARCHIVAL_RESTORE_PENALTY_STROOPS
    } else {
        0
    };

    let base_fee = (BASE_TRANSACTION_FEE_STROOPS as f64 * multiplier).round() as u64;

    let per_item = CostBreakdown {
        cpu_fee_stroops: cpu_fee,
        mem_fee_stroops: mem_fee,
        read_fee_stroops: read_fee,
        write_fee_stroops: write_fee,
        event_fee_stroops: event_fee,
        archival_fee_stroops: archival_fee,
        base_fee_stroops: 0,
    };

    let breakdown = CostBreakdown {
        cpu_fee_stroops: per_item.cpu_fee_stroops * batch_size as u64,
        mem_fee_stroops: per_item.mem_fee_stroops * batch_size as u64,
        read_fee_stroops: per_item.read_fee_stroops * batch_size as u64,
        write_fee_stroops: per_item.write_fee_stroops * batch_size as u64,
        event_fee_stroops: per_item.event_fee_stroops * batch_size as u64,
        archival_fee_stroops: per_item.archival_fee_stroops * batch_size as u64,
        base_fee_stroops: base_fee,
    };

    let total = breakdown.total_stroops();
    let per_item_fee = per_item.total_stroops() + (base_fee / batch_size as u64);

    let notes = build_notes(
        &breakdown,
        usage,
        operation,
        batch_size,
        ledgers_until_expiry,
    );

    CostEstimate {
        schema_version: COST_MODEL_SCHEMA_VERSION,
        operation,
        network: network.to_string(),
        label: None,
        batch_size,
        resource_usage: *usage,
        breakdown,
        total_fee_stroops: total,
        total_fee_xlm: CostEstimate::stroops_to_xlm(total),
        per_item_fee_stroops: per_item_fee,
        archival_ledgers_until_expiry: ledgers_until_expiry,
        notes,
    }
}

fn build_notes(
    breakdown: &CostBreakdown,
    usage: &ResourceUsage,
    operation: OperationKind,
    batch_size: u32,
    ledgers_until_expiry: Option<i64>,
) -> Vec<String> {
    let mut notes = Vec::new();

    if let Some((driver, amount)) = breakdown.ranked_components().first() {
        let total = breakdown.total_stroops().max(1);
        let pct = (*amount as f64 / total as f64) * 100.0;
        notes.push(format!(
            "Dominant cost driver: {} ({:.1}% of total fee)",
            driver, pct
        ));
    }

    if usage.write_entries > 0 || usage.write_bytes > 0 {
        notes.push(format!(
            "Storage growth: {} write entr{} ({} bytes) will occupy ledger space until archived or removed",
            usage.write_entries,
            if usage.write_entries == 1 { "y" } else { "ies" },
            usage.write_bytes
        ));
    }

    if let Some(remaining) = ledgers_until_expiry {
        if remaining <= 0 {
            notes.push(
                "Archival risk: target entry is already archived; a restore fee was applied"
                    .to_string(),
            );
        } else if remaining <= DEFAULT_ARCHIVAL_WARNING_LEDGERS as i64 {
            notes.push(format!(
                "Archival risk: entry expires in {} ledgers, within the {}-ledger warning window \
                 — consider a bump/extend before it lapses",
                remaining, DEFAULT_ARCHIVAL_WARNING_LEDGERS
            ));
        }
    }

    if operation == OperationKind::Batch && batch_size > 1 {
        notes.push(format!(
            "Batch of {} items amortizes the base transaction fee across all items \
             ({} stroops/item vs {} stroops standalone)",
            batch_size,
            breakdown
                .base_fee_stroops
                .checked_div(batch_size as u64)
                .unwrap_or(0),
            breakdown.base_fee_stroops
        ));
    }

    if usage.is_empty() {
        notes.push(
            "No resource usage was supplied or detected; this estimate reflects only the base \
             transaction fee"
                .to_string(),
        );
    }

    notes
}

/// Projects storage rent/archival pressure across a set of future checkpoints
/// (in ledger-count offsets from now), given a fixed decay rate expressed as
/// ledgers-until-expiry shrinking linearly with each checkpoint. Used by the
/// `budget` command to warn about entries that will cross the archival
/// threshold before the next expected estimate run.
pub fn project_archival_horizon(
    current_ledgers_until_expiry: i64,
    checkpoints: &[u32],
) -> Vec<(u32, i64, bool)> {
    checkpoints
        .iter()
        .map(|&offset| {
            let remaining = current_ledgers_until_expiry - offset as i64;
            let at_risk = remaining <= DEFAULT_ARCHIVAL_WARNING_LEDGERS as i64;
            (offset, remaining, at_risk)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(
        cpu: u64,
        mem: u64,
        reads: u32,
        writes: u32,
        rb: u64,
        wb: u64,
        ev: u32,
        evb: u64,
    ) -> ResourceUsage {
        ResourceUsage {
            cpu_insns: cpu,
            mem_bytes: mem,
            read_entries: reads,
            write_entries: writes,
            read_bytes: rb,
            write_bytes: wb,
            event_count: ev,
            event_bytes: evb,
        }
    }

    #[test]
    fn operation_kind_round_trips_through_str() {
        for op in [
            OperationKind::Deploy,
            OperationKind::Invoke,
            OperationKind::StorageWrite,
            OperationKind::StorageRead,
            OperationKind::Archival,
            OperationKind::Event,
            OperationKind::Batch,
        ] {
            assert_eq!(OperationKind::parse(op.as_str()).unwrap(), op);
        }
    }

    #[test]
    fn unknown_operation_kind_is_rejected() {
        assert!(OperationKind::parse("teleport").is_err());
    }

    #[test]
    fn empty_usage_yields_only_base_fee() {
        let est = estimate_cost(
            &ResourceUsage::default(),
            OperationKind::Invoke,
            "testnet",
            1,
            None,
        );
        assert_eq!(est.breakdown.cpu_fee_stroops, 0);
        assert!(est.breakdown.base_fee_stroops > 0);
        assert_eq!(est.total_fee_stroops, est.breakdown.base_fee_stroops);
        assert!(est.notes.iter().any(|n| n.contains("No resource usage")));
    }

    #[test]
    fn heavier_usage_costs_more() {
        let light = usage(10_000, 1024, 1, 1, 100, 100, 1, 50);
        let heavy = usage(100_000, 10_240, 5, 5, 1_000, 1_000, 5, 500);
        let light_est = estimate_cost(&light, OperationKind::Invoke, "testnet", 1, None);
        let heavy_est = estimate_cost(&heavy, OperationKind::Invoke, "testnet", 1, None);
        assert!(heavy_est.total_fee_stroops > light_est.total_fee_stroops);
    }

    #[test]
    fn mainnet_base_fee_exceeds_testnet() {
        let u = usage(1_000, 100, 0, 0, 0, 0, 0, 0);
        let testnet = estimate_cost(&u, OperationKind::Invoke, "testnet", 1, None);
        let mainnet = estimate_cost(&u, OperationKind::Invoke, "mainnet", 1, None);
        assert!(mainnet.breakdown.base_fee_stroops > testnet.breakdown.base_fee_stroops);
    }

    #[test]
    fn batch_amortizes_base_fee_but_scales_resource_fees() {
        let u = usage(50_000, 2048, 2, 2, 200, 200, 2, 100);
        let single = estimate_cost(&u, OperationKind::Batch, "testnet", 1, None);
        let batched = estimate_cost(&u, OperationKind::Batch, "testnet", 10, None);

        assert_eq!(
            batched.breakdown.base_fee_stroops,
            single.breakdown.base_fee_stroops
        );
        assert_eq!(
            batched.breakdown.cpu_fee_stroops,
            single.breakdown.cpu_fee_stroops * 10
        );
        assert!(batched
            .notes
            .iter()
            .any(|n| n.contains("amortizes the base transaction fee")));
    }

    #[test]
    fn archived_entry_applies_restore_penalty_and_note() {
        let u = usage(1_000, 100, 1, 0, 50, 0, 0, 0);
        let est = estimate_cost(&u, OperationKind::Archival, "testnet", 1, Some(-5));
        assert_eq!(
            est.breakdown.archival_fee_stroops,
            ARCHIVAL_RESTORE_PENALTY_STROOPS
        );
        assert!(est.notes.iter().any(|n| n.contains("already archived")));
    }

    #[test]
    fn expiring_soon_entry_warns_without_penalty() {
        let u = usage(1_000, 100, 1, 0, 50, 0, 0, 0);
        let est = estimate_cost(&u, OperationKind::Invoke, "testnet", 1, Some(500));
        assert_eq!(est.breakdown.archival_fee_stroops, 0);
        assert!(est.notes.iter().any(|n| n.contains("warning window")));
    }

    #[test]
    fn stroops_to_xlm_conversion_is_correct() {
        assert!((CostEstimate::stroops_to_xlm(10_000_000) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn project_archival_horizon_flags_future_risk() {
        let checkpoints = [0, 500, 1_500];
        let projection = project_archival_horizon(1_200, &checkpoints);
        assert_eq!(projection.len(), 3);
        assert!(!projection[0].2); // 1200 remaining, not at risk
        assert!(projection[1].2); // 700 remaining, at risk
        assert!(projection[2].2); // negative, at risk
    }

    #[test]
    fn ranked_components_sorted_descending_and_skip_zero() {
        let breakdown = CostBreakdown {
            cpu_fee_stroops: 10,
            mem_fee_stroops: 0,
            read_fee_stroops: 50,
            write_fee_stroops: 5,
            event_fee_stroops: 0,
            archival_fee_stroops: 0,
            base_fee_stroops: 100,
        };
        let ranked = breakdown.ranked_components();
        assert_eq!(ranked.first().unwrap().0, "base fee");
        assert!(ranked.iter().all(|(_, v)| *v > 0));
    }
}
