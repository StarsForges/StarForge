//! Normalized, transport-agnostic resource/fee metrics for budget enforcement.
//!
//! [`BudgetMetrics`] is the single shape every enforcement path (deploy,
//! invoke, batch payouts, classic payments) reduces its numbers into before
//! they reach [`crate::utils::budget::enforce`]. Callers in `src/commands/*`
//! are responsible for extracting these primitive values out of whatever
//! network/simulation type they already hold (Soroban RPC simulation,
//! Horizon fee stats, a CSV batch estimate, ...) — this module intentionally
//! has no knowledge of those richer types so the domain logic stays testable
//! without a live network or RPC fixtures.

use serde::{Deserialize, Serialize};

/// A single named metric a [`crate::utils::budget::policy::LimitSet`] can cap.
///
/// The order here is also the display/report order used throughout the
/// `budget` command family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetricKind {
    ClassicFeeStroops,
    ResourceFeeStroops,
    CpuInsns,
    MemBytes,
    ReadEntries,
    WriteEntries,
    ReadBytes,
    WriteBytes,
    EventBytes,
    TxSizeBytes,
}

impl MetricKind {
    pub const ALL: [MetricKind; 10] = [
        MetricKind::ClassicFeeStroops,
        MetricKind::ResourceFeeStroops,
        MetricKind::CpuInsns,
        MetricKind::MemBytes,
        MetricKind::ReadEntries,
        MetricKind::WriteEntries,
        MetricKind::ReadBytes,
        MetricKind::WriteBytes,
        MetricKind::EventBytes,
        MetricKind::TxSizeBytes,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            MetricKind::ClassicFeeStroops => "classic-fee-stroops",
            MetricKind::ResourceFeeStroops => "resource-fee-stroops",
            MetricKind::CpuInsns => "cpu-insns",
            MetricKind::MemBytes => "mem-bytes",
            MetricKind::ReadEntries => "read-entries",
            MetricKind::WriteEntries => "write-entries",
            MetricKind::ReadBytes => "read-bytes",
            MetricKind::WriteBytes => "write-bytes",
            MetricKind::EventBytes => "event-bytes",
            MetricKind::TxSizeBytes => "tx-size-bytes",
        }
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        Self::ALL
            .iter()
            .find(|m| m.as_str() == value)
            .copied()
            .ok_or_else(|| {
                let known: Vec<&str> = Self::ALL.iter().map(|m| m.as_str()).collect();
                anyhow::anyhow!(
                    "Unknown budget metric '{}'. Expected one of: {}",
                    value,
                    known.join(", ")
                )
            })
    }

    /// A short human label used in report rendering.
    pub fn label(&self) -> &'static str {
        match self {
            MetricKind::ClassicFeeStroops => "Classic fee (stroops)",
            MetricKind::ResourceFeeStroops => "Soroban resource fee (stroops)",
            MetricKind::CpuInsns => "CPU instructions",
            MetricKind::MemBytes => "Memory (bytes)",
            MetricKind::ReadEntries => "Ledger read entries",
            MetricKind::WriteEntries => "Ledger write entries",
            MetricKind::ReadBytes => "Ledger read bytes",
            MetricKind::WriteBytes => "Ledger write bytes",
            MetricKind::EventBytes => "Event payload bytes",
            MetricKind::TxSizeBytes => "Transaction envelope size (bytes)",
        }
    }
}

/// Normalized measurements for a single operation about to be signed (or
/// already captured as a baseline/history point). Every field is a plain
/// counter — `0` means "not applicable / not measured", which is why
/// classic-fee-only paths (a plain payment) can share this type with
/// Soroban invocations without special-casing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct BudgetMetrics {
    pub classic_fee_stroops: u64,
    pub resource_fee_stroops: u64,
    pub cpu_insns: u64,
    pub mem_bytes: u64,
    pub read_entries: u32,
    pub write_entries: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub event_bytes: u64,
    pub tx_size_bytes: u64,
}

impl BudgetMetrics {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        classic_fee_stroops: u64,
        resource_fee_stroops: u64,
        cpu_insns: u64,
        mem_bytes: u64,
        read_entries: u32,
        write_entries: u32,
        read_bytes: u64,
        write_bytes: u64,
        event_bytes: u64,
        tx_size_bytes: u64,
    ) -> Self {
        Self {
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
        }
    }

    /// A classic-only metric set (plain XLM/token payments, batch payouts)
    /// with every Soroban-specific counter left at zero.
    pub fn classic_only(classic_fee_stroops: u64) -> Self {
        Self {
            classic_fee_stroops,
            ..Self::default()
        }
    }

    /// Reads back the raw counter for a given metric kind, widened to `u64`
    /// so callers can compare heterogeneous fields (`u32` entry counts vs
    /// `u64` byte counts) uniformly.
    pub fn value_of(&self, kind: MetricKind) -> u64 {
        match kind {
            MetricKind::ClassicFeeStroops => self.classic_fee_stroops,
            MetricKind::ResourceFeeStroops => self.resource_fee_stroops,
            MetricKind::CpuInsns => self.cpu_insns,
            MetricKind::MemBytes => self.mem_bytes,
            MetricKind::ReadEntries => self.read_entries as u64,
            MetricKind::WriteEntries => self.write_entries as u64,
            MetricKind::ReadBytes => self.read_bytes,
            MetricKind::WriteBytes => self.write_bytes,
            MetricKind::EventBytes => self.event_bytes,
            MetricKind::TxSizeBytes => self.tx_size_bytes,
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == BudgetMetrics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_kind_round_trips_through_str() {
        for kind in MetricKind::ALL {
            assert_eq!(MetricKind::parse(kind.as_str()).unwrap(), kind);
        }
    }

    #[test]
    fn unknown_metric_kind_is_rejected() {
        let err = MetricKind::parse("teleport-distance").unwrap_err();
        assert!(err.to_string().contains("Unknown budget metric"));
    }

    #[test]
    fn classic_only_zeroes_resource_fields() {
        let m = BudgetMetrics::classic_only(12_345);
        assert_eq!(m.classic_fee_stroops, 12_345);
        assert_eq!(m.cpu_insns, 0);
        assert_eq!(m.value_of(MetricKind::CpuInsns), 0);
        assert_eq!(m.value_of(MetricKind::ClassicFeeStroops), 12_345);
    }

    #[test]
    fn value_of_widens_u32_fields_to_u64() {
        let m = BudgetMetrics::from_parts(0, 0, 0, 0, 7, 3, 0, 0, 0, 0);
        assert_eq!(m.value_of(MetricKind::ReadEntries), 7u64);
        assert_eq!(m.value_of(MetricKind::WriteEntries), 3u64);
    }

    #[test]
    fn default_metrics_are_empty() {
        assert!(BudgetMetrics::default().is_empty());
        assert!(!BudgetMetrics::classic_only(1).is_empty());
    }
}
