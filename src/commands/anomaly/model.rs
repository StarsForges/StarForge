//! Core data model for real-time anomaly detection: aggregated observation
//! windows, running baseline statistics, and the alerts detectors emit.
//!
//! Every persisted type here carries a `schema_version` so [`super::migrations`]
//! can reshape on-disk data forward without silently dropping fields (see
//! `src/utils/config/migrations.rs` for the pattern this mirrors).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// A single aggregated slice of contract activity, produced either by live
/// ingestion (see [`super::ingest`]) or replayed from a fixture file, and fed
/// to every detector in [`super::detectors`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WindowMetrics {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    /// Total contract events observed in the window.
    pub event_count: u64,
    /// Distinct caller/source addresses observed (topics, invoking accounts).
    pub unique_callers: BTreeSet<String>,
    /// Transactions/events that resolved successfully.
    pub success_count: u64,
    /// Transactions/events that failed or emitted an error diagnostic.
    pub error_count: u64,
    /// Mean fee paid across observed transactions, in stroops.
    pub avg_fee_stroops: f64,
    /// Largest single fee observed, in stroops.
    pub max_fee_stroops: u64,
    /// Largest CPU instruction count observed in a simulated/executed call.
    pub max_cpu_insns: u64,
    /// Mean CPU instruction count across observed calls.
    pub avg_cpu_insns: f64,
    /// Largest single event/value payload size observed, in bytes.
    pub max_payload_bytes: u64,
    /// Count of payloads that matched a suspicious-pattern rule (see
    /// [`super::ingest::scan_payload`]).
    pub suspicious_payload_hits: u64,
    /// Human-readable names of the suspicious patterns matched, deduplicated.
    #[serde(default)]
    pub suspicious_patterns: BTreeSet<String>,
    /// Whether the RPC/health endpoint was reachable while this window was
    /// collected. `None` when no health probe was attempted (e.g. fixture replay).
    #[serde(default)]
    pub rpc_reachable: Option<bool>,
    /// RPC round-trip latency observed during the health probe, if any.
    #[serde(default)]
    pub rpc_latency_ms: Option<u64>,
}

impl Default for WindowMetrics {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            window_start: now,
            window_end: now,
            event_count: 0,
            unique_callers: BTreeSet::new(),
            success_count: 0,
            error_count: 0,
            avg_fee_stroops: 0.0,
            max_fee_stroops: 0,
            max_cpu_insns: 0,
            avg_cpu_insns: 0.0,
            max_payload_bytes: 0,
            suspicious_payload_hits: 0,
            suspicious_patterns: BTreeSet::new(),
            rpc_reachable: None,
            rpc_latency_ms: None,
        }
    }
}

impl WindowMetrics {
    /// Total observed outcomes (success + error). Never zero in a division —
    /// callers should use [`WindowMetrics::error_rate`] instead of dividing manually.
    pub fn total_outcomes(&self) -> u64 {
        self.success_count + self.error_count
    }

    /// Fraction of outcomes that were errors, in `[0.0, 1.0]`. Zero when no
    /// outcomes were observed (an empty window is not itself an error signal).
    pub fn error_rate(&self) -> f64 {
        let total = self.total_outcomes();
        if total == 0 {
            0.0
        } else {
            self.error_count as f64 / total as f64
        }
    }

    /// Named numeric metrics this window contributes to baseline statistics.
    /// Centralized so [`super::baseline::Baseline::observe`] and the detectors
    /// in [`super::detectors`] stay in sync on metric names.
    pub fn named_metrics(&self) -> [(&'static str, f64); 5] {
        [
            (METRIC_EVENT_COUNT, self.event_count as f64),
            (METRIC_ERROR_RATE, self.error_rate()),
            (METRIC_AVG_FEE_STROOPS, self.avg_fee_stroops),
            (METRIC_MAX_CPU_INSNS, self.max_cpu_insns as f64),
            (METRIC_MAX_PAYLOAD_BYTES, self.max_payload_bytes as f64),
        ]
    }
}

pub const METRIC_EVENT_COUNT: &str = "event_count";
pub const METRIC_ERROR_RATE: &str = "error_rate";
pub const METRIC_AVG_FEE_STROOPS: &str = "avg_fee_stroops";
pub const METRIC_MAX_CPU_INSNS: &str = "max_cpu_insns";
pub const METRIC_MAX_PAYLOAD_BYTES: &str = "max_payload_bytes";

/// Online (Welford) mean/variance accumulator for a single metric.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct MetricStats {
    pub count: u64,
    pub mean: f64,
    /// Sum of squared differences from the mean (Welford's M2).
    pub m2: f64,
    pub min: f64,
    pub max: f64,
}

impl Default for MetricStats {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }
}

impl MetricStats {
    /// Folds a new observation into the running statistics using Welford's
    /// online algorithm, which is numerically stable for long-running
    /// baselines and never requires re-scanning prior samples.
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    /// Population standard deviation. `0.0` until at least two samples have
    /// been observed.
    pub fn stddev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / self.count as f64).sqrt()
        }
    }

    /// Z-score of `value` against this baseline, using a floor on the
    /// denominator so a near-zero-variance baseline (e.g. a metric that is
    /// always exactly 0) doesn't produce a division blow-up or a spurious
    /// infinite score on the first non-zero observation.
    pub fn z_score(&self, value: f64) -> f64 {
        let sd = self.stddev();
        let floor = (self.mean.abs() * MIN_RELATIVE_STDDEV).max(MIN_ABSOLUTE_STDDEV);
        (value - self.mean) / sd.max(floor)
    }
}

/// Stddev floor as a fraction of the running mean, preventing division blow-ups.
const MIN_RELATIVE_STDDEV: f64 = 0.05;
/// Absolute stddev floor used when the mean itself is ~0.
const MIN_ABSOLUTE_STDDEV: f64 = 1e-6;

/// Minimum number of observed windows before a baseline is considered mature
/// enough for z-score based detection. Below this, detectors fall back to
/// fixed deterministic thresholds (see [`super::detectors::ThresholdConfig`]).
pub const MIN_MATURE_SAMPLES: u64 = 5;

/// A versioned, persisted baseline for one `(contract, network)` pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub schema_version: u8,
    pub contract_id: String,
    pub network: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Number of [`WindowMetrics`] folded into this baseline so far.
    pub sample_count: u64,
    pub metrics: std::collections::BTreeMap<String, MetricStats>,
    /// Callers seen across all windows folded into this baseline.
    pub known_callers: BTreeSet<String>,
}

impl Baseline {
    pub fn new(contract_id: impl Into<String>, network: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            schema_version: super::migrations::CURRENT_BASELINE_VERSION,
            contract_id: contract_id.into(),
            network: network.into(),
            created_at: now,
            updated_at: now,
            sample_count: 0,
            metrics: std::collections::BTreeMap::new(),
            known_callers: BTreeSet::new(),
        }
    }

    /// Folds one observed window into the baseline: updates every named
    /// metric's running statistics and grows the known-caller set. Mutates
    /// in place so callers can observe several windows before persisting.
    pub fn observe(&mut self, window: &WindowMetrics) {
        for (name, value) in window.named_metrics() {
            self.metrics
                .entry(name.to_string())
                .or_default()
                .update(value);
        }
        self.known_callers
            .extend(window.unique_callers.iter().cloned());
        self.sample_count += 1;
        self.updated_at = Utc::now();
    }

    pub fn is_mature(&self) -> bool {
        self.sample_count >= MIN_MATURE_SAMPLES
    }

    pub fn metric(&self, name: &str) -> Option<&MetricStats> {
        self.metrics.get(name)
    }
}

/// Severity assigned to a detected anomaly, driving exit codes and how
/// prominently `report`/`monitor` render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

impl Severity {
    /// Maps an absolute z-score to a severity band. Kept as a single source
    /// of truth so every z-score based detector grades consistently.
    pub fn from_z_score(abs_z: f64) -> Self {
        if abs_z >= 6.0 {
            Severity::Critical
        } else if abs_z >= 4.5 {
            Severity::High
        } else if abs_z >= 3.0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

/// The category of anomaly a detector flagged. Kept as a fixed enum (rather
/// than a free-form string) so `report`/`export` output is stable for
/// downstream automation, per the issue's JSON-stability requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    VolumeSpike,
    UnusualCallers,
    ErrorRateShift,
    FeeResourceRegression,
    SuspiciousPayload,
    HealthDegradation,
}

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::VolumeSpike => "volume_spike",
            AnomalyKind::UnusualCallers => "unusual_callers",
            AnomalyKind::ErrorRateShift => "error_rate_shift",
            AnomalyKind::FeeResourceRegression => "fee_resource_regression",
            AnomalyKind::SuspiciousPayload => "suspicious_payload",
            AnomalyKind::HealthDegradation => "health_degradation",
        }
    }
}

/// One anomaly detection result. `Alert` is the unit persisted to alert
/// history, deduplicated, exported, and summarized into incident reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub schema_version: u8,
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub contract_id: String,
    pub network: String,
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub metric: String,
    pub observed_value: f64,
    pub expected_mean: Option<f64>,
    pub deviation_score: Option<f64>,
    pub message: String,
    /// Whether this alert was raised via a z-score baseline comparison
    /// (`false`) or a deterministic fixed-threshold fallback used because
    /// the baseline was not yet mature (`true`).
    pub used_fallback_threshold: bool,
    /// Stable key used for deduplication/cooldown (see [`super::alerts`]):
    /// derived from contract + network + kind + metric, independent of the
    /// observed value or timestamp.
    pub dedup_key: String,
}

impl Alert {
    pub fn dedup_key_for(
        contract_id: &str,
        network: &str,
        kind: AnomalyKind,
        metric: &str,
    ) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(contract_id.as_bytes());
        hasher.update(b"|");
        hasher.update(network.as_bytes());
        hasher.update(b"|");
        hasher.update(kind.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(metric.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welford_mean_and_stddev_match_closed_form() {
        let mut stats = MetricStats::default();
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            stats.update(v);
        }
        assert_eq!(stats.count, 8);
        assert!((stats.mean - 5.0).abs() < 1e-9);
        // Population stddev of this classic example is exactly 2.0.
        assert!((stats.stddev() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn z_score_is_zero_at_the_mean() {
        let mut stats = MetricStats::default();
        for v in [10.0, 12.0, 8.0, 11.0, 9.0] {
            stats.update(v);
        }
        assert!(stats.z_score(stats.mean).abs() < 1e-9);
    }

    #[test]
    fn z_score_does_not_blow_up_on_zero_variance_baseline() {
        let mut stats = MetricStats::default();
        for _ in 0..10 {
            stats.update(0.0);
        }
        let z = stats.z_score(1.0);
        assert!(z.is_finite());
        assert!(z > 0.0);
    }

    #[test]
    fn error_rate_is_zero_for_empty_window() {
        let w = WindowMetrics::default();
        assert_eq!(w.error_rate(), 0.0);
    }

    #[test]
    fn error_rate_computes_fraction() {
        let w = WindowMetrics {
            success_count: 3,
            error_count: 1,
            ..Default::default()
        };
        assert!((w.error_rate() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn baseline_observe_grows_sample_count_and_callers() {
        let mut baseline = Baseline::new("CCONTRACT", "testnet");
        let mut w = WindowMetrics {
            event_count: 10,
            ..Default::default()
        };
        w.unique_callers.insert("GABC".to_string());
        baseline.observe(&w);
        assert_eq!(baseline.sample_count, 1);
        assert!(baseline.known_callers.contains("GABC"));
        assert!(!baseline.is_mature());
        for _ in 0..4 {
            baseline.observe(&w);
        }
        assert!(baseline.is_mature());
    }

    #[test]
    fn severity_bands_are_monotonic() {
        assert_eq!(Severity::from_z_score(1.0), Severity::Low);
        assert_eq!(Severity::from_z_score(3.5), Severity::Medium);
        assert_eq!(Severity::from_z_score(5.0), Severity::High);
        assert_eq!(Severity::from_z_score(7.0), Severity::Critical);
        assert!(Severity::Low < Severity::Critical);
    }

    #[test]
    fn dedup_key_is_stable_and_scoped() {
        let a = Alert::dedup_key_for("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        let b = Alert::dedup_key_for("CFOO", "testnet", AnomalyKind::VolumeSpike, "event_count");
        let c = Alert::dedup_key_for("CFOO", "mainnet", AnomalyKind::VolumeSpike, "event_count");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
