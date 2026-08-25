//! Anomaly detectors: volume spikes, unusual callers, error-rate shifts,
//! fee/resource regressions, and suspicious event payload patterns.
//!
//! Every z-score based detector has a deterministic, threshold-based
//! fallback that fires instead when the baseline is not yet
//! [`Baseline::is_mature`] (fewer than [`MIN_MATURE_SAMPLES`] observed
//! windows) — this satisfies the issue's "AI-assisted incident explanations
//! with deterministic threshold-based fallback alerts" requirement even
//! before any AI narrative is involved: the *detection* itself never
//! silently no-ops just because a baseline hasn't been built yet.

use super::model::{
    Alert, AnomalyKind, Baseline, Severity, WindowMetrics, METRIC_AVG_FEE_STROOPS,
    METRIC_ERROR_RATE, METRIC_EVENT_COUNT, METRIC_MAX_CPU_INSNS, METRIC_MAX_PAYLOAD_BYTES,
};
use chrono::Utc;
use uuid::Uuid;

/// Fixed thresholds used when a baseline is too young to trust for z-scores,
/// and the z-score threshold used once it is mature. All are overridable so
/// operators can tune sensitivity per contract via CLI flags.
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// Absolute z-score beyond which a mature-baseline metric is anomalous.
    pub z_score_threshold: f64,
    /// Fallback: event count above this in a single window is anomalous.
    pub fallback_event_count: f64,
    /// Fallback: error rate above this fraction is anomalous.
    pub fallback_error_rate: f64,
    /// Fallback: average fee (stroops) above this is anomalous.
    pub fallback_avg_fee_stroops: f64,
    /// Fallback: max CPU instructions above this is anomalous.
    pub fallback_max_cpu_insns: f64,
    /// Fallback: max payload bytes above this is anomalous.
    pub fallback_max_payload_bytes: f64,
    /// Fallback / cold-start: number of never-before-seen callers in one
    /// window above this is anomalous.
    pub fallback_new_callers: usize,
    /// Once mature, the fraction of a window's callers that are new before
    /// it's considered an "unusual callers" anomaly.
    pub new_caller_fraction_threshold: f64,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            z_score_threshold: 3.0,
            fallback_event_count: 500.0,
            fallback_error_rate: 0.2,
            fallback_avg_fee_stroops: 1_000_000.0,
            fallback_max_cpu_insns: 80_000_000.0,
            fallback_max_payload_bytes: 65_536.0,
            fallback_new_callers: 25,
            new_caller_fraction_threshold: 0.5,
        }
    }
}

/// Runs every registered detector over one observation window and returns
/// every anomaly found, most severe first.
pub fn detect_all(
    window: &WindowMetrics,
    baseline: &Baseline,
    thresholds: &ThresholdConfig,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    alerts.extend(detect_volume_spike(window, baseline, thresholds));
    alerts.extend(detect_unusual_callers(window, baseline, thresholds));
    alerts.extend(detect_error_rate_shift(window, baseline, thresholds));
    alerts.extend(detect_fee_resource_regression(window, baseline, thresholds));
    alerts.extend(detect_suspicious_payload(window, baseline));
    alerts.extend(detect_health_degradation(window, baseline));
    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}

fn make_alert(
    baseline: &Baseline,
    kind: AnomalyKind,
    metric: &str,
    observed: f64,
    expected_mean: Option<f64>,
    deviation_score: Option<f64>,
    used_fallback_threshold: bool,
    message: String,
) -> Alert {
    let severity = deviation_score
        .map(|z| Severity::from_z_score(z.abs()))
        .unwrap_or(Severity::Medium);
    Alert {
        schema_version: 1,
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        contract_id: baseline.contract_id.clone(),
        network: baseline.network.clone(),
        kind,
        severity,
        metric: metric.to_string(),
        observed_value: observed,
        expected_mean,
        deviation_score,
        message,
        used_fallback_threshold,
        dedup_key: Alert::dedup_key_for(&baseline.contract_id, &baseline.network, kind, metric),
    }
}

/// Evaluates one metric against baseline statistics: z-score based when the
/// baseline is mature, a fixed floor otherwise. Shared by every detector
/// that reduces to "is this one number too high".
#[allow(clippy::too_many_arguments)]
fn evaluate_metric(
    baseline: &Baseline,
    kind: AnomalyKind,
    metric_name: &str,
    observed: f64,
    fallback_floor: f64,
    thresholds: &ThresholdConfig,
    describe: impl Fn(f64, Option<f64>) -> String,
) -> Option<Alert> {
    let stats = baseline.metric(metric_name);
    if baseline.is_mature() {
        let stats = stats?;
        let z = stats.z_score(observed);
        if z.abs() >= thresholds.z_score_threshold {
            return Some(make_alert(
                baseline,
                kind,
                metric_name,
                observed,
                Some(stats.mean),
                Some(z),
                false,
                describe(observed, Some(stats.mean)),
            ));
        }
        None
    } else if observed > fallback_floor {
        Some(make_alert(
            baseline,
            kind,
            metric_name,
            observed,
            None,
            None,
            true,
            describe(observed, None),
        ))
    } else {
        None
    }
}

pub fn detect_volume_spike(
    window: &WindowMetrics,
    baseline: &Baseline,
    thresholds: &ThresholdConfig,
) -> Option<Alert> {
    evaluate_metric(
        baseline,
        AnomalyKind::VolumeSpike,
        METRIC_EVENT_COUNT,
        window.event_count as f64,
        thresholds.fallback_event_count,
        thresholds,
        |observed, mean| {
            match mean {
            Some(mean) => format!(
                "Event volume of {:.0} is a significant deviation from the baseline average of {:.1}.",
                observed, mean
            ),
            None => format!(
                "Event volume of {:.0} exceeds the deterministic fallback threshold ({:.0}) \
                 while the baseline is still warming up.",
                observed, thresholds.fallback_event_count
            ),
        }
        },
    )
}

pub fn detect_error_rate_shift(
    window: &WindowMetrics,
    baseline: &Baseline,
    thresholds: &ThresholdConfig,
) -> Option<Alert> {
    evaluate_metric(
        baseline,
        AnomalyKind::ErrorRateShift,
        METRIC_ERROR_RATE,
        window.error_rate(),
        thresholds.fallback_error_rate,
        thresholds,
        |observed, mean| match mean {
            Some(mean) => format!(
                "Error rate of {:.1}% deviates significantly from the baseline average of {:.1}%.",
                observed * 100.0,
                mean * 100.0
            ),
            None => format!(
                "Error rate of {:.1}% exceeds the deterministic fallback threshold ({:.0}%) \
                 while the baseline is still warming up.",
                observed * 100.0,
                thresholds.fallback_error_rate * 100.0
            ),
        },
    )
}

pub fn detect_fee_resource_regression(
    window: &WindowMetrics,
    baseline: &Baseline,
    thresholds: &ThresholdConfig,
) -> Vec<Alert> {
    let mut out = Vec::new();
    if let Some(a) = evaluate_metric(
        baseline,
        AnomalyKind::FeeResourceRegression,
        METRIC_AVG_FEE_STROOPS,
        window.avg_fee_stroops,
        thresholds.fallback_avg_fee_stroops,
        thresholds,
        |observed, mean| {
            match mean {
            Some(mean) => format!(
                "Average fee of {:.0} stroops deviates significantly from the baseline average of {:.0}.",
                observed, mean
            ),
            None => format!(
                "Average fee of {:.0} stroops exceeds the deterministic fallback threshold \
                 ({:.0}) while the baseline is still warming up.",
                observed, thresholds.fallback_avg_fee_stroops
            ),
        }
        },
    ) {
        out.push(a);
    }
    if let Some(a) = evaluate_metric(
        baseline,
        AnomalyKind::FeeResourceRegression,
        METRIC_MAX_CPU_INSNS,
        window.max_cpu_insns as f64,
        thresholds.fallback_max_cpu_insns,
        thresholds,
        |observed, mean| {
            match mean {
            Some(mean) => format!(
                "Peak CPU instructions ({:.0}) deviate significantly from the baseline average of {:.0}.",
                observed, mean
            ),
            None => format!(
                "Peak CPU instructions ({:.0}) exceed the deterministic fallback threshold \
                 ({:.0}) while the baseline is still warming up.",
                observed, thresholds.fallback_max_cpu_insns
            ),
        }
        },
    ) {
        out.push(a);
    }
    if let Some(a) = evaluate_metric(
        baseline,
        AnomalyKind::FeeResourceRegression,
        METRIC_MAX_PAYLOAD_BYTES,
        window.max_payload_bytes as f64,
        thresholds.fallback_max_payload_bytes,
        thresholds,
        |observed, mean| match mean {
            Some(mean) => format!(
                "Peak event payload size ({:.0} bytes) deviates significantly from the baseline \
                 average of {:.0}.",
                observed, mean
            ),
            None => format!(
                "Peak event payload size ({:.0} bytes) exceeds the deterministic fallback \
                 threshold ({:.0}) while the baseline is still warming up.",
                observed, thresholds.fallback_max_payload_bytes
            ),
        },
    ) {
        out.push(a);
    }
    out
}

pub fn detect_unusual_callers(
    window: &WindowMetrics,
    baseline: &Baseline,
    thresholds: &ThresholdConfig,
) -> Option<Alert> {
    if window.unique_callers.is_empty() {
        return None;
    }
    let new_callers = window
        .unique_callers
        .iter()
        .filter(|c| !baseline.known_callers.contains(*c))
        .count();

    if baseline.is_mature() {
        let fraction = new_callers as f64 / window.unique_callers.len() as f64;
        if fraction >= thresholds.new_caller_fraction_threshold
            && new_callers >= thresholds.fallback_new_callers.min(3)
        {
            return Some(make_alert(
                baseline,
                AnomalyKind::UnusualCallers,
                "new_caller_fraction",
                fraction,
                Some(0.0),
                None,
                false,
                format!(
                    "{} of {} callers this window ({:.0}%) have never been seen before, versus \
                     {} known callers in the baseline.",
                    new_callers,
                    window.unique_callers.len(),
                    fraction * 100.0,
                    baseline.known_callers.len()
                ),
            ));
        }
        None
    } else if new_callers >= thresholds.fallback_new_callers {
        Some(make_alert(
            baseline,
            AnomalyKind::UnusualCallers,
            "new_caller_fraction",
            new_callers as f64,
            None,
            None,
            true,
            format!(
                "{} distinct new callers observed in one window, exceeding the deterministic \
                 fallback threshold ({}) while the baseline is still warming up.",
                new_callers, thresholds.fallback_new_callers
            ),
        ))
    } else {
        None
    }
}

pub fn detect_suspicious_payload(window: &WindowMetrics, baseline: &Baseline) -> Option<Alert> {
    if window.suspicious_payload_hits == 0 {
        return None;
    }
    let severity = if window.suspicious_payload_hits >= 10 {
        Severity::Critical
    } else if window.suspicious_payload_hits >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };
    let patterns = window
        .suspicious_patterns
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let mut alert = make_alert(
        baseline,
        AnomalyKind::SuspiciousPayload,
        "suspicious_payload_hits",
        window.suspicious_payload_hits as f64,
        None,
        None,
        true,
        format!(
            "{} event payload(s) matched suspicious patterns: {}.",
            window.suspicious_payload_hits,
            if patterns.is_empty() {
                "unspecified".to_string()
            } else {
                patterns
            }
        ),
    );
    alert.severity = severity;
    Some(alert)
}

pub fn detect_health_degradation(window: &WindowMetrics, baseline: &Baseline) -> Option<Alert> {
    match window.rpc_reachable {
        Some(false) => Some(make_alert(
            baseline,
            AnomalyKind::HealthDegradation,
            "rpc_reachable",
            0.0,
            None,
            None,
            true,
            "RPC endpoint was unreachable during this observation window.".to_string(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn mature_baseline(mean_events: f64, mean_error_rate: f64) -> Baseline {
        let mut baseline = Baseline::new("CFOO", "testnet");
        for _ in 0..10 {
            let w = WindowMetrics {
                event_count: mean_events as u64,
                success_count: ((1.0 - mean_error_rate) * 100.0) as u64,
                error_count: (mean_error_rate * 100.0) as u64,
                avg_fee_stroops: 1000.0,
                max_cpu_insns: 1_000_000,
                ..Default::default()
            };
            baseline.observe(&w);
        }
        baseline
    }

    #[test]
    fn volume_spike_fires_on_mature_baseline_deviation() {
        let baseline = mature_baseline(100.0, 0.0);
        let window = WindowMetrics {
            event_count: 100_000,
            ..Default::default()
        };
        let alert = detect_volume_spike(&window, &baseline, &ThresholdConfig::default());
        assert!(alert.is_some());
        assert!(!alert.unwrap().used_fallback_threshold);
    }

    #[test]
    fn volume_spike_silent_within_normal_range() {
        let baseline = mature_baseline(100.0, 0.0);
        let window = WindowMetrics {
            event_count: 105,
            ..Default::default()
        };
        assert!(detect_volume_spike(&window, &baseline, &ThresholdConfig::default()).is_none());
    }

    #[test]
    fn volume_spike_uses_fallback_threshold_on_cold_start() {
        let baseline = Baseline::new("CFOO", "testnet");
        let window = WindowMetrics {
            event_count: 10_000,
            ..Default::default()
        };
        let alert = detect_volume_spike(&window, &baseline, &ThresholdConfig::default()).unwrap();
        assert!(alert.used_fallback_threshold);
    }

    #[test]
    fn volume_spike_silent_below_fallback_on_cold_start() {
        let baseline = Baseline::new("CFOO", "testnet");
        let window = WindowMetrics {
            event_count: 5,
            ..Default::default()
        };
        assert!(detect_volume_spike(&window, &baseline, &ThresholdConfig::default()).is_none());
    }

    #[test]
    fn error_rate_shift_fires_when_errors_spike() {
        let baseline = mature_baseline(100.0, 0.01);
        let window = WindowMetrics {
            success_count: 50,
            error_count: 50,
            ..Default::default()
        };
        let alert = detect_error_rate_shift(&window, &baseline, &ThresholdConfig::default());
        assert!(alert.is_some());
    }

    #[test]
    fn fee_resource_regression_flags_cpu_and_fee_independently() {
        let baseline = mature_baseline(100.0, 0.0);
        let window = WindowMetrics {
            avg_fee_stroops: 5_000_000.0,
            max_cpu_insns: 500_000_000,
            ..Default::default()
        };
        let alerts =
            detect_fee_resource_regression(&window, &baseline, &ThresholdConfig::default());
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn unusual_callers_fires_when_mostly_new_on_mature_baseline() {
        let mut baseline = mature_baseline(100.0, 0.0);
        baseline.known_callers = BTreeSet::from(["GKNOWN1".to_string(), "GKNOWN2".to_string()]);
        let window = WindowMetrics {
            unique_callers: BTreeSet::from([
                "GNEW1".to_string(),
                "GNEW2".to_string(),
                "GNEW3".to_string(),
                "GNEW4".to_string(),
            ]),
            ..Default::default()
        };
        let alert = detect_unusual_callers(&window, &baseline, &ThresholdConfig::default());
        assert!(alert.is_some());
    }

    #[test]
    fn unusual_callers_silent_when_all_known() {
        let mut baseline = mature_baseline(100.0, 0.0);
        baseline.known_callers = BTreeSet::from(["GKNOWN1".to_string()]);
        let window = WindowMetrics {
            unique_callers: BTreeSet::from(["GKNOWN1".to_string()]),
            ..Default::default()
        };
        assert!(detect_unusual_callers(&window, &baseline, &ThresholdConfig::default()).is_none());
    }

    #[test]
    fn suspicious_payload_severity_scales_with_hit_count() {
        let baseline = Baseline::new("CFOO", "testnet");
        let low = WindowMetrics {
            suspicious_payload_hits: 1,
            ..Default::default()
        };
        assert_eq!(
            detect_suspicious_payload(&low, &baseline).unwrap().severity,
            Severity::Medium
        );

        let critical = WindowMetrics {
            suspicious_payload_hits: 20,
            ..Default::default()
        };
        assert_eq!(
            detect_suspicious_payload(&critical, &baseline)
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn suspicious_payload_silent_when_no_hits() {
        let baseline = Baseline::new("CFOO", "testnet");
        let window = WindowMetrics::default();
        assert!(detect_suspicious_payload(&window, &baseline).is_none());
    }

    #[test]
    fn health_degradation_fires_only_when_explicitly_unreachable() {
        let baseline = Baseline::new("CFOO", "testnet");
        let mut window = WindowMetrics {
            rpc_reachable: Some(false),
            ..Default::default()
        };
        assert!(detect_health_degradation(&window, &baseline).is_some());

        window.rpc_reachable = Some(true);
        assert!(detect_health_degradation(&window, &baseline).is_none());

        window.rpc_reachable = None;
        assert!(detect_health_degradation(&window, &baseline).is_none());
    }

    #[test]
    fn detect_all_sorts_most_severe_first() {
        let baseline = Baseline::new("CFOO", "testnet");
        let window = WindowMetrics {
            event_count: 10_000,         // fallback -> Medium
            suspicious_payload_hits: 20, // Critical
            ..Default::default()
        };
        let alerts = detect_all(&window, &baseline, &ThresholdConfig::default());
        assert!(alerts.len() >= 2);
        assert_eq!(alerts.first().unwrap().severity, Severity::Critical);
    }

    #[test]
    fn dedup_key_is_populated_on_every_alert() {
        let baseline = Baseline::new("CFOO", "testnet");
        let window = WindowMetrics {
            event_count: 10_000,
            ..Default::default()
        };
        let alerts = detect_all(&window, &baseline, &ThresholdConfig::default());
        assert!(alerts.iter().all(|a| !a.dedup_key.is_empty()));
    }
}
