//! Flame-style summary generation from profile hot spots.
//!
//! Produces a text-based "flame" chart that visualizes the relative CPU cost
//! breakdown of a contract invocation. This is intentionally a simple
//! ASCII representation suitable for terminal display and CI logs.

use crate::utils::performance::metrics::{HotSpot, ProfileMetrics};
use serde::{Deserialize, Serialize};

/// Width of the flame chart bar in characters.
const BAR_WIDTH: usize = 40;

/// A single row in the flame summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlameRow {
    pub label: String,
    pub cpu_insns: u64,
    pub cpu_pct: f64,
    pub mem_bytes: u64,
    /// ASCII bar representation of the cpu_pct fraction.
    pub bar: String,
}

/// Full flame summary for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlameSummary {
    pub contract_label: String,
    pub total_cpu_insns: u64,
    pub total_mem_bytes: u64,
    pub rows: Vec<FlameRow>,
    /// Pre-formatted text version of the chart.
    pub text: String,
}

impl FlameSummary {
    /// Build a flame summary from a [`ProfileMetrics`] value.
    pub fn from_metrics(metrics: &ProfileMetrics) -> Self {
        let rows = build_rows(&metrics.hot_spots, metrics.cpu_insns);
        let text = render_text(
            &metrics.contract_label,
            metrics.cpu_insns,
            metrics.mem_bytes,
            &rows,
        );
        Self {
            contract_label: metrics.contract_label.clone(),
            total_cpu_insns: metrics.cpu_insns,
            total_mem_bytes: metrics.mem_bytes,
            rows,
            text,
        }
    }
}

fn build_rows(hot_spots: &[HotSpot], total_cpu: u64) -> Vec<FlameRow> {
    if hot_spots.is_empty() {
        return Vec::new();
    }
    hot_spots
        .iter()
        .map(|hs| {
            let pct = if total_cpu > 0 {
                (hs.cpu_insns as f64 / total_cpu as f64) * 100.0
            } else {
                hs.cpu_fraction * 100.0
            };
            let filled = ((pct / 100.0) * BAR_WIDTH as f64).round() as usize;
            let filled = filled.min(BAR_WIDTH);
            let bar = format!("{}{}", "█".repeat(filled), "░".repeat(BAR_WIDTH - filled));
            FlameRow {
                label: hs.label.clone(),
                cpu_insns: hs.cpu_insns,
                cpu_pct: pct,
                mem_bytes: hs.mem_bytes,
                bar,
            }
        })
        .collect()
}

fn render_text(label: &str, total_cpu: u64, total_mem: u64, rows: &[FlameRow]) -> String {
    let mut out = String::new();
    out.push_str(&format!("Flame Summary — {}\n", label));
    out.push_str(&format!(
        "Total CPU: {:>12} insns    Peak Mem: {:>10} bytes\n",
        total_cpu, total_mem
    ));
    out.push_str(&format!(
        "{:<28} {:<12} {:>6}%   Bar\n",
        "Segment", "CPU insns", "Share"
    ));
    out.push_str(&"─".repeat(80));
    out.push('\n');
    for row in rows {
        out.push_str(&format!(
            "{:<28} {:>12} {:>6.1}%   {}\n",
            row.label, row.cpu_insns, row.cpu_pct, row.bar
        ));
    }
    out.push_str(&"─".repeat(80));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::performance::metrics::{HotSpot, ProfileMetrics};

    fn make_metrics_with_spots() -> ProfileMetrics {
        let mut m = ProfileMetrics {
            cpu_insns: 1_000_000,
            mem_bytes: 4096,
            contract_label: "flame-test".to_string(),
            ..Default::default()
        };
        m.hot_spots = vec![
            HotSpot {
                label: "computation".to_string(),
                cpu_fraction: 0.60,
                cpu_insns: 600_000,
                mem_bytes: 3276,
            },
            HotSpot {
                label: "storage_io".to_string(),
                cpu_fraction: 0.30,
                cpu_insns: 300_000,
                mem_bytes: 614,
            },
            HotSpot {
                label: "events".to_string(),
                cpu_fraction: 0.10,
                cpu_insns: 100_000,
                mem_bytes: 204,
            },
        ];
        m
    }

    #[test]
    fn flame_summary_has_correct_row_count() {
        let m = make_metrics_with_spots();
        let summary = FlameSummary::from_metrics(&m);
        assert_eq!(summary.rows.len(), 3);
    }

    #[test]
    fn flame_summary_rows_percentages_sum_to_100() {
        let m = make_metrics_with_spots();
        let summary = FlameSummary::from_metrics(&m);
        let total: f64 = summary.rows.iter().map(|r| r.cpu_pct).sum();
        assert!((total - 100.0).abs() < 1.0);
    }

    #[test]
    fn bar_length_respects_bar_width() {
        let m = make_metrics_with_spots();
        let summary = FlameSummary::from_metrics(&m);
        for row in &summary.rows {
            // Count printable chars: each '█' and '░' is one logical char
            let bar_char_count: usize = row.bar.chars().filter(|c| *c == '█' || *c == '░').count();
            assert_eq!(bar_char_count, BAR_WIDTH);
        }
    }

    #[test]
    fn text_contains_label_and_totals() {
        let m = make_metrics_with_spots();
        let summary = FlameSummary::from_metrics(&m);
        assert!(summary.text.contains("flame-test"));
        assert!(summary.text.contains("1000000"));
    }

    #[test]
    fn empty_hot_spots_produces_empty_rows() {
        let m = ProfileMetrics {
            cpu_insns: 0,
            ..Default::default()
        };
        let summary = FlameSummary::from_metrics(&m);
        assert!(summary.rows.is_empty());
    }

    #[test]
    fn flame_summary_serializes_to_json() {
        let m = make_metrics_with_spots();
        let summary = FlameSummary::from_metrics(&m);
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("flame-test"));
        assert!(json.contains("computation"));
    }
}
