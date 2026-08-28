//! Incident report rendering: combines alert history, summary statistics,
//! and an explanation (deterministic or AI-augmented) into markdown or a
//! stable JSON shape suitable for automation.

use super::alerts::AlertStats;
use super::model::Alert;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct IncidentReport {
    pub contract_id: String,
    pub network: String,
    pub generated_at: DateTime<Utc>,
    pub window_hours: i64,
    pub stats: AlertStatsView,
    pub alerts: Vec<Alert>,
    pub explanation: String,
    pub ai_narrative: Option<String>,
}

/// Serializable view of [`AlertStats`] (kept separate so `alerts.rs` doesn't
/// need a `Serialize` dependency on report-specific field names).
#[derive(Debug, Serialize)]
pub struct AlertStatsView {
    pub total: usize,
    pub by_severity: std::collections::BTreeMap<String, usize>,
    pub by_kind: std::collections::BTreeMap<String, usize>,
}

impl From<AlertStats> for AlertStatsView {
    fn from(s: AlertStats) -> Self {
        Self {
            total: s.total,
            by_severity: s.by_severity,
            by_kind: s.by_kind,
        }
    }
}

impl IncidentReport {
    pub fn build(
        contract_id: &str,
        network: &str,
        window_hours: i64,
        alerts: Vec<Alert>,
        explanation: String,
        ai_narrative: Option<String>,
    ) -> Self {
        let stats = super::alerts::summarize(&alerts).into();
        Self {
            contract_id: contract_id.to_string(),
            network: network.to_string(),
            generated_at: Utc::now(),
            window_hours,
            stats,
            alerts,
            explanation,
            ai_narrative,
        }
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "# Anomaly Incident Report: {}\n\n",
            self.contract_id
        ));
        md.push_str(&format!("**Network:** `{}`\n", self.network));
        md.push_str(&format!(
            "**Generated:** {}\n",
            self.generated_at.to_rfc3339()
        ));
        md.push_str(&format!(
            "**Window:** last {} hour(s)\n\n",
            self.window_hours
        ));

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- Total alerts: {}\n", self.stats.total));
        if !self.stats.by_severity.is_empty() {
            md.push_str("- By severity:\n");
            for (severity, count) in &self.stats.by_severity {
                md.push_str(&format!("  - {}: {}\n", severity, count));
            }
        }
        if !self.stats.by_kind.is_empty() {
            md.push_str("- By kind:\n");
            for (kind, count) in &self.stats.by_kind {
                md.push_str(&format!("  - {}: {}\n", kind, count));
            }
        }
        md.push('\n');

        if !self.alerts.is_empty() {
            md.push_str("## Alerts\n\n");
            md.push_str("| Time | Severity | Kind | Metric | Observed | Message |\n");
            md.push_str("|---|---|---|---|---|---|\n");
            for a in &self.alerts {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {:.2} | {} |\n",
                    a.timestamp.to_rfc3339(),
                    a.severity,
                    a.kind.as_str(),
                    a.metric,
                    a.observed_value,
                    a.message.replace('|', "\\|"),
                ));
            }
            md.push('\n');
        }

        md.push_str("## Explanation\n\n");
        md.push_str(&self.explanation);
        md.push('\n');

        if let Some(narrative) = &self.ai_narrative {
            md.push_str("\n## AI Narrative\n\n");
            md.push_str(narrative);
            md.push('\n');
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::anomaly::model::{AnomalyKind, Severity};

    fn sample_alert() -> Alert {
        Alert {
            schema_version: 1,
            id: "id-1".to_string(),
            timestamp: Utc::now(),
            contract_id: "CFOO".to_string(),
            network: "testnet".to_string(),
            kind: AnomalyKind::VolumeSpike,
            severity: Severity::High,
            metric: "event_count".to_string(),
            observed_value: 1000.0,
            expected_mean: Some(100.0),
            deviation_score: Some(5.0),
            message: "spike".to_string(),
            used_fallback_threshold: false,
            dedup_key: "key".to_string(),
        }
    }

    #[test]
    fn json_report_round_trips_alert_count() {
        let report = IncidentReport::build(
            "CFOO",
            "testnet",
            24,
            vec![sample_alert()],
            "explanation".to_string(),
            None,
        );
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["alerts"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["stats"]["total"], 1);
    }

    #[test]
    fn markdown_report_contains_key_sections() {
        let report = IncidentReport::build(
            "CFOO",
            "testnet",
            24,
            vec![sample_alert()],
            "deterministic explanation text".to_string(),
            Some("ai narrative text".to_string()),
        );
        let md = report.to_markdown();
        assert!(md.contains("# Anomaly Incident Report"));
        assert!(md.contains("## Alerts"));
        assert!(md.contains("## Explanation"));
        assert!(md.contains("## AI Narrative"));
        assert!(md.contains("deterministic explanation text"));
        assert!(md.contains("ai narrative text"));
    }

    #[test]
    fn markdown_report_without_alerts_omits_alert_table() {
        let report =
            IncidentReport::build("CFOO", "testnet", 24, vec![], "clean".to_string(), None);
        let md = report.to_markdown();
        assert!(!md.contains("## Alerts"));
        assert!(!md.contains("## AI Narrative"));
    }

    #[test]
    fn markdown_escapes_pipe_characters_in_messages() {
        let mut alert = sample_alert();
        alert.message = "value | with | pipes".to_string();
        let report =
            IncidentReport::build("CFOO", "testnet", 24, vec![alert], "x".to_string(), None);
        let md = report.to_markdown();
        assert!(md.contains("value \\| with \\| pipes"));
    }
}
