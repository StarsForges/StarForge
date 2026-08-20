//! Assembles compliance findings, waivers, and AI-assisted explanations into
//! a single audit-ready report, in stable human-readable and JSON forms.
//!
//! Rendering is UI-agnostic (plain text, no ANSI codes) so it can be tested
//! for stability and reused by both the terminal command and file export.

use super::redact::redact_text;
use super::scanner::ControlStatus;
use super::waiver::FindingOutcome;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const REPORT_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ReportSummary {
    pub pass: usize,
    pub fail: usize,
    pub waived: usize,
    pub needs_evidence: usize,
    pub not_applicable: usize,
}

impl ReportSummary {
    pub fn from_outcomes(outcomes: &[FindingOutcome]) -> Self {
        let mut summary = ReportSummary::default();
        for outcome in outcomes {
            match outcome.effective_status {
                ControlStatus::Pass => summary.pass += 1,
                ControlStatus::Fail => summary.fail += 1,
                ControlStatus::Waived => summary.waived += 1,
                ControlStatus::NeedsEvidence => summary.needs_evidence += 1,
                ControlStatus::NotApplicable => summary.not_applicable += 1,
            }
        }
        summary
    }

    /// A report is "clean" when nothing is actively failing or missing
    /// evidence. Waived and not-applicable controls do not block this —
    /// that's the entire point of recording a waiver.
    pub fn is_clean(&self) -> bool {
        self.fail == 0 && self.needs_evidence == 0
    }
}

/// A complete compliance check result: every evaluated control's effective
/// status, plus any additive AI-generated explanations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub jurisdictions: Vec<String>,
    pub outcomes: Vec<FindingOutcome>,
    pub summary: ReportSummary,
    /// `control_id` -> AI-generated explanation. Additive only: this map is
    /// never consulted when computing `summary` or any finding's status.
    #[serde(default)]
    pub ai_explanations: BTreeMap<String, String>,
}

impl ComplianceReport {
    pub fn new(jurisdictions: Vec<String>, outcomes: Vec<FindingOutcome>) -> Self {
        let summary = ReportSummary::from_outcomes(&outcomes);
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            generated_at: Utc::now(),
            jurisdictions,
            outcomes,
            summary,
            ai_explanations: BTreeMap::new(),
        }
    }

    /// A redacted copy: every free-text field is passed through
    /// [`redact_text`] so secret-shaped tokens never survive into an
    /// exported report.
    fn redacted_clone(&self) -> Self {
        let mut clone = self.clone();
        for outcome in &mut clone.outcomes {
            outcome.finding.detail = redact_text(&outcome.finding.detail);
        }
        for explanation in clone.ai_explanations.values_mut() {
            *explanation = redact_text(explanation);
        }
        clone
    }

    /// Renders the report as pretty-printed, redacted JSON.
    pub fn to_json_redacted(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.redacted_clone())?)
    }

    /// Renders the report as plain, redacted, human-readable text (no ANSI
    /// escapes — coloring, if any, is applied by the caller).
    pub fn render_human(&self) -> String {
        let report = self.redacted_clone();
        let mut out = String::new();
        out.push_str(&format!(
            "Compliance Report — generated {}\n",
            report.generated_at.to_rfc3339()
        ));
        out.push_str(&format!(
            "Jurisdictions: {}\n",
            report.jurisdictions.join(", ")
        ));
        out.push_str(&format!(
            "Summary: {} pass, {} fail, {} waived, {} needs-evidence, {} not-applicable\n\n",
            report.summary.pass,
            report.summary.fail,
            report.summary.waived,
            report.summary.needs_evidence,
            report.summary.not_applicable
        ));

        for outcome in &report.outcomes {
            out.push_str(&format!(
                "[{}] {} — {} ({})\n",
                outcome.effective_status,
                outcome.finding.control_id,
                outcome.finding.title,
                outcome.finding.severity
            ));
            out.push_str(&format!("  {}\n", outcome.finding.detail));
            if let Some(waiver_id) = &outcome.waiver_id {
                out.push_str(&format!("  waived by: {waiver_id}\n"));
            }
            if let Some(explanation) = report.ai_explanations.get(&outcome.finding.control_id) {
                out.push_str(&format!("  AI-assisted explanation: {explanation}\n"));
            }
            out.push('\n');
        }

        if !report.summary.is_clean() {
            out.push_str(
                "Result: NOT CLEAN — one or more controls are failing or need evidence.\n",
            );
        } else {
            out.push_str("Result: CLEAN — no failing or unresolved controls.\n");
        }

        out
    }

    /// Renders the report as a redacted Markdown document, suitable as a
    /// standalone audit artifact (`starforge compliance report export
    /// --format markdown`).
    pub fn render_markdown(&self) -> String {
        self.redacted_clone().markdown_body()
    }

    /// Same as [`Self::render_markdown`], but without redaction. Only use
    /// this when the caller explicitly opted in (e.g. `--reveal-secrets`).
    pub fn render_markdown_unredacted(&self) -> String {
        self.markdown_body()
    }

    fn markdown_body(&self) -> String {
        let report = self;
        let mut out = String::new();

        out.push_str("# Compliance Report\n\n");
        out.push_str(&format!(
            "- **Generated:** {}\n",
            report.generated_at.to_rfc3339()
        ));
        out.push_str(&format!(
            "- **Jurisdictions:** {}\n",
            report.jurisdictions.join(", ")
        ));
        out.push_str(&format!(
            "- **Summary:** {} pass, {} fail, {} waived, {} needs-evidence, {} not-applicable\n\n",
            report.summary.pass,
            report.summary.fail,
            report.summary.waived,
            report.summary.needs_evidence,
            report.summary.not_applicable
        ));

        out.push_str("| Control | Status | Severity | Title | Detail |\n");
        out.push_str("|---|---|---|---|---|\n");
        for outcome in &report.outcomes {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                outcome.finding.control_id,
                outcome.effective_status,
                outcome.finding.severity,
                outcome.finding.title,
                outcome.finding.detail.replace('|', "\\|")
            ));
        }

        if !report.ai_explanations.is_empty() {
            out.push_str("\n## AI-Assisted Explanations\n\n");
            out.push_str(
                "_Additive only — generated after deterministic status was fixed; does not affect pass/fail._\n\n",
            );
            for (control_id, explanation) in &report.ai_explanations {
                out.push_str(&format!("- **{control_id}:** {explanation}\n"));
            }
        }

        out.push('\n');
        if !report.summary.is_clean() {
            out.push_str(
                "**Result: NOT CLEAN** — one or more controls are failing or need evidence.\n",
            );
        } else {
            out.push_str("**Result: CLEAN** — no failing or unresolved controls.\n");
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::compliance::framework::{ControlFamily, Severity};
    use crate::utils::compliance::scanner::ControlFinding;

    fn outcome(control_id: &str, status: ControlStatus, detail: &str) -> FindingOutcome {
        FindingOutcome {
            finding: ControlFinding {
                control_id: control_id.to_string(),
                family: ControlFamily::AccessControl,
                severity: Severity::High,
                title: "Example control".into(),
                status,
                detail: detail.to_string(),
            },
            waiver_id: None,
            effective_status: status,
        }
    }

    #[test]
    fn summary_counts_each_status_bucket() {
        let outcomes = vec![
            outcome("A", ControlStatus::Pass, "ok"),
            outcome("B", ControlStatus::Fail, "bad"),
            outcome("C", ControlStatus::Waived, "waived"),
            outcome("D", ControlStatus::NeedsEvidence, "pending"),
            outcome("E", ControlStatus::NotApplicable, "n/a"),
        ];
        let summary = ReportSummary::from_outcomes(&outcomes);
        assert_eq!(summary.pass, 1);
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.waived, 1);
        assert_eq!(summary.needs_evidence, 1);
        assert_eq!(summary.not_applicable, 1);
    }

    #[test]
    fn clean_report_has_no_fail_or_needs_evidence() {
        let clean = ReportSummary::from_outcomes(&[outcome("A", ControlStatus::Pass, "ok")]);
        assert!(clean.is_clean());

        let unclean = ReportSummary::from_outcomes(&[outcome("A", ControlStatus::Fail, "bad")]);
        assert!(!unclean.is_clean());
    }

    #[test]
    fn json_export_redacts_secret_shaped_tokens() {
        let secret = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        let outcomes = vec![outcome(
            "AC-1",
            ControlStatus::Fail,
            &format!("Found leaked key {secret} in evidence notes"),
        )];
        let report = ComplianceReport::new(vec!["global-baseline".into()], outcomes);
        let json = report.to_json_redacted().unwrap();
        assert!(!json.contains(secret));
        assert!(json.contains("[REDACTED]"));
    }

    #[test]
    fn human_render_redacts_ai_explanations_too() {
        let secret = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        let outcomes = vec![outcome("AC-1", ControlStatus::Fail, "no auth check")];
        let mut report = ComplianceReport::new(vec!["global-baseline".into()], outcomes);
        report
            .ai_explanations
            .insert("AC-1".into(), format!("Rotate key {secret} immediately"));

        let rendered = report.render_human();
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("AI-assisted explanation"));
    }

    #[test]
    fn human_render_reports_not_clean_when_failing() {
        let outcomes = vec![outcome("AC-1", ControlStatus::Fail, "bad")];
        let report = ComplianceReport::new(vec!["global-baseline".into()], outcomes);
        assert!(report.render_human().contains("NOT CLEAN"));
    }

    #[test]
    fn human_render_reports_clean_when_all_pass() {
        let outcomes = vec![outcome("AC-1", ControlStatus::Pass, "ok")];
        let report = ComplianceReport::new(vec!["global-baseline".into()], outcomes);
        assert!(report.render_human().contains("Result: CLEAN"));
    }

    #[test]
    fn markdown_render_redacts_and_includes_table() {
        let secret = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        let outcomes = vec![outcome(
            "AC-1",
            ControlStatus::Fail,
            &format!("leaked {secret}"),
        )];
        let report = ComplianceReport::new(vec!["global-baseline".into()], outcomes);
        let md = report.render_markdown();
        assert!(!md.contains(secret));
        assert!(md.contains("| Control | Status"));
        assert!(md.contains("NOT CLEAN"));
    }

    #[test]
    fn json_round_trips_through_serde() {
        let outcomes = vec![outcome("AC-1", ControlStatus::Pass, "ok")];
        let report = ComplianceReport::new(vec!["global-baseline".into()], outcomes);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, report.schema_version);
        assert_eq!(parsed.summary, report.summary);
    }
}
