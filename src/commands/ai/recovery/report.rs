//! Recovery report builder for the AI disaster-recovery subsystem.

use anyhow::Result;
use chrono::Utc;

use super::model::{RecoveryPlan, RecoveryReport, Recommendation, VerifyResult};
use crate::commands::ai::impact::redactor::redact_text;

/// Build a [`RecoveryReport`] from a plan, optional verify results, and an
/// optional AI narrative string.  Recommendations are derived from
/// `plan.risk_factors` and sorted by priority descending.
pub fn build(
    plan: &RecoveryPlan,
    verify: Option<&[VerifyResult]>,
    ai_narrative: Option<&str>,
) -> RecoveryReport {
    let mut recommendations: Vec<Recommendation> = plan
        .risk_factors
        .iter()
        .map(|f| Recommendation {
            priority: f.points,
            description: redact_text(&f.description),
            action: action_for_factor(&f.description),
        })
        .collect();
    recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));

    RecoveryReport {
        schema_version: 1,
        generated_at: Utc::now(),
        plan: plan.clone(),
        verify_summary: verify.map(|v| v.to_vec()),
        recommendations,
        ai_narrative: ai_narrative.map(|n| redact_text(n)),
    }
}

/// Render a [`RecoveryReport`] as a Markdown string.
pub fn to_markdown(report: &RecoveryReport) -> String {
    let mut out = String::new();
    out.push_str("# StarForge Recovery Report\n\n");
    out.push_str(&format!("Generated: {}\n\n", report.generated_at.to_rfc3339()));
    out.push_str(&format!(
        "## Risk Assessment\n\n- **Risk Score**: {}\n- **Risk Level**: {}\n\n",
        report.plan.risk_score,
        report.plan.risk_level.as_str()
    ));

    if !report.plan.risk_factors.is_empty() {
        out.push_str("### Risk Factors\n\n");
        for f in &report.plan.risk_factors {
            out.push_str(&format!("- {} (+{} pts)\n", f.description, f.points));
        }
        out.push('\n');
    }

    out.push_str("## Artifacts\n\n");
    out.push_str(&format!(
        "Total discovered: {}\n\n",
        report.plan.artifacts.len()
    ));

    if !report.recommendations.is_empty() {
        out.push_str("## Recommendations\n\n");
        for (i, r) in report.recommendations.iter().enumerate() {
            out.push_str(&format!(
                "{}. **{}** (priority: {})\n   → {}\n\n",
                i + 1,
                r.description,
                r.priority,
                r.action
            ));
        }
    }

    if let Some(ref narrative) = report.ai_narrative {
        out.push_str("## AI Analysis\n\n");
        out.push_str(narrative);
        out.push('\n');
    }

    out
}

/// Serialize a [`RecoveryReport`] to a JSON string.
pub fn to_json(report: &RecoveryReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn action_for_factor(description: &str) -> String {
    let d = description.to_lowercase();
    if d.contains("missing wasm") {
        "Re-deploy or restore the missing WASM binary from a previous backup.".to_string()
    } else if d.contains("missing deploy manifest") || d.contains("missing manifest") {
        "Restore the deploy manifest from version control or a previous backup.".to_string()
    } else if d.contains("stale digest") {
        "Re-run `starforge ai recovery backup` to capture the current artifact state.".to_string()
    } else if d.contains("key reference") {
        "Remove key material from artifact paths and store keys in a secure vault.".to_string()
    } else if d.contains("backup") && d.contains("cadence") {
        "Run `starforge ai recovery backup` now to bring backups within cadence.".to_string()
    } else {
        "Review the risk factor and take corrective action.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ai::recovery::model::{RiskFactor, RiskLevel};
    use chrono::Utc;

    fn make_plan(factors: Vec<RiskFactor>) -> RecoveryPlan {
        let risk_score: u8 = factors.iter().map(|f| f.points).sum::<u8>().min(100);
        let risk_level = RiskLevel::from_score(risk_score);
        RecoveryPlan {
            schema_version: 1,
            generated_at: Utc::now(),
            network: "testnet".to_string(),
            artifacts: vec![],
            risk_score,
            risk_level,
            risk_factors: factors,
            ai_narrative: None,
        }
    }

    #[test]
    fn recommendations_sorted_by_priority_descending() {
        let plan = make_plan(vec![
            RiskFactor { description: "stale digest mismatch".to_string(), points: 20 },
            RiskFactor { description: "missing WASM binary".to_string(), points: 30 },
            RiskFactor { description: "no backup in cadence".to_string(), points: 10 },
        ]);
        let report = build(&plan, None, None);
        let priorities: Vec<u8> = report.recommendations.iter().map(|r| r.priority).collect();
        assert_eq!(priorities, vec![30, 20, 10]);
    }

    #[test]
    fn ai_narrative_with_secret_is_redacted() {
        let plan = make_plan(vec![]);
        let secret = "SAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGG";
        let narrative = format!("Key is {}", secret);
        let report = build(&plan, None, Some(&narrative));
        let stored = report.ai_narrative.unwrap();
        assert!(!stored.contains(secret), "secret must be redacted in narrative");
    }

    #[test]
    fn to_json_contains_schema_version_1() {
        let plan = make_plan(vec![]);
        let report = build(&plan, None, None);
        let json = to_json(&report).unwrap();
        assert!(json.contains("\"schema_version\": 1"));
    }

    #[test]
    fn to_markdown_contains_risk_level() {
        let plan = make_plan(vec![
            RiskFactor { description: "missing WASM binary".to_string(), points: 30 },
        ]);
        let report = build(&plan, None, None);
        let md = to_markdown(&report);
        assert!(md.contains("Risk Level"));
    }
}
