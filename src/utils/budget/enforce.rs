//! Pure enforcement logic: compares [`BudgetMetrics`] against a
//! [`ResolvedPolicy`] and produces an [`EnforcementReport`].
//!
//! This module has no I/O — it does not load policies, write audit records,
//! or print anything. [`crate::utils::budget::gate`] is the thin,
//! side-effecting wrapper that command handlers call; keeping the decision
//! logic here pure is what makes it exhaustively unit-testable without
//! touching the filesystem.

use super::metrics::{BudgetMetrics, MetricKind};
use super::policy::{ResolvedPolicy, Scope};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Warning,
    Violation,
}

/// The outcome of checking a single metric against its resolved limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricCheck {
    pub metric: MetricKind,
    pub actual: u64,
    pub limit: u64,
    /// `actual / limit`, as a percentage. Not emitted when `limit == 0`
    /// (nothing to divide by; any positive actual is already a violation).
    pub ratio_percent: f64,
    pub severity: Severity,
}

/// Overall pre-signing decision for one enforcement run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// No configured limit was exceeded or approached.
    Allow,
    /// At least one metric crossed its warning threshold, but none exceeded
    /// its hard limit. The operation proceeds; the warning is surfaced.
    Warn,
    /// At least one metric exceeded its hard limit and no valid override was
    /// supplied. Callers must not proceed.
    Block,
    /// At least one metric exceeded its hard limit, but a non-empty override
    /// reason was supplied, so the operation is allowed to proceed. The
    /// override is always audit-logged by [`super::gate`].
    OverrideAllowed,
}

impl Decision {
    pub fn blocks(&self) -> bool {
        matches!(self, Decision::Block)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub schema_version: u8,
    pub command: String,
    pub network: String,
    pub contract: Option<String>,
    pub function: Option<String>,
    pub metrics: BudgetMetrics,
    pub warning_threshold_percent: f64,
    pub policy_layers: Vec<String>,
    /// Every metric that had a configured limit, whether it passed or not.
    pub checks: Vec<MetricCheck>,
    pub decision: Decision,
    pub override_reason: Option<String>,
}

pub const ENFORCEMENT_REPORT_SCHEMA_VERSION: u8 = 1;

impl EnforcementReport {
    pub fn violations(&self) -> Vec<&MetricCheck> {
        self.checks
            .iter()
            .filter(|c| c.severity == Severity::Violation)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&MetricCheck> {
        self.checks
            .iter()
            .filter(|c| c.severity == Severity::Warning)
            .collect()
    }

    /// A plain-text (uncolored) multi-line explanation of every violation,
    /// suitable for an `anyhow::bail!` message. Callers that want colored
    /// terminal rendering should format `checks` themselves instead of using
    /// this — it exists so a `Decision::Block` failure is self-explanatory
    /// even when captured by CI log scraping rather than a human terminal.
    pub fn block_message(&self) -> String {
        let mut lines = vec![format!(
            "Budget check failed for '{}' on {}: {} metric(s) exceeded their configured limit.",
            self.command,
            self.network,
            self.violations().len()
        )];
        for check in self.violations() {
            lines.push(format!(
                "  - {}: {} exceeds limit {} ({:.1}% of limit)",
                check.metric.label(),
                check.actual,
                check.limit,
                check.ratio_percent
            ));
        }
        lines.push(
            "Re-run with --budget-override-reason \"<why this is acceptable>\" to proceed \
             (the override will be recorded in the budget audit log)."
                .to_string(),
        );
        lines.join("\n")
    }
}

/// Evaluates `metrics` against `resolved` for the given `scope`, without any
/// override applied yet. This is the pure comparison step; [`decide`] turns
/// the resulting checks plus an optional override reason into a [`Decision`].
pub fn evaluate(
    scope: &Scope,
    metrics: BudgetMetrics,
    resolved: &ResolvedPolicy,
) -> EnforcementReport {
    let mut checks = Vec::new();

    for kind in MetricKind::ALL {
        let Some(limit) = resolved.limits.limit_of(kind) else {
            continue;
        };
        let actual = metrics.value_of(kind);
        let ratio_percent = if limit == 0 {
            if actual == 0 {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            (actual as f64 / limit as f64) * 100.0
        };

        let severity = if actual > limit {
            Some(Severity::Violation)
        } else if ratio_percent >= resolved.warning_threshold_percent {
            Some(Severity::Warning)
        } else {
            None
        };

        if let Some(severity) = severity {
            checks.push(MetricCheck {
                metric: kind,
                actual,
                limit,
                ratio_percent,
                severity,
            });
        }
    }

    let decision = if checks.iter().any(|c| c.severity == Severity::Violation) {
        Decision::Block
    } else if !checks.is_empty() {
        Decision::Warn
    } else {
        Decision::Allow
    };

    EnforcementReport {
        schema_version: ENFORCEMENT_REPORT_SCHEMA_VERSION,
        command: scope.command.to_string(),
        network: scope.network.to_string(),
        contract: scope.contract.map(str::to_string),
        function: scope.function.map(str::to_string),
        metrics,
        warning_threshold_percent: resolved.warning_threshold_percent,
        policy_layers: resolved.contributing_layers.clone(),
        checks,
        decision,
        override_reason: None,
    }
}

/// Minimum length (in characters) an override reason must have to be
/// accepted. This is not meant to be a strong content check — it exists so
/// `--budget-override-reason x` can't be used to rubber-stamp past a
/// violation without leaving a reason a human could later act on in the
/// audit log.
pub const MIN_OVERRIDE_REASON_LEN: usize = 8;

/// Applies an optional override reason to an already-[`evaluate`]d report,
/// upgrading `Block` to `OverrideAllowed` when the reason is non-trivial.
/// Reports that were already `Allow`/`Warn` are returned unchanged (there is
/// nothing to override), except that a supplied reason is still recorded for
/// audit-trail completeness.
pub fn apply_override(
    mut report: EnforcementReport,
    override_reason: Option<&str>,
) -> Result<EnforcementReport, String> {
    let trimmed = override_reason.map(str::trim).filter(|s| !s.is_empty());

    if report.decision == Decision::Block {
        match trimmed {
            Some(reason) if reason.chars().count() >= MIN_OVERRIDE_REASON_LEN => {
                report.decision = Decision::OverrideAllowed;
                report.override_reason = Some(reason.to_string());
            }
            Some(_) => {
                return Err(format!(
                    "Override reason must be at least {} characters long and explain why this \
                     budget violation is acceptable",
                    MIN_OVERRIDE_REASON_LEN
                ));
            }
            None => { /* no override supplied; stays Block */ }
        }
    } else if let Some(reason) = trimmed {
        report.override_reason = Some(reason.to_string());
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::budget::policy::LimitSet;

    fn resolved(limits: LimitSet) -> ResolvedPolicy {
        ResolvedPolicy {
            warning_threshold_percent: 80.0,
            contributing_layers: vec!["global".to_string()],
            limits,
        }
    }

    #[test]
    fn no_limits_configured_allows() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(999, 999, 999, 999, 99, 99, 999, 999, 999, 999);
        let report = evaluate(&scope, metrics, &resolved(LimitSet::default()));
        assert_eq!(report.decision, Decision::Allow);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn under_threshold_allows() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(100, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        assert_eq!(report.decision, Decision::Allow);
    }

    #[test]
    fn near_threshold_warns_without_blocking() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(850, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        assert_eq!(report.decision, Decision::Warn);
        assert_eq!(report.warnings().len(), 1);
        assert!(report.violations().is_empty());
    }

    #[test]
    fn over_limit_blocks() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(1_500, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        assert_eq!(report.decision, Decision::Block);
        assert_eq!(report.violations().len(), 1);
    }

    #[test]
    fn zero_limit_treats_any_positive_actual_as_violation() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(0, 0, 0, 0, 0, 0, 0, 0, 1, 0);
        let limits = LimitSet {
            max_event_bytes: Some(0),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        assert_eq!(report.decision, Decision::Block);
    }

    #[test]
    fn zero_limit_and_zero_actual_passes() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_event_bytes: Some(0),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        assert_eq!(report.decision, Decision::Allow);
    }

    #[test]
    fn override_with_valid_reason_unblocks() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(1_500, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        let overridden = apply_override(report, Some("approved by ops for hotfix")).unwrap();
        assert_eq!(overridden.decision, Decision::OverrideAllowed);
        assert_eq!(
            overridden.override_reason.as_deref(),
            Some("approved by ops for hotfix")
        );
    }

    #[test]
    fn override_with_too_short_reason_is_rejected() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(1_500, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        let err = apply_override(report, Some("nah")).unwrap_err();
        assert!(err.contains("at least"));
    }

    #[test]
    fn override_without_a_violation_is_a_no_op_decision_but_recorded() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(10, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        let overridden = apply_override(report, Some("just in case, noted")).unwrap();
        assert_eq!(overridden.decision, Decision::Allow);
        assert!(overridden.override_reason.is_some());
    }

    #[test]
    fn blank_override_reason_leaves_block_in_place() {
        let scope = Scope::new("invoke", "testnet");
        let metrics = BudgetMetrics::from_parts(1_500, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        let overridden = apply_override(report, Some("   ")).unwrap();
        assert_eq!(overridden.decision, Decision::Block);
    }

    #[test]
    fn multiple_violations_are_all_reported() {
        let scope = Scope::new("deploy", "mainnet");
        let metrics = BudgetMetrics::from_parts(2_000, 2_000, 0, 0, 0, 0, 0, 0, 0, 0);
        let limits = LimitSet {
            max_classic_fee_stroops: Some(1_000),
            max_resource_fee_stroops: Some(1_000),
            ..Default::default()
        };
        let report = evaluate(&scope, metrics, &resolved(limits));
        assert_eq!(report.violations().len(), 2);
        assert_eq!(report.decision, Decision::Block);
    }
}
