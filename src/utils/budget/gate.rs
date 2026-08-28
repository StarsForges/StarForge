//! The single side-effecting entry point every fee/resource-emitting command
//! path calls before signing: [`gate`] loads the resolved policy, evaluates
//! metrics against it, applies an optional override, and appends an audit
//! record — then hands back a plain [`EnforcementReport`] for the caller to
//! render and (if blocked) turn into a command failure.
//!
//! Deliberately thin: policy loading is [`super::policy`], the comparison is
//! [`super::enforce`], persistence is [`super::audit`]. This module only
//! wires them together in the order pre-signing enforcement needs, so it has
//! no rendering and no network access of its own — it can be exercised in
//! tests purely through environment variables and a temp `HOME`.

use super::audit::AuditRecord;
use super::enforce::{self, Decision, EnforcementReport};
use super::metrics::BudgetMetrics;
use super::policy::{self, Scope};
use anyhow::Result;
use std::path::Path;

/// Everything a call site needs to run a pre-signing budget check for one
/// operation. `override_reason` should be the raw value of a
/// `--budget-override-reason` flag (or `None` if not supplied); it is only
/// consulted when the metrics actually violate a hard limit.
pub struct GateRequest<'a> {
    pub command: &'a str,
    pub network: &'a str,
    pub contract: Option<&'a str>,
    pub function: Option<&'a str>,
    pub metrics: BudgetMetrics,
    pub override_reason: Option<&'a str>,
    /// Explicit policy file path, bypassing `STARFORGE_BUDGET_POLICY` and the
    /// default location. `starforge budget check --policy <path>` uses this;
    /// integrated command paths (deploy/invoke/batch/tx) leave it `None`.
    pub policy_path: Option<&'a Path>,
}

/// Runs the pre-signing budget check described by `req`.
///
/// Returns `Ok(report)` in every case except a genuine I/O/parse failure
/// loading the policy or an override reason that fails validation — a
/// `Block` decision without an override is still `Ok`, with
/// `report.decision.blocks() == true`; callers decide whether that should
/// fail the command (every integrated command path does).
///
/// When no policy has been initialized yet (`starforge budget init` was
/// never run), this is a silent no-op: it returns `Decision::Allow` with no
/// checks and writes nothing to the audit log, so budgets stay strictly
/// opt-in and impose no behavior change on users who don't use them.
pub fn gate(req: GateRequest) -> Result<EnforcementReport> {
    let policy_path = policy::resolve_policy_path(req.policy_path)?;
    let Some(document) = policy::load_policy_if_present(&policy_path)? else {
        return Ok(allow_report(&req));
    };

    let scope = Scope {
        command: req.command,
        network: req.network,
        contract: req.contract,
        function: req.function,
    };
    let resolved = document.resolve(&scope);
    let report = enforce::evaluate(&scope, req.metrics, &resolved);
    let report =
        enforce::apply_override(report, req.override_reason).map_err(|e| anyhow::anyhow!(e))?;

    super::audit::append_record(&AuditRecord::from_report(&report))?;

    Ok(report)
}

fn allow_report(req: &GateRequest) -> EnforcementReport {
    EnforcementReport {
        schema_version: enforce::ENFORCEMENT_REPORT_SCHEMA_VERSION,
        command: req.command.to_string(),
        network: req.network.to_string(),
        contract: req.contract.map(str::to_string),
        function: req.function.map(str::to_string),
        metrics: req.metrics,
        warning_threshold_percent: policy::DEFAULT_WARNING_THRESHOLD_PERCENT,
        policy_layers: Vec::new(),
        checks: Vec::new(),
        decision: Decision::Allow,
        override_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::budget::policy::{BudgetPolicyDocument, LimitSet};
    use std::sync::Mutex;
    use tempfile::tempdir;

    // `gate()` reads config::get_data_dir(), which honors $HOME; serialize
    // these tests so they don't race on process-wide env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_isolated_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let home = tempdir().unwrap();
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", home.path());
        std::env::remove_var("STARFORGE_BUDGET_POLICY");
        let result = f();
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        result
    }

    #[test]
    fn no_policy_configured_allows_silently_and_does_not_audit() {
        with_isolated_home(|| {
            let metrics = BudgetMetrics::classic_only(u64::MAX);
            let report = gate(GateRequest {
                command: "invoke",
                network: "testnet",
                contract: None,
                function: None,
                metrics,
                override_reason: None,
                policy_path: None,
            })
            .unwrap();
            assert_eq!(report.decision, Decision::Allow);

            let audit_path = super::super::audit::default_audit_log_path().unwrap();
            assert!(!audit_path.exists());
        });
    }

    #[test]
    fn violation_without_override_blocks_and_is_audited() {
        with_isolated_home(|| {
            let policy_path = policy::default_policy_path().unwrap();
            let mut doc = BudgetPolicyDocument::new("test");
            doc.global.max_classic_fee_stroops = Some(100);
            policy::save_policy(&policy_path, &doc).unwrap();

            let report = gate(GateRequest {
                command: "deploy",
                network: "testnet",
                contract: None,
                function: None,
                metrics: BudgetMetrics::classic_only(1_000),
                override_reason: None,
                policy_path: None,
            })
            .unwrap();
            assert_eq!(report.decision, Decision::Block);

            let records = super::super::audit::read_records().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].decision, Decision::Block);
        });
    }

    #[test]
    fn violation_with_valid_override_is_allowed_and_audited_with_reason() {
        with_isolated_home(|| {
            let policy_path = policy::default_policy_path().unwrap();
            let mut doc = BudgetPolicyDocument::new("test");
            doc.global.max_classic_fee_stroops = Some(100);
            policy::save_policy(&policy_path, &doc).unwrap();

            let report = gate(GateRequest {
                command: "deploy",
                network: "testnet",
                contract: None,
                function: None,
                metrics: BudgetMetrics::classic_only(1_000),
                override_reason: Some("hotfix approved by release manager"),
                policy_path: None,
            })
            .unwrap();
            assert_eq!(report.decision, Decision::OverrideAllowed);

            let records = super::super::audit::read_records().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].override_reason.as_deref(),
                Some("hotfix approved by release manager")
            );
        });
    }

    #[test]
    fn invalid_override_reason_errors_without_auditing() {
        with_isolated_home(|| {
            let policy_path = policy::default_policy_path().unwrap();
            let mut doc = BudgetPolicyDocument::new("test");
            doc.global.max_classic_fee_stroops = Some(100);
            policy::save_policy(&policy_path, &doc).unwrap();

            let result = gate(GateRequest {
                command: "deploy",
                network: "testnet",
                contract: None,
                function: None,
                metrics: BudgetMetrics::classic_only(1_000),
                override_reason: Some("no"),
                policy_path: None,
            });
            assert!(result.is_err());
            assert!(super::super::audit::read_records().unwrap().is_empty());
        });
    }

    #[test]
    fn contract_and_function_overrides_are_honored_through_the_gate() {
        with_isolated_home(|| {
            let policy_path = policy::default_policy_path().unwrap();
            let mut doc = BudgetPolicyDocument::new("test");
            doc.global.max_cpu_insns = Some(1_000_000);
            doc.functions.insert(
                "CABC::transfer".to_string(),
                LimitSet {
                    max_cpu_insns: Some(10),
                    ..Default::default()
                },
            );
            policy::save_policy(&policy_path, &doc).unwrap();

            let report = gate(GateRequest {
                command: "invoke",
                network: "testnet",
                contract: Some("CABC"),
                function: Some("transfer"),
                metrics: BudgetMetrics::from_parts(0, 0, 500, 0, 0, 0, 0, 0, 0, 0),
                override_reason: None,
                policy_path: None,
            })
            .unwrap();
            assert_eq!(report.decision, Decision::Block);
        });
    }
}
