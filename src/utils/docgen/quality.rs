//! Documentation-quality assessment with CI-friendly gates.
//!
//! [`assess`] produces a deterministic report of issues plus a coverage
//! metric; the CLI turns a failing report into a non-zero exit code so
//! documentation regressions can block merges exactly like lint failures.

use crate::utils::docgen::model::KnowledgeBase;
use serde::{Deserialize, Serialize};

pub const QUALITY_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityIssue {
    pub severity: Severity,
    /// Stable machine-readable code, e.g. `missing_function_doc`.
    pub code: String,
    /// Stable entry ID the issue applies to.
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityReport {
    pub schema_version: String,
    pub coverage_percent: f64,
    pub documented_functions: usize,
    pub total_functions: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub passed: bool,
    pub issues: Vec<QualityIssue>,
}

/// Which documentation rules are enforced. Errors fail the gate; warnings do
/// not unless promoted by the policy.
#[derive(Debug, Clone, PartialEq)]
pub struct QualityPolicy {
    /// Minimum share of documented public functions, in percent (0–100).
    pub min_coverage_percent: f64,
    /// Promote missing function docs from warnings to errors.
    pub require_function_docs: bool,
    /// Promote missing error-case docs to errors.
    pub require_error_case_docs: bool,
    /// Promote missing parameter docs to errors.
    pub require_param_docs: bool,
}

impl Default for QualityPolicy {
    fn default() -> Self {
        QualityPolicy {
            min_coverage_percent: 0.0,
            require_function_docs: false,
            require_error_case_docs: false,
            require_param_docs: false,
        }
    }
}

impl QualityPolicy {
    /// True when any gate is active; used to keep default runs advisory.
    pub fn has_gates(&self) -> bool {
        *self != QualityPolicy::default()
    }
}

/// Assesses documentation quality of a knowledge base against `policy`.
pub fn assess(kb: &KnowledgeBase, policy: &QualityPolicy) -> QualityReport {
    let mut issues = Vec::new();

    for f in &kb.functions {
        if f.doc.as_deref().is_none_or(|d| d.trim().is_empty()) {
            issues.push(QualityIssue {
                severity: if policy.require_function_docs {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                code: "missing_function_doc".to_string(),
                subject: f.id.clone(),
                message: format!("Public function `{}` has no doc comment", f.name),
            });
        }
        for p in &f.params {
            if p.doc.as_deref().is_none_or(|d| d.trim().is_empty()) {
                issues.push(QualityIssue {
                    severity: if policy.require_param_docs {
                        Severity::Error
                    } else {
                        Severity::Warning
                    },
                    code: "missing_param_doc".to_string(),
                    subject: f.id.clone(),
                    message: format!("Parameter `{}` of `{}` has no doc comment", p.name, f.name),
                });
            }
        }
    }

    for e in &kb.errors {
        for case in &e.cases {
            if case.doc.as_deref().is_none_or(|d| d.trim().is_empty()) {
                issues.push(QualityIssue {
                    severity: if policy.require_error_case_docs {
                        Severity::Error
                    } else {
                        Severity::Warning
                    },
                    code: "missing_error_case_doc".to_string(),
                    subject: case.id.clone(),
                    message: format!("Error case `{}::{}` has no doc comment", e.name, case.name),
                });
            }
        }
    }

    issues.sort_by(|a, b| {
        a.subject
            .cmp(&b.subject)
            .then(a.code.cmp(&b.code))
            .then(a.message.cmp(&b.message))
    });

    let total_functions = kb.summary.functions;
    let documented_functions = kb.summary.documented_functions;
    let coverage_percent = if total_functions == 0 {
        100.0
    } else {
        (documented_functions as f64 / total_functions as f64) * 100.0
    };

    if coverage_percent + f64::EPSILON < policy.min_coverage_percent {
        issues.push(QualityIssue {
            severity: Severity::Error,
            code: "coverage_below_minimum".to_string(),
            subject: "kb".to_string(),
            message: format!(
                "Documentation coverage {:.1}% is below the required minimum {:.1}%",
                coverage_percent, policy.min_coverage_percent
            ),
        });
    }

    let error_count = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count();
    let warning_count = issues.len() - error_count;

    QualityReport {
        schema_version: QUALITY_SCHEMA_VERSION.to_string(),
        coverage_percent,
        documented_functions,
        total_functions,
        error_count,
        warning_count,
        passed: error_count == 0,
        issues,
    }
}

impl QualityReport {
    /// Renders the report as deterministic Markdown.
    pub fn to_markdown(&self) -> String {
        let mut md = String::from("# Documentation Quality Report\n\n");
        md.push_str(&format!(
            "- Coverage: **{:.1}%** ({} of {} functions documented)\n",
            self.coverage_percent, self.documented_functions, self.total_functions
        ));
        md.push_str(&format!("- Errors: {}\n", self.error_count));
        md.push_str(&format!(
            "- Warnings: {}\n- Gate: {}\n\n",
            self.warning_count,
            if self.passed { "PASSED" } else { "FAILED" }
        ));

        if self.issues.is_empty() {
            md.push_str("No documentation issues found.\n");
            return md;
        }

        md.push_str("| Severity | Code | Subject | Message |\n|---|---|---|---|\n");
        for issue in &self.issues {
            md.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                issue.severity.as_str(),
                issue.code,
                issue.subject,
                issue.message.replace('|', "\\|")
            ));
        }
        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::docgen::extract::{build_kb, ExtractOptions};
    use crate::utils::docgen::fixtures::{build_spec_wasm, sample_entries};
    use std::path::Path;

    fn sample_kb() -> KnowledgeBase {
        build_kb(
            Path::new("token.wasm"),
            &build_spec_wasm(&sample_entries()),
            &ExtractOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn default_policy_reports_warnings_only_and_passes() {
        // The fixture leaves one error case and several params undocumented.
        let report = assess(&sample_kb(), &QualityPolicy::default());
        assert!(report.passed);
        assert!(report.warning_count > 0);
        assert_eq!(report.error_count, 0);
        assert!(report.total_functions == 2 && report.documented_functions == 2);
        assert!((report.coverage_percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn strict_policy_fails_on_undocumented_case() {
        let policy = QualityPolicy {
            require_function_docs: true,
            require_error_case_docs: true,
            require_param_docs: true,
            ..Default::default()
        };
        let report = assess(&sample_kb(), &policy);
        assert!(!report.passed);
        assert!(report.error_count > 0);
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "missing_error_case_doc" && i.subject.contains("Unauthorized")));
        assert!(report.to_markdown().contains("FAILED"));
    }

    #[test]
    fn coverage_gate_blocks_low_documentation() {
        let policy = QualityPolicy {
            min_coverage_percent: 50.0,
            ..Default::default()
        };
        // Strip all function docs to force 0% coverage.
        let mut kb = sample_kb();
        for f in &mut kb.functions {
            f.doc = None;
        }
        kb.finalize();
        let report = assess(&kb, &policy);
        assert!(!report.passed);
        assert_eq!(report.coverage_percent, 0.0);
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "coverage_below_minimum"));
    }

    #[test]
    fn empty_contract_counts_as_full_coverage() {
        let kb = build_kb(
            Path::new("empty.wasm"),
            &build_spec_wasm(&[]),
            &ExtractOptions::default(),
        )
        .unwrap();
        let report = assess(&kb, &QualityPolicy::default());
        assert_eq!(report.coverage_percent, 100.0);
        assert!(report.passed);
    }

    #[test]
    fn report_is_deterministic() {
        let kb = sample_kb();
        let policy = QualityPolicy {
            require_param_docs: true,
            ..Default::default()
        };
        assert_eq!(assess(&kb, &policy), assess(&kb, &policy));
    }
}
