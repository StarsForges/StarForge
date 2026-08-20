//! Deterministic evaluation of compliance controls against a contract
//! artifact and its deployment metadata.
//!
//! Every finding produced here is the sole source of truth for pass/fail
//! status. AI-assisted explanations (see [`super::ai_assist`]) are attached
//! afterwards and never change a finding's status.

use super::framework::{Control, ControlFamily, Severity};
use super::metadata::DeploymentMetadata;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use wasmparser::{Parser as WasmParser, Payload};

/// Personal-data-shaped keywords looked for in a wasm module's data section.
/// This is a coarse heuristic, not a guarantee — it exists to catch obvious
/// mistakes, not to replace a real privacy review.
const PII_KEYWORDS: &[&str] = &[
    "email",
    "ssn",
    "passport",
    "date_of_birth",
    "home_address",
    "phone_number",
];

/// Substrings looked for in exported function names to detect a pause /
/// emergency-stop entry point.
const PAUSE_EXPORT_HINTS: &[&str] = &["pause", "emergency_stop", "circuit_breaker"];

/// Facts extracted from a compiled Soroban `.wasm` artifact via static
/// inspection (no execution).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WasmFacts {
    pub has_require_auth_import: bool,
    pub export_names: Vec<String>,
    pub suspicious_data_strings: Vec<String>,
}

impl WasmFacts {
    pub fn has_pause_export(&self) -> bool {
        self.export_names.iter().any(|name| {
            let lower = name.to_lowercase();
            PAUSE_EXPORT_HINTS.iter().any(|hint| lower.contains(hint))
        })
    }
}

/// Statically inspects a compiled wasm module for the facts the scanner
/// needs. Never executes the module.
pub fn analyze_wasm(bytes: &[u8]) -> Result<WasmFacts> {
    let mut facts = WasmFacts::default();
    let parser = WasmParser::new(0);

    for payload in parser.parse_all(bytes) {
        match payload? {
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import?;
                    if import.name.contains("require_auth") {
                        facts.has_require_auth_import = true;
                    }
                }
            }
            Payload::ExportSection(section) => {
                for export in section {
                    let export = export?;
                    facts.export_names.push(export.name.to_string());
                }
            }
            Payload::DataSection(section) => {
                for data in section.into_iter().flatten() {
                    if let Ok(text) = std::str::from_utf8(data.data) {
                        let lower = text.to_lowercase();
                        for needle in PII_KEYWORDS {
                            if lower.contains(needle)
                                && !facts.suspicious_data_strings.contains(&needle.to_string())
                            {
                                facts.suspicious_data_strings.push(needle.to_string());
                            }
                        }
                    }
                }
            }
            Payload::End(_) => break,
            _ => {}
        }
    }

    Ok(facts)
}

/// Result of a single control's deterministic evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Pass,
    Fail,
    /// A waiver was applied and is currently active.
    Waived,
    /// Cannot be verified automatically; a human must supply evidence.
    NeedsEvidence,
    NotApplicable,
}

impl ControlStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ControlStatus::Pass => "pass",
            ControlStatus::Fail => "fail",
            ControlStatus::Waived => "waived",
            ControlStatus::NeedsEvidence => "needs-evidence",
            ControlStatus::NotApplicable => "not-applicable",
        }
    }
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The deterministic outcome of evaluating one control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFinding {
    pub control_id: String,
    pub family: ControlFamily,
    pub severity: Severity,
    pub title: String,
    pub status: ControlStatus,
    pub detail: String,
}

/// Context that isn't derived from the wasm artifact or metadata file, but
/// is still needed for a small number of controls (telemetry state, whether
/// recent evidence has been recorded). Kept separate so [`evaluate`] doesn't
/// need to know how to load config or evidence itself.
pub struct OperationalContext<'a> {
    pub telemetry_enabled: bool,
    /// Returns true if evidence has recently been recorded for the given control id.
    pub evidence_recent: &'a dyn Fn(&str) -> bool,
}

/// Evaluates every given control deterministically against the available
/// wasm facts and deployment metadata.
pub fn evaluate(
    controls: &[Control],
    wasm: Option<&WasmFacts>,
    metadata: &DeploymentMetadata,
    ctx: &OperationalContext,
) -> Vec<ControlFinding> {
    controls
        .iter()
        .map(|control| evaluate_one(control, wasm, metadata, ctx))
        .collect()
}

fn finding(control: &Control, status: ControlStatus, detail: impl Into<String>) -> ControlFinding {
    ControlFinding {
        control_id: control.id.clone(),
        family: control.family,
        severity: control.severity,
        title: control.title.clone(),
        status,
        detail: detail.into(),
    }
}

fn evaluate_one(
    control: &Control,
    wasm: Option<&WasmFacts>,
    metadata: &DeploymentMetadata,
    ctx: &OperationalContext,
) -> ControlFinding {
    match control.id.as_str() {
        "AC-1" => match wasm {
            None => finding(
                control,
                ControlStatus::NeedsEvidence,
                "No wasm artifact provided; require_auth() usage could not be verified automatically.",
            ),
            Some(facts) if facts.has_require_auth_import => {
                finding(control, ControlStatus::Pass, "require_auth import found in the wasm module.")
            }
            Some(_) => finding(
                control,
                ControlStatus::Fail,
                "No require_auth import found in the wasm module.",
            ),
        },
        "AC-2" => {
            if metadata.has_multi_party_signers() {
                finding(control, ControlStatus::Pass, "Signer threshold requires multiple independent signers.")
            } else {
                finding(
                    control,
                    ControlStatus::Fail,
                    "signer_threshold is unset or below 2, or fewer signers are configured than the threshold.",
                )
            }
        }
        "UG-1" => {
            if metadata.upgrade_authority_multisig {
                finding(control, ControlStatus::Pass, "upgrade_authority_multisig is set.")
            } else {
                finding(control, ControlStatus::Fail, "upgrade_authority_multisig is not set.")
            }
        }
        "UG-2" => match metadata.upgrade_timelock_seconds {
            Some(secs) if secs > 0 => finding(
                control,
                ControlStatus::Pass,
                format!("Upgrade timelock configured at {secs} seconds."),
            ),
            _ => finding(control, ControlStatus::Fail, "No upgrade timelock configured."),
        },
        "DP-1" => match wasm {
            None => finding(
                control,
                ControlStatus::NeedsEvidence,
                "No wasm artifact provided; on-chain data could not be scanned automatically.",
            ),
            Some(facts) if facts.suspicious_data_strings.is_empty() => {
                finding(control, ControlStatus::Pass, "No personal-data-shaped strings found in the data section.")
            }
            Some(facts) => {
                if metadata.stores_personal_data && metadata.data_minimization_reviewed {
                    finding(
                        control,
                        ControlStatus::Waived,
                        format!(
                            "Personal-data-shaped strings found ({}), but stores_personal_data and data_minimization_reviewed are both acknowledged.",
                            facts.suspicious_data_strings.join(", ")
                        ),
                    )
                } else {
                    finding(
                        control,
                        ControlStatus::Fail,
                        format!(
                            "Personal-data-shaped strings found in the data section: {}.",
                            facts.suspicious_data_strings.join(", ")
                        ),
                    )
                }
            }
        },
        "DP-2" => {
            if !metadata.stores_personal_data {
                finding(control, ControlStatus::NotApplicable, "stores_personal_data is not set.")
            } else if metadata.data_minimization_reviewed {
                finding(control, ControlStatus::Pass, "data_minimization_reviewed is set.")
            } else {
                finding(
                    control,
                    ControlStatus::Fail,
                    "stores_personal_data is set but data_minimization_reviewed is not.",
                )
            }
        }
        "FC-1" => bool_finding(control, metadata.kyc_provider_integrated, "kyc_provider_integrated"),
        "FC-2" => bool_finding(control, metadata.sanctions_screening, "sanctions_screening"),
        "FC-3" => bool_finding(
            control,
            metadata.transfer_restrictions_documented,
            "transfer_restrictions_documented",
        ),
        "AT-1" => bool_finding_with(control, ctx.telemetry_enabled, "telemetry.enabled"),
        "AT-2" => {
            if (ctx.evidence_recent)(&control.id) {
                finding(control, ControlStatus::Pass, "Recent evidence is on file for this control.")
            } else {
                finding(
                    control,
                    ControlStatus::NeedsEvidence,
                    "No evidence recorded for this control within the last 90 days.",
                )
            }
        }
        "IR-1" => match wasm {
            None => finding(
                control,
                ControlStatus::NeedsEvidence,
                "No wasm artifact provided; pause mechanism could not be verified automatically.",
            ),
            Some(facts) if metadata.has_pause_mechanism && facts.has_pause_export() => {
                finding(control, ControlStatus::Pass, "A pause/emergency-stop export was found and acknowledged in metadata.")
            }
            Some(facts) if facts.has_pause_export() => finding(
                control,
                ControlStatus::NeedsEvidence,
                "A pause-shaped export was found, but has_pause_mechanism is not confirmed in metadata.",
            ),
            Some(_) => finding(
                control,
                ControlStatus::Fail,
                "No pause/emergency-stop export found in the wasm module.",
            ),
        },
        "IR-2" => option_finding(control, metadata.incident_response_contact.as_deref(), "incident_response_contact"),
        "DT-1" => option_finding(control, metadata.terms_of_service_url.as_deref(), "terms_of_service_url"),
        "DT-2" => option_finding(control, metadata.privacy_policy_url.as_deref(), "privacy_policy_url"),
        other => finding(
            control,
            ControlStatus::NeedsEvidence,
            format!("Control '{other}' has no built-in evaluation rule; supply evidence manually."),
        ),
    }
}

fn bool_finding(control: &Control, value: bool, field: &str) -> ControlFinding {
    if value {
        finding(control, ControlStatus::Pass, format!("{field} is set."))
    } else {
        finding(control, ControlStatus::Fail, format!("{field} is not set."))
    }
}

fn bool_finding_with(control: &Control, value: bool, field: &str) -> ControlFinding {
    if value {
        finding(control, ControlStatus::Pass, format!("{field} is enabled."))
    } else {
        finding(
            control,
            ControlStatus::Fail,
            format!("{field} is disabled."),
        )
    }
}

fn option_finding(control: &Control, value: Option<&str>, field: &str) -> ControlFinding {
    match value {
        Some(_) => finding(control, ControlStatus::Pass, format!("{field} is set.")),
        None => finding(control, ControlStatus::Fail, format!("{field} is not set.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::compliance::framework::built_in_controls;

    fn wasm_with(require_auth: bool, exports: &[&str], data_strings: &[&str]) -> WasmFacts {
        WasmFacts {
            has_require_auth_import: require_auth,
            export_names: exports.iter().map(|s| s.to_string()).collect(),
            suspicious_data_strings: data_strings.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ctx(telemetry_enabled: bool) -> OperationalContext<'static> {
        OperationalContext {
            telemetry_enabled,
            evidence_recent: &|_| false,
        }
    }

    fn control(id: &str) -> Control {
        built_in_controls()
            .into_iter()
            .find(|c| c.id == id)
            .unwrap()
    }

    #[test]
    fn analyze_wasm_detects_require_auth_import() {
        let wat = r#"
            (module
                (import "e" "require_auth" (func $ra (param i64)))
                (func (export "transfer"))
            )
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let facts = analyze_wasm(&bytes).unwrap();
        assert!(facts.has_require_auth_import);
        assert!(facts.export_names.contains(&"transfer".to_string()));
    }

    #[test]
    fn analyze_wasm_flags_pause_export() {
        let wat = r#"(module (func (export "emergency_pause")))"#;
        let bytes = wat::parse_str(wat).unwrap();
        let facts = analyze_wasm(&bytes).unwrap();
        assert!(facts.has_pause_export());
    }

    #[test]
    fn analyze_wasm_finds_pii_shaped_data_strings() {
        let wat = r#"(module (memory 1) (data (i32.const 0) "user email on file"))"#;
        let bytes = wat::parse_str(wat).unwrap();
        let facts = analyze_wasm(&bytes).unwrap();
        assert!(facts.suspicious_data_strings.contains(&"email".to_string()));
    }

    #[test]
    fn ac1_passes_with_require_auth_import() {
        let c = control("AC-1");
        let wasm = wasm_with(true, &[], &[]);
        let meta = DeploymentMetadata::default();
        let f = evaluate_one(&c, Some(&wasm), &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::Pass);
    }

    #[test]
    fn ac1_fails_without_require_auth_import() {
        let c = control("AC-1");
        let wasm = wasm_with(false, &[], &[]);
        let meta = DeploymentMetadata::default();
        let f = evaluate_one(&c, Some(&wasm), &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::Fail);
    }

    #[test]
    fn ac1_needs_evidence_without_wasm() {
        let c = control("AC-1");
        let meta = DeploymentMetadata::default();
        let f = evaluate_one(&c, None, &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::NeedsEvidence);
    }

    #[test]
    fn ac2_reflects_multi_party_signers() {
        let c = control("AC-2");
        let meta = DeploymentMetadata {
            signer_public_keys: vec!["G1".into(), "G2".into()],
            signer_threshold: Some(2),
            ..Default::default()
        };
        let f = evaluate_one(&c, None, &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::Pass);
    }

    #[test]
    fn dp1_waives_acknowledged_personal_data() {
        let c = control("DP-1");
        let wasm = wasm_with(false, &[], &["email"]);
        let meta = DeploymentMetadata {
            stores_personal_data: true,
            data_minimization_reviewed: true,
            ..Default::default()
        };
        let f = evaluate_one(&c, Some(&wasm), &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::Waived);
    }

    #[test]
    fn dp1_fails_unacknowledged_personal_data() {
        let c = control("DP-1");
        let wasm = wasm_with(false, &[], &["email"]);
        let meta = DeploymentMetadata::default();
        let f = evaluate_one(&c, Some(&wasm), &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::Fail);
    }

    #[test]
    fn dp2_not_applicable_when_no_personal_data() {
        let c = control("DP-2");
        let meta = DeploymentMetadata::default();
        let f = evaluate_one(&c, None, &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::NotApplicable);
    }

    #[test]
    fn at1_reflects_telemetry_flag() {
        let c = control("AT-1");
        let meta = DeploymentMetadata::default();
        assert_eq!(
            evaluate_one(&c, None, &meta, &ctx(true)).status,
            ControlStatus::Pass
        );
        assert_eq!(
            evaluate_one(&c, None, &meta, &ctx(false)).status,
            ControlStatus::Fail
        );
    }

    #[test]
    fn at2_uses_evidence_recent_callback() {
        let c = control("AT-2");
        let meta = DeploymentMetadata::default();
        let recent_ctx = OperationalContext {
            telemetry_enabled: false,
            evidence_recent: &|id| id == "AT-2",
        };
        assert_eq!(
            evaluate_one(&c, None, &meta, &recent_ctx).status,
            ControlStatus::Pass
        );
        assert_eq!(
            evaluate_one(&c, None, &meta, &ctx(false)).status,
            ControlStatus::NeedsEvidence
        );
    }

    #[test]
    fn ir1_passes_when_export_and_metadata_agree() {
        let c = control("IR-1");
        let wasm = wasm_with(false, &["emergency_pause"], &[]);
        let meta = DeploymentMetadata {
            has_pause_mechanism: true,
            ..Default::default()
        };
        let f = evaluate_one(&c, Some(&wasm), &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::Pass);
    }

    #[test]
    fn ir1_needs_evidence_when_export_found_but_unconfirmed() {
        let c = control("IR-1");
        let wasm = wasm_with(false, &["emergency_pause"], &[]);
        let meta = DeploymentMetadata::default();
        let f = evaluate_one(&c, Some(&wasm), &meta, &ctx(false));
        assert_eq!(f.status, ControlStatus::NeedsEvidence);
    }

    #[test]
    fn dt1_reflects_terms_of_service_url() {
        let c = control("DT-1");
        let meta = DeploymentMetadata {
            terms_of_service_url: Some("https://example.com/tos".into()),
            ..Default::default()
        };
        assert_eq!(
            evaluate_one(&c, None, &meta, &ctx(false)).status,
            ControlStatus::Pass
        );
    }

    #[test]
    fn evaluate_covers_every_built_in_control_without_panicking() {
        let controls = built_in_controls();
        let meta = DeploymentMetadata::default();
        let findings = evaluate(&controls, None, &meta, &ctx(false));
        assert_eq!(findings.len(), controls.len());
    }
}
