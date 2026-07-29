//! Static compatibility analysis for Soroban contract upgrades.
//!
//! Function specifications are part of Soroban's `contractspecv0` metadata and
//! are therefore treated as confirmed evidence. Storage schemas are not part of
//! the standard metadata. We can only infer likely keys from contract types
//! conventionally named `DataKey`/`StorageKey`; every such finding is marked as
//! heuristic so callers do not mistake it for full storage-layout recovery.

use crate::utils::bindings::{read_spec_entries, spec_type_name};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtUnionCaseV0};

pub const REPORT_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Breaking,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    Interface,
    Storage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub risk: Risk,
    pub confidence: Confidence,
    pub code: String,
    pub subject: String,
    pub message: String,
    pub current: Option<String>,
    pub candidate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub breaking: usize,
    pub warnings: usize,
    pub info: usize,
    pub safe_to_upgrade: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeReport {
    pub schema_version: String,
    pub current: Artifact,
    pub candidate: Artifact,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSpec {
    inputs: Vec<String>,
    outputs: Vec<String>,
}

impl FunctionSpec {
    fn display(&self) -> String {
        let output = match self.outputs.as_slice() {
            [] => "()".to_string(),
            [only] => only.clone(),
            many => format!("({})", many.join(", ")),
        };
        format!("({}) -> {}", self.inputs.join(", "), output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StorageKeySpec {
    shape: String,
}

pub fn analyze_paths(current: &Path, candidate: &Path) -> Result<UpgradeReport> {
    let current_wasm = fs::read(current)
        .with_context(|| format!("Failed to read current WASM {}", current.display()))?;
    let candidate_wasm = fs::read(candidate)
        .with_context(|| format!("Failed to read candidate WASM {}", candidate.display()))?;

    analyze_bytes(
        &current_wasm,
        current.display().to_string(),
        &candidate_wasm,
        candidate.display().to_string(),
    )
}

pub fn analyze_bytes(
    current_wasm: &[u8],
    current_path: String,
    candidate_wasm: &[u8],
    candidate_path: String,
) -> Result<UpgradeReport> {
    let current_entries = read_spec_entries(current_wasm)
        .with_context(|| format!("Could not inspect current contract ({current_path})"))?;
    let candidate_entries = read_spec_entries(candidate_wasm)
        .with_context(|| format!("Could not inspect candidate contract ({candidate_path})"))?;

    let mut findings = diff_interfaces(&current_entries, &candidate_entries);
    findings.extend(diff_storage(&current_entries, &candidate_entries));
    findings.sort_by(|a, b| {
        risk_order(a.risk)
            .cmp(&risk_order(b.risk))
            .then(a.category_string().cmp(b.category_string()))
            .then(a.subject.cmp(&b.subject))
    });

    let breaking = findings
        .iter()
        .filter(|finding| finding.risk == Risk::Breaking)
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.risk == Risk::Warning)
        .count();
    let info = findings
        .iter()
        .filter(|finding| finding.risk == Risk::Info)
        .count();

    Ok(UpgradeReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        current: Artifact {
            path: current_path,
            sha256: sha256(current_wasm),
        },
        candidate: Artifact {
            path: candidate_path,
            sha256: sha256(candidate_wasm),
        },
        summary: Summary {
            breaking,
            warnings,
            info,
            safe_to_upgrade: breaking == 0,
        },
        findings,
    })
}

impl Finding {
    fn category_string(&self) -> &'static str {
        match self.category {
            FindingCategory::Interface => "interface",
            FindingCategory::Storage => "storage",
        }
    }
}

fn risk_order(risk: Risk) -> u8 {
    match risk {
        Risk::Breaking => 0,
        Risk::Warning => 1,
        Risk::Info => 2,
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn interface(entries: &[ScSpecEntry]) -> BTreeMap<String, FunctionSpec> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            ScSpecEntry::FunctionV0(function) => Some((
                function.name.to_string(),
                FunctionSpec {
                    inputs: function
                        .inputs
                        .iter()
                        .map(|input| spec_type_name(&input.type_))
                        .collect(),
                    outputs: function.outputs.iter().map(spec_type_name).collect(),
                },
            )),
            _ => None,
        })
        .collect()
}

fn diff_interfaces(current: &[ScSpecEntry], candidate: &[ScSpecEntry]) -> Vec<Finding> {
    let current = interface(current);
    let candidate = interface(candidate);
    let names = current
        .keys()
        .chain(candidate.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();

    for name in names {
        match (current.get(&name), candidate.get(&name)) {
            (Some(old), None) => findings.push(Finding {
                category: FindingCategory::Interface,
                risk: Risk::Breaking,
                confidence: Confidence::Confirmed,
                code: "interface.function_removed".to_string(),
                subject: name.clone(),
                message: format!("Public function `{name}` was removed or renamed"),
                current: Some(old.display()),
                candidate: None,
            }),
            (None, Some(new)) => findings.push(Finding {
                category: FindingCategory::Interface,
                risk: Risk::Info,
                confidence: Confidence::Confirmed,
                code: "interface.function_added".to_string(),
                subject: name.clone(),
                message: format!("Public function `{name}` was added"),
                current: None,
                candidate: Some(new.display()),
            }),
            (Some(old), Some(new)) if old != new => findings.push(Finding {
                category: FindingCategory::Interface,
                risk: Risk::Breaking,
                confidence: Confidence::Confirmed,
                code: "interface.signature_changed".to_string(),
                subject: name.clone(),
                message: format!("Public function `{name}` changed its signature"),
                current: Some(old.display()),
                candidate: Some(new.display()),
            }),
            (Some(old), Some(_)) => findings.push(Finding {
                category: FindingCategory::Interface,
                risk: Risk::Info,
                confidence: Confidence::Confirmed,
                code: "interface.signature_unchanged".to_string(),
                subject: name.clone(),
                message: format!("Public function `{name}` is unchanged"),
                current: Some(old.display()),
                candidate: Some(old.display()),
            }),
            (None, None) => unreachable!(),
        }
    }
    findings
}

fn looks_like_storage_key_type(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(normalized.as_str(), "key" | "datakey" | "storagekey")
        || (normalized.contains("storage") && normalized.ends_with("key"))
}

fn storage_keys(entries: &[ScSpecEntry]) -> BTreeMap<String, StorageKeySpec> {
    let mut keys = BTreeMap::new();
    for entry in entries {
        match entry {
            ScSpecEntry::UdtUnionV0(union)
                if looks_like_storage_key_type(&union.name.to_string()) =>
            {
                let type_name = union.name.to_string();
                for case in union.cases.iter() {
                    let (name, shape) = match case {
                        ScSpecUdtUnionCaseV0::VoidV0(case) => {
                            (case.name.to_string(), "unit".to_string())
                        }
                        ScSpecUdtUnionCaseV0::TupleV0(case) => (
                            case.name.to_string(),
                            format!(
                                "({})",
                                case.type_
                                    .iter()
                                    .map(spec_type_name)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        ),
                    };
                    keys.insert(format!("{type_name}::{name}"), StorageKeySpec { shape });
                }
            }
            ScSpecEntry::UdtEnumV0(enumeration)
                if looks_like_storage_key_type(&enumeration.name.to_string()) =>
            {
                let type_name = enumeration.name.to_string();
                for case in enumeration.cases.iter() {
                    keys.insert(
                        format!("{type_name}::{}", case.name),
                        StorageKeySpec {
                            shape: format!("integer discriminant {}", case.value),
                        },
                    );
                }
            }
            ScSpecEntry::UdtStructV0(structure)
                if looks_like_storage_key_type(&structure.name.to_string()) =>
            {
                keys.insert(
                    structure.name.to_string(),
                    StorageKeySpec {
                        shape: format!(
                            "{{{}}}",
                            structure
                                .fields
                                .iter()
                                .map(|field| {
                                    format!("{}: {}", field.name, spec_type_name(&field.type_))
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    },
                );
            }
            _ => {}
        }
    }
    keys
}

fn diff_storage(current: &[ScSpecEntry], candidate: &[ScSpecEntry]) -> Vec<Finding> {
    let current = storage_keys(current);
    let candidate = storage_keys(candidate);
    let names = current
        .keys()
        .chain(candidate.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();

    for name in names {
        match (current.get(&name), candidate.get(&name)) {
            (Some(old), None) => findings.push(Finding {
                category: FindingCategory::Storage,
                risk: Risk::Breaking,
                confidence: Confidence::Heuristic,
                code: "storage.key_removed".to_string(),
                subject: name.clone(),
                message: format!(
                    "Likely storage key `{name}` was removed; verify all existing ledger entries manually"
                ),
                current: Some(old.shape.clone()),
                candidate: None,
            }),
            (None, Some(new)) => findings.push(Finding {
                category: FindingCategory::Storage,
                risk: Risk::Info,
                confidence: Confidence::Heuristic,
                code: "storage.key_added".to_string(),
                subject: name.clone(),
                message: format!("Likely storage key `{name}` was added"),
                current: None,
                candidate: Some(new.shape.clone()),
            }),
            (Some(old), Some(new)) if old != new => findings.push(Finding {
                category: FindingCategory::Storage,
                risk: Risk::Breaking,
                confidence: Confidence::Heuristic,
                code: "storage.key_shape_changed".to_string(),
                subject: name.clone(),
                message: format!(
                    "Likely storage key `{name}` changed shape; existing entries may become unreadable"
                ),
                current: Some(old.shape.clone()),
                candidate: Some(new.shape.clone()),
            }),
            _ => {}
        }
    }

    findings.push(Finding {
        category: FindingCategory::Storage,
        risk: Risk::Warning,
        confidence: Confidence::Heuristic,
        code: "storage.analysis_limited".to_string(),
        subject: "storage layout".to_string(),
        message: if current.is_empty() && candidate.is_empty() {
            "No conventional DataKey/StorageKey contract types were found. Standard Soroban metadata does not expose storage scopes or stored value types; verify the storage layout manually."
                .to_string()
        } else {
            "Keys were inferred from conventionally named contract types. Standard Soroban metadata does not confirm that they are used for storage, their durability scope, or their stored value types; verify these manually."
                .to_string()
        },
        current: None,
        candidate: None,
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        Limits, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtUnionCaseTupleV0,
        ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0, ScSymbol, StringM, VecM, WriteXdr,
    };

    fn function(name: &str, input: ScSpecTypeDef) -> ScSpecEntry {
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: StringM::default(),
            name: ScSymbol(StringM::try_from(name.as_bytes().to_vec()).unwrap()),
            inputs: VecM::try_from(vec![ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: StringM::try_from(b"value".to_vec()).unwrap(),
                type_: input,
            }])
            .unwrap(),
            outputs: VecM::try_from(vec![ScSpecTypeDef::Bool]).unwrap(),
        })
    }

    fn data_key(case_type: ScSpecTypeDef) -> ScSpecEntry {
        ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: StringM::try_from(b"DataKey".to_vec()).unwrap(),
            cases: VecM::try_from(vec![ScSpecUdtUnionCaseV0::TupleV0(
                ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: StringM::try_from(b"Balance".to_vec()).unwrap(),
                    type_: VecM::try_from(vec![case_type]).unwrap(),
                },
            )])
            .unwrap(),
        })
    }

    fn wasm_with_spec(entries: &[ScSpecEntry]) -> Vec<u8> {
        let mut spec = Vec::new();
        for entry in entries {
            spec.extend(entry.to_xdr(Limits::none()).unwrap());
        }

        let name = b"contractspecv0";
        let mut section = Vec::new();
        push_var_u32(&mut section, name.len() as u32);
        section.extend(name);
        section.extend(spec);

        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        wasm.push(0);
        push_var_u32(&mut wasm, section.len() as u32);
        wasm.extend(section);
        wasm
    }

    fn push_var_u32(output: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn additive_interface_change_has_no_breaking_findings() {
        let old = vec![function("set", ScSpecTypeDef::U32)];
        let new = vec![
            function("set", ScSpecTypeDef::U32),
            function("get", ScSpecTypeDef::U32),
        ];
        let findings = diff_interfaces(&old, &new);
        assert!(!findings.iter().any(|f| f.risk == Risk::Breaking));
        assert!(findings
            .iter()
            .any(|f| f.code == "interface.function_added" && f.subject == "get"));
    }

    #[test]
    fn changed_argument_type_is_breaking_and_names_function() {
        let old = vec![function("set", ScSpecTypeDef::U32)];
        let new = vec![function("set", ScSpecTypeDef::I64)];
        let finding = diff_interfaces(&old, &new)
            .into_iter()
            .find(|f| f.risk == Risk::Breaking)
            .unwrap();
        assert_eq!(finding.subject, "set");
        assert_eq!(finding.code, "interface.signature_changed");
        assert_eq!(finding.current.as_deref(), Some("(u32) -> bool"));
        assert_eq!(finding.candidate.as_deref(), Some("(i64) -> bool"));
    }

    #[test]
    fn paired_wasm_addition_is_safe_but_signature_change_is_not() {
        let current = wasm_with_spec(&[function("set", ScSpecTypeDef::U32)]);
        let additive = wasm_with_spec(&[
            function("set", ScSpecTypeDef::U32),
            function("get", ScSpecTypeDef::U32),
        ]);
        let breaking = wasm_with_spec(&[function("set", ScSpecTypeDef::I64)]);

        let additive_report = analyze_bytes(
            &current,
            "current.wasm".to_string(),
            &additive,
            "additive.wasm".to_string(),
        )
        .unwrap();
        assert!(additive_report.summary.safe_to_upgrade);
        assert_eq!(additive_report.summary.breaking, 0);

        let breaking_report = analyze_bytes(
            &current,
            "current.wasm".to_string(),
            &breaking,
            "breaking.wasm".to_string(),
        )
        .unwrap();
        assert!(!breaking_report.summary.safe_to_upgrade);
        assert_eq!(breaking_report.summary.breaking, 1);
        assert!(breaking_report.findings.iter().any(|finding| {
            finding.code == "interface.signature_changed" && finding.subject == "set"
        }));
    }

    #[test]
    fn storage_key_shape_change_is_breaking_but_heuristic() {
        let findings = diff_storage(
            &[data_key(ScSpecTypeDef::Address)],
            &[data_key(ScSpecTypeDef::U32)],
        );
        let finding = findings
            .iter()
            .find(|finding| finding.code == "storage.key_shape_changed")
            .unwrap();
        assert_eq!(finding.risk, Risk::Breaking);
        assert_eq!(finding.confidence, Confidence::Heuristic);
        assert_eq!(finding.subject, "DataKey::Balance");
    }

    #[test]
    fn report_json_has_stable_ci_fields() {
        let report = UpgradeReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            current: Artifact {
                path: "old.wasm".to_string(),
                sha256: "a".repeat(64),
            },
            candidate: Artifact {
                path: "new.wasm".to_string(),
                sha256: "b".repeat(64),
            },
            summary: Summary {
                breaking: 0,
                warnings: 1,
                info: 1,
                safe_to_upgrade: true,
            },
            findings: vec![],
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["schema_version"], "1.0");
        assert_eq!(json["summary"]["safe_to_upgrade"], true);
        assert!(json["findings"].is_array());
    }
}
