use crate::compatibility::domain::{
    CapabilityMatrix, CompatibilityEvaluator, CompatibilityFinding, CompatibilityLevel,
    CompatibilityStatus, EndpointEvidence, FindingSeverity, COMPATIBILITY_SCHEMA_VERSION,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_FILES: usize = 10_000;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub root: PathBuf,
    pub max_files: usize,
    pub max_artifact_bytes: u64,
    pub endpoint: Option<EndpointEvidence>,
}

impl AuditOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_files: DEFAULT_MAX_FILES,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            endpoint: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: EndpointEvidence) -> Self {
        self.endpoint = Some(endpoint);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInventory {
    pub files_scanned: usize,
    pub cargo_manifests: usize,
    pub wasm_artifacts: usize,
    pub transaction_fixtures: usize,
    pub plugin_manifests: usize,
    pub compatibility_manifests: usize,
}

impl ProjectInventory {
    fn new() -> Self {
        Self {
            files_scanned: 0,
            cargo_manifests: 0,
            wasm_artifacts: 0,
            transaction_fixtures: 0,
            plugin_manifests: 0,
            compatibility_manifests: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAudit {
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyAudit {
    pub manifest: String,
    pub dependency: String,
    pub declared_version: String,
    pub level: CompatibilityLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginAudit {
    pub manifest: String,
    pub name: String,
    pub plugin_version: String,
    pub starforge_version: String,
    pub level: CompatibilityLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionFixtureAudit {
    pub path: String,
    pub protocol_version: Option<u32>,
    pub rpc_methods: BTreeSet<String>,
    pub vendor_methods: BTreeSet<String>,
    pub valid_json: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema_version: u32,
    pub matrix_version: String,
    pub generated_at: DateTime<Utc>,
    pub root: String,
    pub level: CompatibilityLevel,
    pub inventory: ProjectInventory,
    pub dependencies: Vec<DependencyAudit>,
    pub artifacts: Vec<ArtifactAudit>,
    pub plugins: Vec<PluginAudit>,
    pub transaction_fixtures: Vec<TransactionFixtureAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_status: Option<CompatibilityStatus>,
    pub findings: Vec<CompatibilityFinding>,
}

impl AuditReport {
    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Warning)
            .count()
    }

    pub fn should_fail(&self, threshold: AuditFailureThreshold) -> bool {
        match threshold {
            AuditFailureThreshold::Never => false,
            AuditFailureThreshold::Incompatible => self.level == CompatibilityLevel::Incompatible,
            AuditFailureThreshold::Degraded => self.level != CompatibilityLevel::Compatible,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailureThreshold {
    Never,
    Incompatible,
    Degraded,
}

pub struct CompatibilityAuditor {
    matrix: CapabilityMatrix,
}

impl CompatibilityAuditor {
    pub fn new(matrix: CapabilityMatrix) -> Self {
        Self { matrix }
    }

    pub fn audit(&self, options: AuditOptions) -> anyhow::Result<AuditReport> {
        self.audit_at(options, Utc::now())
    }

    pub fn audit_at(
        &self,
        options: AuditOptions,
        generated_at: DateTime<Utc>,
    ) -> anyhow::Result<AuditReport> {
        let root = options.root.canonicalize().map_err(|error| {
            anyhow::anyhow!(
                "Failed to resolve audit root {}: {}",
                options.root.display(),
                error
            )
        })?;
        if !root.is_dir() {
            anyhow::bail!(
                "Compatibility audit root must be a directory: {}",
                root.display()
            );
        }
        let mut files = Vec::new();
        collect_files(&root, &root, options.max_files, &mut files)?;
        files.sort();
        let mut inventory = ProjectInventory::new();
        inventory.files_scanned = files.len();
        let mut dependencies = Vec::new();
        let mut artifacts = Vec::new();
        let mut plugins = Vec::new();
        let mut transaction_fixtures = Vec::new();
        let mut findings = Vec::new();

        for path in files {
            let relative = relative_display(&root, &path);
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if name == "Cargo.toml" {
                inventory.cargo_manifests += 1;
                self.inspect_cargo(&path, &relative, &mut dependencies, &mut findings);
            }
            if name == "starforge-plugin.toml" {
                inventory.plugin_manifests += 1;
                self.inspect_plugin(&path, &relative, &mut plugins, &mut findings);
            }
            if name == "starforge.compatibility.toml" {
                inventory.compatibility_manifests += 1;
                self.inspect_compatibility_manifest(&path, &relative, &mut findings);
            }
            if path.extension().and_then(|extension| extension.to_str()) == Some("wasm") {
                inventory.wasm_artifacts += 1;
                self.inspect_wasm(
                    &path,
                    &relative,
                    options.max_artifact_bytes,
                    &mut artifacts,
                    &mut findings,
                );
            }
            if is_transaction_fixture(&path) {
                inventory.transaction_fixtures += 1;
                self.inspect_transaction_fixture(
                    &path,
                    &relative,
                    &mut transaction_fixtures,
                    &mut findings,
                );
            }
        }

        if inventory.cargo_manifests == 0 {
            findings.push(CompatibilityFinding::new(
                "project.cargo_manifest_missing",
                FindingSeverity::Warning,
                "project",
                "No Cargo.toml was found in the audited project.",
                "Run the audit at the Rust workspace root or document a non-Rust project boundary.",
            ));
        }
        if inventory.wasm_artifacts == 0 {
            findings.push(CompatibilityFinding::new(
                "artifact.wasm_missing",
                FindingSeverity::Info,
                "artifact",
                "No compiled Soroban WASM artifact was available for validation.",
                "Build release artifacts and repeat the audit before an upgrade.",
            ));
        }

        let endpoint_status = options.endpoint.map(|endpoint| {
            CompatibilityEvaluator::new(&self.matrix).evaluate_endpoint(endpoint, generated_at)
        });
        if let Some(status) = &endpoint_status {
            findings.extend(status.findings.clone());
        } else {
            findings.push(CompatibilityFinding::new(
                "endpoint.evidence_missing",
                FindingSeverity::Warning,
                "endpoint",
                "No fresh endpoint capability evidence was included in the audit.",
                "Run compatibility probe, then repeat audit with cached endpoint evidence.",
            ));
        }

        findings.sort_by(|left, right| {
            right
                .severity
                .rank()
                .cmp(&left.severity.rank())
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.summary.cmp(&right.summary))
        });
        findings.dedup_by(|left, right| {
            left.code == right.code
                && left.component == right.component
                && left.summary == right.summary
                && left.evidence == right.evidence
        });
        let level =
            findings.iter().fold(
                CompatibilityLevel::Compatible,
                |level, finding| match finding.severity {
                    FindingSeverity::Error => level.merge(CompatibilityLevel::Incompatible),
                    FindingSeverity::Warning => level.merge(CompatibilityLevel::Degraded),
                    FindingSeverity::Info => level,
                },
            );
        Ok(AuditReport {
            schema_version: COMPATIBILITY_SCHEMA_VERSION,
            matrix_version: self.matrix.matrix_version.clone(),
            generated_at,
            root: root.display().to_string(),
            level,
            inventory,
            dependencies,
            artifacts,
            plugins,
            transaction_fixtures,
            endpoint_status,
            findings,
        })
    }

    fn inspect_cargo(
        &self,
        path: &Path,
        relative: &str,
        dependencies: &mut Vec<DependencyAudit>,
        findings: &mut Vec<CompatibilityFinding>,
    ) {
        let Ok(contents) = fs::read_to_string(path) else {
            findings.push(file_error(
                "project.manifest_unreadable",
                relative,
                "Cargo manifest could not be read.",
            ));
            return;
        };
        let Ok(manifest) = toml::from_str::<toml::Value>(&contents) else {
            findings.push(file_error(
                "project.manifest_malformed",
                relative,
                "Cargo manifest is malformed.",
            ));
            return;
        };
        let Some(version) = dependency_version(&manifest, "stellar-xdr") else {
            return;
        };
        let major = parse_version_major(&version);
        let level = match major {
            Some(value) if value < self.matrix.xdr.protocol.minimum => {
                CompatibilityLevel::Incompatible
            }
            Some(value) if value > self.matrix.xdr.protocol.maximum => {
                CompatibilityLevel::Incompatible
            }
            Some(_) => CompatibilityLevel::Compatible,
            None => CompatibilityLevel::Unknown,
        };
        dependencies.push(DependencyAudit {
            manifest: relative.into(),
            dependency: "stellar-xdr".into(),
            declared_version: version.clone(),
            level,
        });
        if level != CompatibilityLevel::Compatible {
            let (code, summary) = match major {
                Some(value) if value > self.matrix.xdr.protocol.maximum => (
                    "xdr.future_unverified",
                    format!("stellar-xdr {version} is newer than the validated matrix."),
                ),
                Some(_) => (
                    "xdr.too_old",
                    format!("stellar-xdr {version} is older than supported Soroban XDR."),
                ),
                None => (
                    "xdr.version_ambiguous",
                    format!("stellar-xdr declaration {version} could not be evaluated."),
                ),
            };
            findings.push(
                CompatibilityFinding::new(
                    code,
                    if level == CompatibilityLevel::Incompatible {
                        FindingSeverity::Error
                    } else {
                        FindingSeverity::Warning
                    },
                    "xdr",
                    summary,
                    format!(
                        "Pin stellar-xdr to the evidence-backed {} release series and regenerate fixtures.",
                        self.matrix.xdr.crate_version
                    ),
                )
                .with_evidence("manifest", relative),
            );
        }
    }

    fn inspect_wasm(
        &self,
        path: &Path,
        relative: &str,
        max_bytes: u64,
        artifacts: &mut Vec<ArtifactAudit>,
        findings: &mut Vec<CompatibilityFinding>,
    ) {
        let Ok(bytes) = fs::read(path) else {
            findings.push(file_error(
                "artifact.unreadable",
                relative,
                "WASM artifact could not be read.",
            ));
            return;
        };
        let size = bytes.len() as u64;
        let valid_magic = bytes.starts_with(b"\0asm");
        let structurally_valid =
            valid_magic && wasmparser::Validator::new().validate_all(&bytes).is_ok();
        let digest = Sha256::digest(&bytes);
        artifacts.push(ArtifactAudit {
            path: relative.into(),
            kind: "soroban_wasm".into(),
            size_bytes: size,
            sha256: hex::encode(digest),
            valid: structurally_valid,
        });
        if !structurally_valid {
            findings.push(
                CompatibilityFinding::new(
                    "artifact.wasm_invalid",
                    FindingSeverity::Error,
                    "artifact",
                    "A .wasm artifact is not a structurally valid WebAssembly module.",
                    "Rebuild the contract artifact and verify the build output before deployment.",
                )
                .with_evidence("path", relative),
            );
        }
        if size > max_bytes {
            findings.push(
                CompatibilityFinding::new(
                    "artifact.wasm_limit",
                    FindingSeverity::Error,
                    "artifact",
                    format!("A WASM artifact is {size} bytes, above the audit limit {max_bytes}."),
                    "Optimize the contract and confirm the target network's contract-size limit.",
                )
                .with_evidence("path", relative),
            );
        }
    }

    fn inspect_plugin(
        &self,
        path: &Path,
        relative: &str,
        plugins: &mut Vec<PluginAudit>,
        findings: &mut Vec<CompatibilityFinding>,
    ) {
        let value = fs::read_to_string(path)
            .ok()
            .and_then(|contents| toml::from_str::<toml::Value>(&contents).ok());
        let Some(table) = value.as_ref().and_then(toml::Value::as_table) else {
            findings.push(file_error(
                "plugin.manifest_malformed",
                relative,
                "Plugin manifest is malformed or unreadable.",
            ));
            return;
        };
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let version = table
            .get("version")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let starforge = table
            .get("starforge_version")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let core_major = parse_version_major(env!("CARGO_PKG_VERSION"));
        let plugin_major = parse_version_major(starforge);
        let level = if name.is_empty() || version.is_empty() || starforge.is_empty() {
            CompatibilityLevel::Incompatible
        } else if core_major == plugin_major {
            CompatibilityLevel::Compatible
        } else {
            CompatibilityLevel::Incompatible
        };
        plugins.push(PluginAudit {
            manifest: relative.into(),
            name: name.into(),
            plugin_version: version.into(),
            starforge_version: starforge.into(),
            level,
        });
        if level != CompatibilityLevel::Compatible {
            findings.push(
                CompatibilityFinding::new(
                    "plugin.version_incompatible",
                    FindingSeverity::Error,
                    "plugin",
                    "A plugin manifest does not target the running StarForge major version.",
                    "Rebuild the plugin against the current plugin SDK and update its manifest.",
                )
                .with_evidence("manifest", relative),
            );
        }
    }

    fn inspect_compatibility_manifest(
        &self,
        path: &Path,
        relative: &str,
        findings: &mut Vec<CompatibilityFinding>,
    ) {
        let value = fs::read_to_string(path)
            .ok()
            .and_then(|contents| toml::from_str::<toml::Value>(&contents).ok());
        let Some(value) = value else {
            findings.push(file_error(
                "compatibility.manifest_malformed",
                relative,
                "Compatibility requirements manifest is malformed or unreadable.",
            ));
            return;
        };
        let minimum = value
            .get("protocol")
            .and_then(|protocol| protocol.get("minimum"))
            .and_then(toml::Value::as_integer)
            .and_then(|number| u32::try_from(number).ok());
        let maximum = value
            .get("protocol")
            .and_then(|protocol| protocol.get("maximum"))
            .and_then(toml::Value::as_integer)
            .and_then(|number| u32::try_from(number).ok());
        if let (Some(minimum), Some(maximum)) = (minimum, maximum) {
            if minimum > maximum {
                findings.push(
                    CompatibilityFinding::new(
                        "compatibility.protocol_range_invalid",
                        FindingSeverity::Error,
                        "project",
                        "The project compatibility protocol range is inverted.",
                        "Set protocol.minimum less than or equal to protocol.maximum.",
                    )
                    .with_evidence("manifest", relative),
                );
            }
            if maximum > self.matrix.xdr.protocol.maximum {
                findings.push(
                    CompatibilityFinding::new(
                        "compatibility.future_protocol_requested",
                        FindingSeverity::Error,
                        "project",
                        format!("The project declares unvalidated future protocol {maximum}."),
                        "Validate the protocol and upgrade the StarForge matrix/XDR dependency first.",
                    )
                    .with_evidence("manifest", relative),
                );
            }
            if minimum < self.matrix.xdr.protocol.minimum {
                findings.push(
                    CompatibilityFinding::new(
                        "compatibility.old_protocol_requested",
                        FindingSeverity::Error,
                        "project",
                        format!("The project declares unsupported protocol {minimum}."),
                        "Raise the project minimum protocol or use a compatible release branch.",
                    )
                    .with_evidence("manifest", relative),
                );
            }
        } else {
            findings.push(
                CompatibilityFinding::new(
                    "compatibility.protocol_range_missing",
                    FindingSeverity::Warning,
                    "project",
                    "Compatibility manifest lacks protocol.minimum and protocol.maximum.",
                    "Declare an explicit evidence-backed protocol range.",
                )
                .with_evidence("manifest", relative),
            );
        }
    }

    fn inspect_transaction_fixture(
        &self,
        path: &Path,
        relative: &str,
        fixtures: &mut Vec<TransactionFixtureAudit>,
        findings: &mut Vec<CompatibilityFinding>,
    ) {
        let value = fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<JsonValue>(&bytes).ok());
        let Some(value) = value else {
            fixtures.push(TransactionFixtureAudit {
                path: relative.into(),
                protocol_version: None,
                rpc_methods: BTreeSet::new(),
                vendor_methods: BTreeSet::new(),
                valid_json: false,
            });
            findings.push(
                CompatibilityFinding::new(
                    "fixture.transaction_malformed",
                    FindingSeverity::Error,
                    "fixture",
                    "A transaction fixture is not valid JSON.",
                    "Regenerate or repair the deterministic transaction fixture.",
                )
                .with_evidence("path", relative),
            );
            return;
        };
        let protocol = find_protocol_version(&value);
        let mut methods = BTreeSet::new();
        collect_rpc_methods(&value, &mut methods);
        let known = self.matrix.known_methods();
        let vendor_methods = methods.difference(&known).cloned().collect();
        fixtures.push(TransactionFixtureAudit {
            path: relative.into(),
            protocol_version: protocol,
            rpc_methods: methods,
            vendor_methods,
            valid_json: true,
        });
        if let Some(protocol) = protocol {
            let status =
                CompatibilityEvaluator::new(&self.matrix).evaluate_protocol(Some(protocol));
            if status.level == CompatibilityLevel::Incompatible {
                findings.push(
                    CompatibilityFinding::new(
                        "fixture.protocol_incompatible",
                        FindingSeverity::Error,
                        "fixture",
                        format!("A transaction fixture targets incompatible protocol {protocol}."),
                        "Regenerate the fixture with a validated protocol and XDR release.",
                    )
                    .with_evidence("path", relative),
                );
            }
        }
    }
}

fn collect_files(
    root: &Path,
    directory: &Path,
    max_files: usize,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            if matches!(
                name.to_str(),
                Some(".git" | "target" | "node_modules" | ".starforge")
            ) {
                continue;
            }
            collect_files(root, &path, max_files, files)?;
        } else if file_type.is_file() {
            if files.len() >= max_files {
                anyhow::bail!(
                    "Compatibility audit exceeded the bounded file limit of {} under {}",
                    max_files,
                    root.display()
                );
            }
            files.push(path);
        }
    }
    Ok(())
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_transaction_fixture(path: &Path) -> bool {
    if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
        return false;
    }
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("transaction") || lower.contains("/tx_") || lower.contains("/tx-")
}

fn dependency_version(manifest: &toml::Value, name: &str) -> Option<String> {
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|section| manifest.get(*section))
        .filter_map(toml::Value::as_table)
        .find_map(|table| {
            table.get(name).and_then(|value| match value {
                toml::Value::String(version) => Some(version.clone()),
                toml::Value::Table(table) => table
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .map(ToOwned::to_owned),
                _ => None,
            })
        })
}

fn parse_version_major(version: &str) -> Option<u32> {
    version
        .trim()
        .trim_start_matches(['=', '^', '~', '>', '<'])
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()
}

fn find_protocol_version(value: &JsonValue) -> Option<u32> {
    match value {
        JsonValue::Object(object) => {
            for name in ["protocol_version", "protocolVersion", "protocol"] {
                if let Some(version) = object.get(name).and_then(|field| {
                    field
                        .as_u64()
                        .or_else(|| field.as_str().and_then(|text| text.parse().ok()))
                }) {
                    if let Ok(version) = u32::try_from(version) {
                        return Some(version);
                    }
                }
            }
            object.values().find_map(find_protocol_version)
        }
        JsonValue::Array(values) => values.iter().find_map(find_protocol_version),
        _ => None,
    }
}

fn collect_rpc_methods(value: &JsonValue, methods: &mut BTreeSet<String>) {
    match value {
        JsonValue::Object(object) => {
            if object.get("jsonrpc").and_then(JsonValue::as_str) == Some("2.0") {
                if let Some(method) = object.get("method").and_then(JsonValue::as_str) {
                    methods.insert(method.into());
                }
            }
            for value in object.values() {
                collect_rpc_methods(value, methods);
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                collect_rpc_methods(value, methods);
            }
        }
        _ => {}
    }
}

fn file_error(code: &str, relative: &str, summary: &str) -> CompatibilityFinding {
    CompatibilityFinding::new(
        code,
        FindingSeverity::Error,
        "file",
        summary,
        "Repair the file and repeat the compatibility audit.",
    )
    .with_evidence("path", relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    #[test]
    fn audit_finds_future_xdr_malformed_fixture_and_invalid_wasm() {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n[dependencies]\nstellar-xdr='99'\n",
        )
        .unwrap();
        fs::create_dir(temp.path().join("transactions")).unwrap();
        fs::write(
            temp.path().join("transactions/transaction.json"),
            b"not-json",
        )
        .unwrap();
        fs::write(temp.path().join("contract.wasm"), b"not-wasm").unwrap();
        let at = Utc.with_ymd_and_hms(2026, 8, 28, 12, 0, 0).unwrap();
        let report = CompatibilityAuditor::new(CapabilityMatrix::builtin())
            .audit_at(AuditOptions::new(temp.path()), at)
            .unwrap();
        assert_eq!(report.level, CompatibilityLevel::Incompatible);
        assert!(report
            .findings
            .iter()
            .any(|item| item.code == "xdr.future_unverified"));
        assert!(report
            .findings
            .iter()
            .any(|item| item.code == "fixture.transaction_malformed"));
        assert!(report
            .findings
            .iter()
            .any(|item| item.code == "artifact.wasm_invalid"));
    }

    #[test]
    fn audit_accepts_valid_wasm_and_known_protocol_fixture() {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n[dependencies]\nstellar-xdr='22'\n",
        )
        .unwrap();
        fs::write(temp.path().join("contract.wasm"), b"\0asm\x01\0\0\0").unwrap();
        fs::write(
            temp.path().join("transaction.json"),
            r#"{"protocol_version":22,"jsonrpc":"2.0","method":"getLatestLedger"}"#,
        )
        .unwrap();
        let report = CompatibilityAuditor::new(CapabilityMatrix::builtin())
            .audit(AuditOptions::new(temp.path()))
            .unwrap();
        assert!(report.artifacts[0].valid);
        assert_eq!(report.dependencies[0].level, CompatibilityLevel::Compatible);
        assert_eq!(report.transaction_fixtures[0].protocol_version, Some(22));
    }
}
