//! Data model for the generated contract knowledge base.
//!
//! The knowledge base is a single versioned JSON document (`kb.json`) plus a
//! set of Markdown files rendered from it. Every documented item carries a
//! *stable identifier* (`fn:transfer`, `err:ContractError::InsufficientBalance`,
//! …) and a deterministic anchor slug so Markdown cross-links survive
//! regeneration as long as the underlying API is unchanged. Each entry also
//! stores a SHA-256 content hash of its documentation-relevant fields, which
//! powers structural diffing and stale detection without re-reading WASM.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Schema version of the knowledge base artifact. Bump the minor component
/// for backwards-compatible additions and the major component on breaking
/// format changes.
pub const KB_SCHEMA_VERSION: &str = "1.0";

/// Highest schema major version this build can read.
pub const SUPPORTED_MAJOR: u64 = 1;

pub const GENERATOR_NAME: &str = "starforge-docgen";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExplanationSource {
    Template,
    Ai,
}

impl ExplanationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExplanationSource::Template => "template",
            ExplanationSource::Ai => "ai",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKeyKind {
    Unit,
    Tuple,
    Struct,
    EnumDiscriminant,
}

impl StorageKeyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageKeyKind::Unit => "unit",
            StorageKeyKind::Tuple => "tuple",
            StorageKeyKind::Struct => "struct",
            StorageKeyKind::EnumDiscriminant => "enum",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Struct,
    Union,
    Enum,
}

impl TypeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TypeKind::Struct => "struct",
            TypeKind::Union => "union",
            TypeKind::Enum => "enum",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamDoc {
    pub name: String,
    pub type_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExampleDoc {
    pub title: Option<String>,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionDoc {
    pub id: String,
    pub anchor: String,
    pub name: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    pub params: Vec<ParamDoc>,
    pub outputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<ExampleDoc>,
    /// Hash over every documentation-relevant field except explanations,
    /// which may be regenerated independently of the API surface.
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation_source: Option<ExplanationSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDoc {
    pub id: String,
    pub anchor: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    pub topics: Vec<ParamDoc>,
    pub data: Vec<ParamDoc>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCaseDoc {
    pub id: String,
    pub name: String,
    pub code: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnumDoc {
    pub id: String,
    pub anchor: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    pub cases: Vec<ErrorCaseDoc>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageKeyDoc {
    pub id: String,
    pub anchor: String,
    pub key_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    pub kind: StorageKeyKind,
    pub shape: String,
    /// Always true today: standard Soroban metadata does not confirm that the
    /// type is actually used for storage; see `upgrade_analyzer` for the same
    /// caveat in interface diffing.
    pub inferred: bool,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDoc {
    pub id: String,
    pub anchor: String,
    pub name: String,
    pub kind: TypeKind,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    pub content_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRequirements {
    pub wasm_size_bytes: u64,
    #[serde(default)]
    pub env_imports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_min_pages: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub data_segment_count: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub data_segment_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_function: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init_params: Vec<ParamDoc>,
    /// Storage durability kinds observed in scanned source (`--source`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_kinds: Vec<String>,
    /// True when a source tree was scanned to enrich this section.
    #[serde(default)]
    pub source_scanned: bool,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// File name only — full local paths are deliberately not persisted so
    /// committed artifacts do not leak machine layout.
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KbSummary {
    pub functions: usize,
    pub documented_functions: usize,
    pub events: usize,
    pub error_enums: usize,
    pub error_cases: usize,
    pub storage_keys: usize,
    pub types: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeBase {
    pub schema_version: String,
    pub generator: String,
    pub generator_version: String,
    pub project: ProjectMeta,
    pub artifact: ArtifactInfo,
    /// SHA-256 over the canonical spec section bytes. Changes whenever any
    /// spec entry changes, even if documentation output would be identical.
    pub spec_sha256: String,
    /// SHA-256 over the scanned source snapshot, when a source scan ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    /// RFC 3339 timestamp; only populated when generation runs with an
    /// explicit opt-in flag so default output stays byte-for-byte stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub summary: KbSummary,
    pub deployment: DeploymentRequirements,
    pub functions: Vec<FunctionDoc>,
    pub events: Vec<EventDoc>,
    pub errors: Vec<ErrorEnumDoc>,
    pub storage_keys: Vec<StorageKeyDoc>,
    pub types: Vec<TypeDoc>,
}

impl KnowledgeBase {
    /// Recomputes anchors, summary counts, and per-entry content hashes, and
    /// sorts every collection by stable ID. Must be called after mutation and
    /// before serialization so output remains deterministic.
    pub fn finalize(&mut self) {
        for f in &mut self.functions {
            f.anchor = anchor_for(&f.id);
            f.content_hash = function_hash(f);
        }
        self.functions.sort_by(|a, b| a.id.cmp(&b.id));
        for e in &mut self.events {
            e.anchor = anchor_for(&e.id);
            e.content_hash = event_hash(e);
        }
        self.events.sort_by(|a, b| a.id.cmp(&b.id));
        for e in &mut self.errors {
            e.anchor = anchor_for(&e.id);
            e.content_hash = error_enum_hash(e);
        }
        self.errors.sort_by(|a, b| a.id.cmp(&b.id));
        for k in &mut self.storage_keys {
            k.anchor = anchor_for(&k.id);
            k.content_hash = storage_key_hash(k);
        }
        self.storage_keys.sort_by(|a, b| a.id.cmp(&b.id));
        for t in &mut self.types {
            t.anchor = anchor_for(&t.id);
            t.content_hash = type_doc_hash(t);
        }
        self.types.sort_by(|a, b| a.id.cmp(&b.id));

        self.schema_version = KB_SCHEMA_VERSION.to_string();
        self.generator = GENERATOR_NAME.to_string();
        self.summary = KbSummary {
            functions: self.functions.len(),
            documented_functions: self
                .functions
                .iter()
                .filter(|f| f.doc.as_deref().is_some_and(|d| !d.trim().is_empty()))
                .count(),
            events: self.events.len(),
            error_enums: self.errors.len(),
            error_cases: self.errors.iter().map(|e| e.cases.len()).sum(),
            storage_keys: self.storage_keys.len(),
            types: self.types.len(),
        };
        self.deployment.env_imports.sort();
        self.deployment.env_imports.dedup();
    }

    /// Map of entry ID → content hash across all collections.
    pub fn entry_hashes(&self) -> std::collections::BTreeMap<String, String> {
        let mut map = std::collections::BTreeMap::new();
        for f in &self.functions {
            map.insert(f.id.clone(), f.content_hash.clone());
        }
        for e in &self.events {
            map.insert(e.id.clone(), e.content_hash.clone());
        }
        for e in &self.errors {
            for case in &e.cases {
                map.insert(case.id.clone(), error_case_hash(case));
            }
            // Also record the enum container itself (doc changes).
            map.insert(e.id.clone(), e.content_hash.clone());
        }
        for k in &self.storage_keys {
            map.insert(k.id.clone(), k.content_hash.clone());
        }
        for t in &self.types {
            map.insert(t.id.clone(), t.content_hash.clone());
        }
        map
    }

    /// Stable fingerprint over all entry hashes. Two knowledge bases built
    /// from identical APIs produce equal fingerprints regardless of machine.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for (id, hash) in self.entry_hashes() {
            hasher.update(id.as_bytes());
            hasher.update([0]);
            hasher.update(hash.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    pub fn find_function(&self, id: &str) -> Option<&FunctionDoc> {
        self.functions.iter().find(|f| f.id == id)
    }
}

/// Builds a stable entry identifier such as `fn:transfer` or
/// `err:ContractError::InsufficientBalance`.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    format!("{prefix}:{}", parts.join("::"))
}

/// Deterministic anchor slug for a stable ID: lowercased, every run of
/// non-alphanumeric characters collapsed into a single hyphen.
pub fn anchor_for(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    let mut last_hyphen = true; // avoid leading hyphen
    for ch in id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.extend(ch.to_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn content_hash<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// Content hashes must be stable under explanation regeneration, so AI or
/// template text is excluded from the hashed projection of each entry.
fn function_hash(f: &FunctionDoc) -> String {
    let mut projection = f.clone();
    projection.explanation = None;
    projection.explanation_source = None;
    projection.content_hash = String::new();
    content_hash(&projection)
}

fn event_hash(e: &EventDoc) -> String {
    let mut projection = e.clone();
    projection.content_hash = String::new();
    content_hash(&projection)
}

fn error_enum_hash(e: &ErrorEnumDoc) -> String {
    let mut projection = e.clone();
    projection.content_hash = String::new();
    content_hash(&projection)
}

pub(crate) fn error_case_hash(case: &ErrorCaseDoc) -> String {
    content_hash(case)
}

fn storage_key_hash(k: &StorageKeyDoc) -> String {
    let mut projection = k.clone();
    projection.content_hash = String::new();
    content_hash(&projection)
}

fn type_doc_hash(t: &TypeDoc) -> String {
    let mut projection = t.clone();
    projection.content_hash = String::new();
    content_hash(&projection)
}

/// Parses the major component of a `MAJOR.MINOR` version string.
pub fn parse_major_version(version: &str) -> Result<u64> {
    version
        .split('.')
        .next()
        .unwrap_or_default()
        .trim()
        .parse::<u64>()
        .with_context(|| format!("Malformed schema version '{version}'"))
}

/// Loads and validates a knowledge base from `kb.json`. Refuses formats from
/// a newer major schema with an actionable upgrade hint.
pub fn load_kb(path: &Path) -> Result<KnowledgeBase> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read knowledge base {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("Knowledge base {} is not valid JSON", path.display()))?;

    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let major =
        parse_major_version(version).with_context(|| unknown_format_message(path, version))?;
    if major > SUPPORTED_MAJOR {
        anyhow::bail!(
            "{} uses knowledge-base schema {version}, but this starforge supports up to \
             {SUPPORTED_MAJOR}.x. Upgrade starforge or regenerate the docs.",
            path.display()
        );
    }

    serde_json::from_value(value)
        .with_context(|| format!("Failed to parse knowledge base {}", path.display()))
}

fn unknown_format_message(path: &Path, version: &str) -> String {
    if version.is_empty() {
        format!(
            "{} has no recognizable schema_version field; it may not be a starforge knowledge base",
            path.display()
        )
    } else {
        format!(
            "Cannot parse schema version '{version}' in {}",
            path.display()
        )
    }
}

/// Serializes a knowledge base to pretty JSON. Pure function of the model.
pub fn kb_to_json(kb: &KnowledgeBase) -> Result<String> {
    serde_json::to_string_pretty(kb).map_err(Into::into)
}

/// Writes bytes atomically: data lands in a sibling temporary file first and
/// is then moved onto the destination, so interrupted runs never leave a
/// truncated artifact behind.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent.unwrap_or_else(|| Path::new(".")))
        .with_context(|| format!("Failed to create temporary file next to {}", path.display()))?;
    tmp.write_all(contents)
        .and_then(|_| tmp.flush())
        .with_context(|| format!("Failed to buffer contents for {}", path.display()))?;
    tmp.into_temp_path()
        .persist(path)
        .map_err(|err| anyhow::anyhow!("Failed to persist {}: {}", path.display(), err))?;
    Ok(())
}

/// Saves the knowledge base JSON document.
pub fn save_kb(kb: &KnowledgeBase, path: &Path) -> Result<()> {
    write_atomic(path, kb_to_json(kb)?.as_bytes())
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_kb() -> KnowledgeBase {
        let mut kb = KnowledgeBase {
            schema_version: KB_SCHEMA_VERSION.to_string(),
            generator: GENERATOR_NAME.to_string(),
            generator_version: "0.1.0".to_string(),
            project: ProjectMeta {
                name: "token".to_string(),
                ..Default::default()
            },
            artifact: ArtifactInfo {
                file_name: "token.wasm".to_string(),
                sha256: "aa".repeat(32),
                size_bytes: 10,
            },
            spec_sha256: "bb".repeat(32),
            source_sha256: None,
            generated_at: None,
            summary: KbSummary::default(),
            deployment: DeploymentRequirements {
                wasm_size_bytes: 10,
                ..Default::default()
            },
            functions: vec![FunctionDoc {
                id: stable_id("fn", &["transfer"]),
                anchor: String::new(),
                name: "transfer".to_string(),
                signature: "(from: Address, to: Address, amount: i128)".to_string(),
                doc: Some("Moves tokens.".to_string()),
                params: vec![ParamDoc {
                    name: "from".to_string(),
                    type_name: "Address".to_string(),
                    doc: None,
                }],
                outputs: vec![],
                examples: vec![],
                content_hash: String::new(),
                explanation: None,
                explanation_source: None,
            }],
            events: vec![EventDoc {
                id: stable_id("evt", &["Transfer"]),
                anchor: String::new(),
                name: "Transfer".to_string(),
                doc: None,
                topics: vec![],
                data: vec![ParamDoc {
                    name: "amount".to_string(),
                    type_name: "i128".to_string(),
                    doc: None,
                }],
                content_hash: String::new(),
            }],
            errors: vec![ErrorEnumDoc {
                id: stable_id("err", &["ContractError"]),
                anchor: String::new(),
                name: "ContractError".to_string(),
                doc: Some("Errors".to_string()),
                cases: vec![ErrorCaseDoc {
                    id: stable_id("err", &["ContractError", "InsufficientBalance"]),
                    name: "InsufficientBalance".to_string(),
                    code: 1,
                    doc: None,
                }],
                content_hash: String::new(),
            }],
            storage_keys: vec![StorageKeyDoc {
                id: stable_id("key", &["DataKey", "Balance"]),
                anchor: String::new(),
                key_type: "DataKey".to_string(),
                case: Some("Balance".to_string()),
                kind: StorageKeyKind::Tuple,
                shape: "(Address)".to_string(),
                inferred: true,
                content_hash: String::new(),
            }],
            types: vec![TypeDoc {
                id: stable_id("type", &["AllowanceDataKey"]),
                anchor: String::new(),
                name: "AllowanceDataKey".to_string(),
                kind: TypeKind::Struct,
                summary: "{amount: i128}".to_string(),
                doc: None,
                content_hash: String::new(),
            }],
        };
        kb.finalize();
        kb
    }

    #[test]
    fn finalize_sorts_entries_and_computes_hashes() {
        let kb = sample_kb();
        assert_eq!(kb.functions[0].id, "fn:transfer");
        assert_eq!(kb.summary.functions, 1);
        assert_eq!(kb.summary.documented_functions, 1);
        assert_eq!(kb.summary.error_cases, 1);
        assert!(!kb.functions[0].content_hash.is_empty());
        assert_eq!(kb.functions[0].anchor, "fn-transfer");
        assert_eq!(kb.storage_keys[0].anchor, "key-datakey-balance");
    }

    #[test]
    fn fingerprint_is_stable_and_order_independent() {
        let mut a = sample_kb();
        let mut b = sample_kb();
        b.functions.reverse();
        a.finalize();
        b.finalize();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn explanation_changes_do_not_affect_entry_hash_or_fingerprint() {
        let mut plain = sample_kb();
        let mut explained = sample_kb();
        explained.functions[0].explanation = Some("AI text".to_string());
        explained.functions[0].explanation_source = Some(ExplanationSource::Ai);
        explained.finalize();
        plain.finalize();
        assert_ne!(plain.functions, explained.functions);
        assert_eq!(plain.fingerprint(), explained.fingerprint());
    }

    #[test]
    fn anchors_are_slugs_without_special_characters() {
        assert_eq!(anchor_for("err:Token::BadAuth"), "err-token-badauth");
        assert_eq!(anchor_for("fn:init_v2"), "fn-init_v2");
        assert_eq!(anchor_for("evt:Transfer"), "evt-transfer");
    }

    #[test]
    fn parse_major_version_handles_semverish_input() {
        assert_eq!(parse_major_version("1.0").unwrap(), 1);
        assert_eq!(parse_major_version("2").unwrap(), 2);
        assert!(parse_major_version("").is_err());
        assert!(parse_major_version("x.y").is_err());
    }

    #[test]
    fn kb_json_roundtrip_is_lossless() {
        let kb = sample_kb();
        let json = kb_to_json(&kb).unwrap();
        let parsed: KnowledgeBase = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kb);
        // Schema metadata is present in serialized form.
        assert!(json.contains("\"schema_version\": \"1.0\""));
    }

    #[test]
    fn load_rejects_newer_schema_with_actionable_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kb.json");
        fs::write(&path, r#"{"schema_version": "9.0", "generator": "future"}"#).unwrap();
        let err = load_kb(&path).unwrap_err().to_string();
        assert!(err.contains("schema 9.0"), "{err}");
        assert!(err.contains("Upgrade starforge"), "{err}");
    }

    #[test]
    fn load_rejects_non_json_with_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kb.json");
        fs::write(&path, "not json").unwrap();
        let err = load_kb(&path).unwrap_err().to_string();
        assert!(err.contains("not valid JSON"), "{err}");
    }

    #[test]
    fn write_atomic_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("out.txt");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
    }
}
