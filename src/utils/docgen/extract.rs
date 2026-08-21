//! Extraction of a documentation knowledge base from contract artifacts.
//!
//! Two evidence sources are combined:
//!
//! * **WASM `contractspecv0` metadata** (confirmed evidence): public
//!   functions, error enums, user-defined types, and storage-key-shaped
//!   unions/structs/enums. This is the same metadata the host environment
//!   enforces, so signatures extracted here are authoritative.
//! * **Rust source tree** (optional, heuristic evidence): event definitions
//!   (`#[contractevent]` structs) and storage durability kinds, neither of
//!   which are part of XDR v22 spec metadata. Every heuristic finding is
//!   marked as such in the output.
//!
//! All free-text fields pass through [`redact_text`] before entering the
//! knowledge base so committed documentation cannot leak credentials or the
//! local directory layout.

use crate::utils::bindings::{contract_spec_section, read_spec_entries, spec_type_name};
use crate::utils::docgen::model::{
    anchor_for, stable_id, DeploymentRequirements, ErrorCaseDoc, ErrorEnumDoc, EventDoc,
    FunctionDoc, KbSummary, KnowledgeBase, ParamDoc, ProjectMeta, StorageKeyDoc, StorageKeyKind,
    TypeDoc, TypeKind,
};
use crate::utils::docgen::redact::redact_text;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtUnionCaseV0};
use wasmparser::{Parser, Payload};

/// Inputs for a single knowledge-base build.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Descriptive project metadata embedded in the artifact.
    pub project: ProjectMeta,
    /// Optional Rust source tree scanned for heuristic signals (events,
    /// storage durability kinds).
    pub source_dir: Option<PathBuf>,
    /// Home-directory prefix redacted from free text (`None` disables path
    /// redaction; secret redaction always runs unless [`Self::no_redact`]).
    pub home: Option<String>,
    /// Opt-out for all redaction; only honoured when explicitly requested by
    /// the operator (CLI `--no-redact`).
    pub no_redact: bool,
    /// Optional RFC 3339 timestamp recorded in the artifact. Left unset by
    /// default so default output stays byte-for-byte deterministic.
    pub generated_at: Option<String>,
}

/// Builds a complete knowledge base from WASM bytes and optional sources.
pub fn build_kb(wasm_path: &Path, wasm: &[u8], options: &ExtractOptions) -> Result<KnowledgeBase> {
    let entries = read_spec_entries(wasm)
        .with_context(|| format!("Could not read spec metadata from {}", wasm_path.display()))?;
    let spec = contract_spec_section(wasm)
        .with_context(|| format!("Could not locate spec section in {}", wasm_path.display()))?;

    let mut kb = KnowledgeBase {
        schema_version: String::new(), // set by finalize()
        generator: String::new(),      // set by finalize()
        generator_version: env!("CARGO_PKG_VERSION").to_string(),
        project: options.project.clone(),
        artifact: crate::utils::docgen::model::ArtifactInfo {
            file_name: wasm_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "contract.wasm".to_string()),
            sha256: sha256_hex(wasm),
            size_bytes: wasm.len() as u64,
        },
        spec_sha256: sha256_hex(spec),
        source_sha256: None,
        generated_at: options.generated_at.clone(),
        summary: KbSummary::default(),
        deployment: deployment_requirements(wasm)?,
        functions: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
        storage_keys: Vec::new(),
        types: Vec::new(),
    };

    extract_spec_entries(&entries, &mut kb, options);

    if let Some(dir) = &options.source_dir {
        let scan = scan_source_tree(dir, options)?;
        kb.events.extend(scan.events);
        kb.deployment.storage_kinds = scan.storage_kinds.into_keys().collect();
        kb.deployment.source_scanned = true;
        kb.source_sha256 = Some(scan.tree_hash);
    }

    kb.finalize();
    Ok(kb)
}

fn extract_spec_entries(entries: &[ScSpecEntry], kb: &mut KnowledgeBase, options: &ExtractOptions) {
    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                kb.functions.push(function_doc(f, options));
            }
            ScSpecEntry::UdtErrorEnumV0(e) => {
                kb.errors.push(error_enum_doc(e, options));
            }
            ScSpecEntry::UdtUnionV0(u) => {
                let name = u.name.to_string();
                if looks_like_storage_key_type(&name) {
                    for case in u.cases.iter() {
                        kb.storage_keys.push(union_case_key_doc(&name, case));
                    }
                } else {
                    kb.types.push(TypeDoc {
                        id: stable_id("type", &[&name]),
                        anchor: String::new(),
                        name: name.clone(),
                        kind: TypeKind::Union,
                        summary: union_summary(u),
                        doc: clean_doc(&raw_string(&u.doc), options),
                        content_hash: String::new(),
                    });
                }
            }
            ScSpecEntry::UdtEnumV0(e) => {
                let name = e.name.to_string();
                if looks_like_storage_key_type(&name) {
                    for case in e.cases.iter() {
                        kb.storage_keys.push(StorageKeyDoc {
                            id: stable_id("key", &[&name, &case.name.to_string()]),
                            anchor: String::new(),
                            key_type: name.clone(),
                            case: Some(case.name.to_string()),
                            kind: StorageKeyKind::EnumDiscriminant,
                            shape: format!("integer discriminant {}", case.value),
                            inferred: true,
                            content_hash: String::new(),
                        });
                    }
                } else {
                    kb.types.push(TypeDoc {
                        id: stable_id("type", &[&name]),
                        anchor: String::new(),
                        name: name.clone(),
                        kind: TypeKind::Enum,
                        summary: enum_summary(e),
                        doc: clean_doc(&raw_string(&e.doc), options),
                        content_hash: String::new(),
                    });
                }
            }
            ScSpecEntry::UdtStructV0(s) => {
                let name = s.name.to_string();
                if looks_like_storage_key_type(&name) {
                    kb.storage_keys.push(StorageKeyDoc {
                        id: stable_id("key", &[&name]),
                        anchor: String::new(),
                        key_type: name.clone(),
                        case: None,
                        kind: StorageKeyKind::Struct,
                        shape: struct_summary(s),
                        inferred: true,
                        content_hash: String::new(),
                    });
                } else {
                    kb.types.push(TypeDoc {
                        id: stable_id("type", &[&name]),
                        anchor: String::new(),
                        name: name.clone(),
                        kind: TypeKind::Struct,
                        summary: struct_summary(s),
                        doc: clean_doc(&raw_string(&s.doc), options),
                        content_hash: String::new(),
                    });
                }
            }
        }
    }

    // Constructor parameters are only knowable when the constructor also
    // appears in the spec; enrich the deployment section when it does.
    if kb.deployment.init_function.is_some() {
        if let Some(constructor) = entries.iter().find_map(|e| match e {
            ScSpecEntry::FunctionV0(f) if f.name.to_string() == "__constructor" => Some(f),
            _ => None,
        }) {
            kb.deployment.init_params = constructor
                .inputs
                .iter()
                .map(|input| ParamDoc {
                    name: input.name.to_string(),
                    type_name: spec_type_name(&input.type_),
                    doc: clean_doc(&raw_string(&input.doc), options),
                })
                .collect();
        }
    }
}

fn function_doc(f: &stellar_xdr::curr::ScSpecFunctionV0, options: &ExtractOptions) -> FunctionDoc {
    let name = f.name.to_string();
    let params: Vec<ParamDoc> = f
        .inputs
        .iter()
        .map(|input| ParamDoc {
            name: input.name.to_string(),
            type_name: spec_type_name(&input.type_),
            doc: clean_doc(&raw_string(&input.doc), options),
        })
        .collect();
    let outputs: Vec<String> = f.outputs.iter().map(spec_type_name).collect();
    FunctionDoc {
        id: stable_id("fn", &[&name]),
        anchor: anchor_for(&stable_id("fn", &[&name])),
        name,
        signature: signature_line(&params, &outputs),
        doc: clean_doc(&raw_string(&f.doc), options),
        params,
        outputs,
        examples: Vec::new(),
        content_hash: String::new(),
        explanation: None,
        explanation_source: None,
    }
}

fn error_enum_doc(
    e: &stellar_xdr::curr::ScSpecUdtErrorEnumV0,
    options: &ExtractOptions,
) -> ErrorEnumDoc {
    let name = e.name.to_string();
    ErrorEnumDoc {
        id: stable_id("err", &[&name]),
        anchor: String::new(),
        name: name.clone(),
        doc: clean_doc(&raw_string(&e.doc), options),
        cases: e
            .cases
            .iter()
            .map(|case| ErrorCaseDoc {
                id: stable_id("err", &[&name, &case.name.to_string()]),
                name: case.name.to_string(),
                code: case.value,
                doc: clean_doc(&raw_string(&case.doc), options),
            })
            .collect(),
        content_hash: String::new(),
    }
}

fn union_case_key_doc(key_type: &str, case: &ScSpecUdtUnionCaseV0) -> StorageKeyDoc {
    let (case_name, kind, shape) = match case {
        ScSpecUdtUnionCaseV0::VoidV0(c) => {
            (c.name.to_string(), StorageKeyKind::Unit, "()".to_string())
        }
        ScSpecUdtUnionCaseV0::TupleV0(c) => (
            c.name.to_string(),
            StorageKeyKind::Tuple,
            format!(
                "({})",
                c.type_
                    .iter()
                    .map(spec_type_name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    };
    StorageKeyDoc {
        id: stable_id("key", &[key_type, &case_name]),
        anchor: String::new(),
        key_type: key_type.to_string(),
        case: Some(case_name),
        kind,
        shape,
        inferred: true,
        content_hash: String::new(),
    }
}

/// Reads an XDR string as raw UTF-8. `StringM`'s `Display` impl escapes
/// control characters (a newline becomes the two characters `\` + `n`),
/// which would corrupt multi-line doc comments — so docs must never go
/// through `to_string()`.
pub(crate) fn raw_string<const MAX: u32>(m: &stellar_xdr::curr::StringM<MAX>) -> String {
    String::from_utf8_lossy(m.as_vec()).into_owned()
}

fn signature_line(params: &[ParamDoc], outputs: &[String]) -> String {
    let inputs = params
        .iter()
        .map(|p| format!("{}: {}", p.name, p.type_name))
        .collect::<Vec<_>>()
        .join(", ");
    let output = match outputs {
        [] => "()".to_string(),
        [only] => only.clone(),
        many => format!("({})", many.join(", ")),
    };
    format!("({inputs}) -> {output}")
}

fn struct_summary(s: &stellar_xdr::curr::ScSpecUdtStructV0) -> String {
    format!(
        "{{{}}}",
        s.fields
            .iter()
            .map(|f| format!("{}: {}", f.name, spec_type_name(&f.type_)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn union_summary(u: &stellar_xdr::curr::ScSpecUdtUnionV0) -> String {
    let cases = u
        .cases
        .iter()
        .map(|case| match case {
            ScSpecUdtUnionCaseV0::VoidV0(c) => c.name.to_string(),
            ScSpecUdtUnionCaseV0::TupleV0(c) => format!(
                "{}({})",
                c.name,
                c.type_
                    .iter()
                    .map(spec_type_name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
        .collect::<Vec<_>>()
        .join(" | ");
    format!("enum {{ {cases} }}")
}

fn enum_summary(e: &stellar_xdr::curr::ScSpecUdtEnumV0) -> String {
    let cases = e
        .cases
        .iter()
        .map(|c| format!("{} = {}", c.name, c.value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {cases} }}")
}

/// Mirrors the heuristic used by `upgrade_analyzer`: only types whose names
/// conventionally identify storage keys are treated as such, and every
/// resulting entry carries `inferred = true`.
pub(crate) fn looks_like_storage_key_type(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(normalized.as_str(), "key" | "datakey" | "storagekey")
        || (normalized.contains("storage") && normalized.ends_with("key"))
}

/// Normalises an XDR doc string and applies redaction. Empty docs collapse to
/// `None` so downstream quality checks see a consistent notion of "missing".
pub(crate) fn clean_doc(raw: &str, options: &ExtractOptions) -> Option<String> {
    let joined = raw
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    // Collapse runs of blank lines so knowledge-base entries stay compact.
    let mut collapsed = String::with_capacity(joined.len());
    let mut at_newline_run = false;
    for ch in joined.chars() {
        if ch == '\n' {
            if !at_newline_run {
                collapsed.push(ch);
            }
            at_newline_run = true;
        } else {
            collapsed.push(ch);
            at_newline_run = false;
        }
    }
    let trimmed = collapsed.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    let cleaned = if options.no_redact {
        trimmed
    } else {
        redact_text(&trimmed, options.home.as_deref())
    };
    if cleaned.trim().is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

// ── Deployment requirements ─────────────────────────────────────────────────

/// Scans the raw module for facts relevant to deployment docs: imported host
/// functions (`env` module), memory sizing, data segments, and whether a
/// Soroban constructor export exists.
pub fn deployment_requirements(wasm: &[u8]) -> Result<DeploymentRequirements> {
    let mut req = DeploymentRequirements {
        wasm_size_bytes: wasm.len() as u64,
        ..Default::default()
    };
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.context("Malformed WASM while scanning deployment requirements")? {
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import.context("Malformed WASM import section")?;
                    if import.module == "env" {
                        req.env_imports.push(import.name.to_string());
                    }
                }
            }
            Payload::MemorySection(section) => {
                for memory in section {
                    let memory = memory.context("Malformed WASM memory section")?;
                    if req.memory_min_pages.is_none() {
                        req.memory_min_pages = Some(memory.initial);
                    }
                }
            }
            Payload::DataSection(section) => {
                for data in section {
                    let data = data.context("Malformed WASM data section")?;
                    req.data_segment_count += 1;
                    req.data_segment_bytes += data.data.len() as u64;
                }
            }
            Payload::ExportSection(section) => {
                for export in section {
                    let export = export.context("Malformed WASM export section")?;
                    if export.name == "__constructor" {
                        req.init_function = Some(export.name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(req)
}

// ── Source-tree scanning ────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SourceScan {
    events: Vec<EventDoc>,
    storage_kinds: BTreeMap<String, ()>,
    tree_hash: String,
}

/// Recursively scans `.rs` files under `dir` (deterministic order) for
/// heuristic documentation signals.
pub fn scan_source_tree(dir: &Path, options: &ExtractOptions) -> Result<SourceScan> {
    let mut files = BTreeMap::new();
    collect_rs_files(dir, dir, &mut files)?;

    let mut scan = SourceScan::default();
    let mut hasher = Sha256::new();
    for (rel, abs) in &files {
        let contents = fs::read_to_string(abs)
            .with_context(|| format!("Failed to read source file {}", abs.display()))?;
        hasher.update(rel.as_bytes());
        hasher.update([0]);
        hasher.update(sha256_hex(contents.as_bytes()).as_bytes());

        scan_events(&contents, &mut scan.events, options);
        for kind in detect_storage_kinds(&contents) {
            scan.storage_kinds.insert(kind, ());
        }
    }
    scan.tree_hash = hex::encode(hasher.finalize());
    Ok(scan)
}

fn collect_rs_files(root: &Path, dir: &Path, out: &mut BTreeMap<String, PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("Failed to list directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to list directory {}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(root, &path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, path);
        }
    }
    Ok(())
}

const STORAGE_KIND_MARKERS: [(&str, &str); 3] = [
    ("env.storage().instance()", "instance"),
    ("env.storage().persistent()", "persistent"),
    ("env.storage().temporary()", "temporary"),
];

fn detect_storage_kinds(source: &str) -> Vec<String> {
    STORAGE_KIND_MARKERS
        .iter()
        .filter(|(marker, _)| source.contains(marker))
        .map(|(_, kind)| (*kind).to_string())
        .collect()
}

/// Extracts event documentation from `#[contractevent]` definitions.
///
/// Recognised shapes (soroban-sdk ≥ 20.1):
///
/// ```ignore
/// /// Doc comment becomes the event description.
/// #[contractevent]
/// #[topic("account")]     // container-level topic list (names only)
/// pub struct TransferEvent {
///     #[topic] account: Address,   // field-level topic marker
///     amount: i128,                // remaining fields are data
/// }
/// ```
///
/// The parse is deliberately textual and conservative: anything that does not
/// match the canonical shape is skipped rather than guessed at.
pub fn scan_events(source: &str, out: &mut Vec<EventDoc>, options: &ExtractOptions) {
    const MARKER: &str = "#[contractevent]";
    let mut rest = source;
    while let Some(pos) = rest.find(MARKER) {
        let after_marker = &rest[pos + MARKER.len()..];
        let doc_comment = trailing_doc_comment(&rest[..pos]);

        // Container-level attributes between the marker and the struct keyword.
        let Some(struct_kw) = find_keyword(after_marker, "struct") else {
            rest = after_marker;
            continue;
        };
        let header = &after_marker[..struct_kw];
        let container_topics = quoted_idents_after(header, "topic");

        let Some(name) = ident_at(after_marker, struct_kw + "struct".len()) else {
            rest = after_marker;
            continue;
        };

        let Some((body, body_end)) = balanced_braces(after_marker) else {
            rest = after_marker;
            continue;
        };

        let fields = parse_struct_fields(&body);
        let field_topics: Vec<&Field> = fields.iter().filter(|f| f.topic).collect();

        let topics: Vec<ParamDoc> = if !container_topics.is_empty() {
            container_topics
                .iter()
                .map(|t| {
                    let ty = fields
                        .iter()
                        .find(|f| &f.name == t)
                        .map(|f| f.type_name.clone())
                        .unwrap_or_else(|| "Symbol".to_string());
                    ParamDoc {
                        name: t.clone(),
                        type_name: ty,
                        doc: None,
                    }
                })
                .collect()
        } else {
            field_topics
                .iter()
                .map(|f| ParamDoc {
                    name: f.name.clone(),
                    type_name: f.type_name.clone(),
                    doc: None,
                })
                .collect()
        };

        let data: Vec<ParamDoc> = fields
            .iter()
            .filter(|f| !f.topic && !container_topics.contains(&f.name))
            .map(|f| ParamDoc {
                name: f.name.clone(),
                type_name: f.type_name.clone(),
                doc: None,
            })
            .collect();

        out.push(EventDoc {
            id: stable_id("evt", &[&name]),
            anchor: String::new(),
            name,
            doc: doc_comment.and_then(|d| clean_doc(&d, options)),
            topics,
            data,
            content_hash: String::new(),
        });

        rest = &after_marker[body_end..];
    }
}

struct Field {
    name: String,
    type_name: String,
    topic: bool,
}

/// Returns the contiguous `///` doc comment immediately preceding `text`'s
/// end (ignoring blank lines and other attributes directly above).
fn trailing_doc_comment(text: &str) -> Option<String> {
    let mut lines = Vec::new();
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if let Some(doc) = trimmed.strip_prefix("///") {
            lines.push(doc.trim().to_string());
        } else if trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            continue;
        } else {
            break;
        }
    }
    if lines.is_empty() {
        None
    } else {
        lines.reverse();
        Some(lines.join("\n"))
    }
}

/// Finds `keyword` as a standalone identifier in `text`, returning its offset.
fn find_keyword(text: &str, keyword: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(keyword) {
        let start = search_from + rel;
        let end = start + keyword.len();
        let before_ok =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let after_ok =
            end >= bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if before_ok && after_ok {
            return Some(start);
        }
        search_from = end;
    }
    None
}

/// Reads the identifier starting at byte offset `start`, skipping whitespace.
fn ident_at(text: &str, start: usize) -> Option<String> {
    let rest = text.get(start..)?;
    let ident: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        None
    } else {
        Some(ident)
    }
}

/// Collects string literals inside every `#[name("a", "b")]` attribute found
/// in `text`.
fn quoted_idents_after(text: &str, attr: &str) -> Vec<String> {
    let needle = format!("#{attr}");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        if let Some(open) = after.find('(') {
            let close = after[open..].find(')').map(|c| open + c);
            if let Some(close) = close {
                let inner = &after[open + 1..close];
                out.extend(extract_string_literals(inner));
                rest = &after[close..];
                continue;
            }
        }
        rest = after;
    }
    out
}

fn extract_string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, ch) in text.char_indices() {
        if ch == '"' {
            let value: String = text[idx + 1..].chars().take_while(|c| *c != '"').collect();
            out.push(value);
        }
    }
    out
}

/// Given text starting at `{`, returns the balanced brace body (including the
/// braces) and the offset just past the closing brace.
fn balanced_braces(text: &str) -> Option<(String, usize)> {
    let open = text.find('{')?;
    let mut depth = 0usize;
    for (offset, ch) in text[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let end = open + offset + ch.len_utf8();
                    return Some((text[open..end].to_string(), end));
                }
            }
            _ => {}
        }
    }
    None
}

/// Parses `name: Type` pairs from a struct body, honouring `#[topic]`
/// field attributes and skipping nested braces/generics when splitting on
/// commas.
fn parse_struct_fields(body: &str) -> Vec<Field> {
    let inner = body
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or("");
    let mut fields = Vec::new();
    let mut pending_topic = false;

    for segment in split_top_level(inner, ',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if segment.starts_with("#[") {
            // A field attribute (`#[topic]`, `#[data]`, …) may share its
            // comma-segment with the field itself.
            pending_topic = segment.contains("#[topic");
            if let Some(field) = parse_field_pair(segment) {
                fields.push(Field {
                    topic: pending_topic,
                    ..field
                });
                pending_topic = false;
            }
            continue;
        }
        if let Some(field) = parse_field_pair(segment) {
            fields.push(Field {
                topic: pending_topic,
                ..field
            });
            pending_topic = false;
        }
    }
    fields
}

fn parse_field_pair(segment: &str) -> Option<Field> {
    let segment = segment.trim();
    let colon = segment.find(':')?;
    let name: String = segment[..colon]
        .trim()
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if name.is_empty() {
        return None;
    }
    let type_name = segment[colon + 1..]
        .trim()
        .trim_end_matches(',')
        .to_string();
    if type_name.is_empty() {
        return None;
    }
    Some(Field {
        name,
        type_name,
        topic: false,
    })
}

/// Splits `text` on `sep` occurring at bracket depth zero.
fn split_top_level(text: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in text.chars() {
        match ch {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            c if c == sep && depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            c => current.push(c),
        }
    }
    parts.push(current);
    parts
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::docgen::fixtures::{build_spec_wasm, sample_entries};
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecType, ScSpecTypeDef, ScSpecTypeOption,
        ScSymbol, StringM, VecM,
    };

    fn sym(s: &str) -> ScSymbol {
        s.try_into().unwrap()
    }

    fn name(s: &str) -> StringM<60> {
        s.try_into().unwrap()
    }

    fn str1024(s: &str) -> StringM<1024> {
        s.try_into().unwrap()
    }

    fn bare_options() -> ExtractOptions {
        ExtractOptions::default()
    }

    #[test]
    fn builds_functions_errors_and_types_from_spec() {
        let wasm = build_spec_wasm(&sample_entries());
        let kb = build_kb(Path::new("token.wasm"), &wasm, &bare_options()).unwrap();

        assert_eq!(kb.functions.len(), 2);
        let transfer = kb.find_function("fn:transfer").unwrap();
        assert_eq!(
            transfer.signature,
            "(from: Address, to: Address, amount: i128) -> bool"
        );
        assert_eq!(
            transfer.doc.as_deref(),
            Some("Moves `amount` tokens from `from` to `to`.\nCaller must be authorized.")
        );
        assert_eq!(transfer.params[0].doc.as_deref(), Some("Token owner."));

        assert_eq!(kb.errors.len(), 1);
        assert_eq!(kb.errors[0].cases.len(), 2);
        assert_eq!(kb.errors[0].cases[0].code, 1);

        // DataKey is storage-key shaped; Invoice is a plain documented type.
        assert_eq!(kb.storage_keys.len(), 2);
        assert!(kb.storage_keys.iter().all(|k| k.inferred));
        assert_eq!(kb.types.len(), 1);
        assert_eq!(kb.types[0].kind, TypeKind::Struct);
        assert_eq!(kb.summary.functions, 2);
        assert_eq!(kb.summary.documented_functions, 2);
        assert_eq!(kb.summary.error_cases, 2);
        assert_eq!(kb.summary.storage_keys, 2);
        assert_eq!(kb.summary.types, 1);
    }

    #[test]
    fn deployment_requirements_reads_wasm_sections() {
        // A tiny module importing two env functions, exporting a constructor,
        // declaring one memory page and one data segment.
        let wat = r#"
            (module
                (import "env" "log_data" (func))
                (import "v" "not_env" (func))
                (memory 3)
                (data "starforge")
                (func (export "__constructor") )
            )
        "#;
        let wasm = wat::parse_str(wat).unwrap();
        let req = deployment_requirements(&wasm).unwrap();
        assert_eq!(req.wasm_size_bytes, wasm.len() as u64);
        assert_eq!(req.env_imports, vec!["log_data".to_string()]);
        assert_eq!(req.memory_min_pages, Some(3));
        assert_eq!(req.data_segment_count, 1);
        assert_eq!(req.data_segment_bytes, 9);
        assert_eq!(req.init_function.as_deref(), Some("__constructor"));
    }

    #[test]
    fn constructor_params_enriched_from_spec() {
        let mut entries = sample_entries();
        entries.insert(
            0,
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: str1024("Constructs the contract."),
                name: sym("__constructor"),
                inputs: vec![ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "admin".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                }]
                .try_into()
                .unwrap(),
                outputs: VecM::default(),
            }),
        );
        let mut wasm = build_spec_wasm(&entries);
        // Append a constructor export so init_function is detected.
        let export_section: &[u8] = &[
            0x07, // section: export
            0x11, // section length
            0x01, // vector length
            0x0d, // name length
            b'_', b'_', b'c', b'o', b'n', b's', b't', b'r', b'u', b'c', b't', b'o', b'r', 0x00,
            0x00, // kind func, index 0
        ];
        wasm.extend_from_slice(export_section);

        let kb = build_kb(Path::new("c.wasm"), &wasm, &bare_options()).unwrap();
        assert_eq!(
            kb.deployment.init_function.as_deref(),
            Some("__constructor")
        );
        assert_eq!(kb.deployment.init_params.len(), 1);
        assert_eq!(kb.deployment.init_params[0].name, "admin");
    }

    #[test]
    fn source_scan_extracts_contractevents_and_storage_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("lib.rs");
        fs::write(
            &src,
            r#"
            /// Emitted whenever tokens move between accounts.
            #[contractevent]
            #[topic("from")]
            pub struct TransferEvent {
                #[topic]
                from: Address,
                to: Address,
                amount: i128,
            }

            pub fn touch(env: &Env) {
                let _ = env.storage().instance();
                let _ = env.storage().persistent();
            }
            "#,
        )
        .unwrap();

        let scan = scan_source_tree(dir.path(), &bare_options()).unwrap();
        assert_eq!(scan.events.len(), 1);
        let event = &scan.events[0];
        assert_eq!(event.id, "evt:TransferEvent");
        assert_eq!(event.topics.len(), 1);
        assert_eq!(event.topics[0].name, "from");
        assert_eq!(event.topics[0].type_name, "Address");
        assert_eq!(
            event
                .data
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            vec!["to", "amount"]
        );
        assert_eq!(
            event.doc.as_deref(),
            Some("Emitted whenever tokens move between accounts.")
        );
        assert_eq!(
            scan.storage_kinds.keys().cloned().collect::<Vec<_>>(),
            vec!["instance", "persistent"]
        );

        let mut kb = build_kb(Path::new("c.wasm"), &build_spec_wasm(&[]), &{
            let mut o = bare_options();
            o.source_dir = Some(dir.path().to_path_buf());
            o
        })
        .unwrap();
        assert_eq!(kb.events.len(), 1);
        assert!(kb.deployment.source_scanned);
        assert!(kb.source_sha256.is_some());
        kb.finalize();
        assert_eq!(kb.summary.events, 1);
    }

    #[test]
    fn field_level_topic_markers_become_topics_without_container_list() {
        let mut events = Vec::new();
        scan_events(
            r#"
            #[contractevent]
            struct Minted {
                #[topic] holder: Address,
                qty: i128,
            }
            "#,
            &mut events,
            &bare_options(),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].topics[0].name, "holder");
        assert_eq!(events[0].topics[0].type_name, "Address");
        assert_eq!(events[0].data.len(), 1);
        assert_eq!(events[0].data[0].name, "qty");
    }

    #[test]
    fn malformed_event_shapes_are_skipped_not_fatal() {
        let mut events = Vec::new();
        scan_events(
            "#[contractevent]\nlet broken = 1;\n",
            &mut events,
            &bare_options(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn clean_doc_redacts_secrets_and_home_paths() {
        let mut options = bare_options();
        options.home = Some("/home/dev".to_string());
        let doc = clean_doc(
            "built in /home/dev/secrets SCZTJANLGSDROTOSIJDNTIJVGO3M6FBJX7PTKLTCYMS3FAS5DFQGVL2K",
            &options,
        );
        let doc = doc.unwrap();
        assert!(doc.contains("~/secrets"), "{doc}");
        assert!(doc.contains("REDACTED_SECRET"), "{doc}");

        options.no_redact = true;
        let raw = clean_doc("/home/dev/x", &options).unwrap();
        assert_eq!(raw, "/home/dev/x");
    }

    #[test]
    fn empty_docs_collapse_to_none() {
        assert_eq!(clean_doc("", &bare_options()), None);
        assert_eq!(clean_doc("   \n  ", &bare_options()), None);
    }

    #[test]
    fn storage_key_heuristic_matches_upgrade_analyzer_conventions() {
        assert!(looks_like_storage_key_type("DataKey"));
        assert!(looks_like_storage_key_type("StorageKey"));
        assert!(looks_like_storage_key_type("ContractStorageKey"));
        assert!(!looks_like_storage_key_type("Invoice"));
        assert!(!looks_like_storage_key_type("KeyEvent")); // contains key but not storage-prefixed
    }

    #[test]
    fn split_top_level_respects_generics_and_tuples() {
        let parts = split_top_level("a: Map<Address, Vec<u32>>, b: (i128, i128)", ',');
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].trim(), "b: (i128, i128)");
    }

    #[test]
    fn spec_type_names_cover_boxed_variants() {
        let option = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        assert_eq!(spec_type_name(&option), "Option<u32>");
        let udt = ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
            name: name("Invoice"),
        });
        assert_eq!(spec_type_name(&udt), "Invoice");
        assert_eq!(ScSpecType::U32 as i32, 4);
        assert_eq!(ScSpecType::Address as i32, 19);
    }
}
