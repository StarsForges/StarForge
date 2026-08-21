//! Deterministic Markdown rendering of a [`KnowledgeBase`].
//!
//! The renderer is a pure function of the knowledge base: identical input
//! always produces byte-identical output, which is what makes doc diffs and
//! CI staleness gates reliable. Every section heading is preceded by an
//! explicit HTML anchor so cross-links remain stable across Markdown
//! renderers whose auto-slug algorithms differ.

use crate::utils::docgen::model::{
    ErrorEnumDoc, EventDoc, FunctionDoc, KnowledgeBase, StorageKeyDoc, TypeDoc,
};
use std::collections::BTreeSet;

/// Renders the complete reference document for a knowledge base.
pub fn render_markdown(kb: &KnowledgeBase) -> String {
    let mut md = String::new();
    let known_types = known_type_names(kb);

    md.push_str(&format!("# {} Reference\n\n", kb.project.name));
    render_metadata(&mut md, kb);
    render_toc(&mut md, kb);

    if !kb.functions.is_empty() {
        md.push_str("## Functions\n\n");
        for f in &kb.functions {
            render_function(&mut md, f, &known_types, kb);
        }
    }

    if !kb.events.is_empty() {
        md.push_str("## Events\n\n");
        md.push_str(
            "> Events are recovered heuristically from `#[contractevent]` \
             definitions in the scanned source tree.\n\n",
        );
        for e in &kb.events {
            render_event(&mut md, e);
        }
    }

    if !kb.errors.is_empty() {
        md.push_str("## Errors\n\n");
        for e in &kb.errors {
            render_error_enum(&mut md, e);
        }
    }

    if !kb.storage_keys.is_empty() {
        md.push_str("## Storage Keys\n\n");
        md.push_str(
            "> Storage keys are inferred from types conventionally named \
             `DataKey`/`StorageKey`; they are not confirmed by contract \
             metadata.\n\n",
        );
        for k in &kb.storage_keys {
            render_storage_key(&mut md, k);
        }
    }

    if !kb.types.is_empty() {
        md.push_str("## Types\n\n");
        for t in &kb.types {
            render_type(&mut md, t);
        }
    }

    render_deployment(&mut md, kb);
    md
}

fn render_metadata(md: &mut String, kb: &KnowledgeBase) {
    md.push_str("| Field | Value |\n|---|---|\n");
    md.push_str(&format!(
        "| Artifact | `{}` ({} bytes) |\n",
        kb.artifact.file_name, kb.artifact.size_bytes
    ));
    md.push_str(&format!(
        "| Artifact SHA-256 | `{}` |\n",
        kb.artifact.sha256
    ));
    if let Some(version) = &kb.project.version {
        md.push_str(&format!("| Version | {version} |\n"));
    }
    if let Some(license) = &kb.project.license {
        md.push_str(&format!("| License | {license} |\n"));
    }
    if let Some(repo) = &kb.project.repository {
        md.push_str(&format!("| Repository | {repo} |\n"));
    }
    md.push_str(&format!(
        "| Generator | {} v{} (schema {}) |\n",
        kb.generator, kb.generator_version, kb.schema_version
    ));
    md.push_str(&format!("| Fingerprint | `{}` |\n", kb.fingerprint()));
    if let Some(ts) = &kb.generated_at {
        md.push_str(&format!("| Generated | {ts} |\n"));
    }
    md.push('\n');
}

fn render_toc(md: &mut String, kb: &KnowledgeBase) {
    md.push_str("## Contents\n\n");
    if !kb.functions.is_empty() {
        md.push_str("- [Functions](#functions)\n");
        for f in &kb.functions {
            md.push_str(&format!("  - [`{}`](#{})\n", f.name, f.anchor));
        }
    }
    if !kb.events.is_empty() {
        md.push_str("- [Events](#events)\n");
        for e in &kb.events {
            md.push_str(&format!("  - [`{}`](#{})\n", e.name, e.anchor));
        }
    }
    if !kb.errors.is_empty() {
        md.push_str("- [Errors](#errors)\n");
        for e in &kb.errors {
            md.push_str(&format!("  - [`{}`](#{})\n", e.name, e.anchor));
        }
    }
    if !kb.storage_keys.is_empty() {
        md.push_str("- [Storage Keys](#storage-keys)\n");
    }
    if !kb.types.is_empty() {
        md.push_str("- [Types](#types)\n");
        for t in &kb.types {
            md.push_str(&format!("  - [`{}`](#{})\n", t.name, t.anchor));
        }
    }
    md.push_str("- [Deployment Requirements](#deployment-requirements)\n");
    md.push('\n');
}

fn render_function(
    md: &mut String,
    f: &FunctionDoc,
    known_types: &BTreeSet<String>,
    kb: &KnowledgeBase,
) {
    push_anchor(md, &f.anchor);
    md.push_str(&format!("### `{}`\n\n", f.name));

    md.push_str("```text\n");
    md.push_str(&format!("{}{}\n", f.name, f.signature));
    md.push_str("```\n\n");

    if let Some(doc) = &f.doc {
        md.push_str(doc);
        md.push_str("\n\n");
    }

    if !f.params.is_empty() {
        md.push_str("| Parameter | Type | Description |\n|---|---|---|\n");
        for p in &f.params {
            md.push_str(&format!(
                "| `{}` | {} | {} |\n",
                p.name,
                linked_type(&p.type_name, known_types, kb),
                p.doc.as_deref().unwrap_or("—")
            ));
        }
        md.push('\n');
    }

    if !f.outputs.is_empty() && f.outputs != ["()"] {
        let rendered = f
            .outputs
            .iter()
            .map(|o| linked_type(o, known_types, kb))
            .collect::<Vec<_>>()
            .join(", ");
        md.push_str(&format!("**Returns:** {rendered}\n\n"));
    }

    for example in &f.examples {
        match &example.title {
            Some(title) => md.push_str(&format!("#### {title}\n\n")),
            None => md.push_str("#### Example\n\n"),
        }
        md.push_str("```rust\n");
        md.push_str(example.code.trim_end());
        md.push_str("\n```\n\n");
    }

    if let Some(explanation) = &f.explanation {
        md.push_str("> **How it works**\n>\n");
        for line in explanation.lines() {
            md.push_str(&format!("> {line}\n"));
        }
        md.push('\n');
    }
}

fn render_event(md: &mut String, e: &EventDoc) {
    push_anchor(md, &e.anchor);
    md.push_str(&format!("### `{}`\n\n", e.name));
    if let Some(doc) = &e.doc {
        md.push_str(doc);
        md.push_str("\n\n");
    }
    if !e.topics.is_empty() {
        md.push_str(&format!(
            "**Topics:** {}\n\n",
            e.topics
                .iter()
                .map(|t| format!("`{}` ({})", t.name, t.type_name))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !e.data.is_empty() {
        md.push_str(&format!(
            "**Data:** {}\n\n",
            e.data
                .iter()
                .map(|d| format!("`{}` ({})", d.name, d.type_name))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_error_enum(md: &mut String, e: &ErrorEnumDoc) {
    push_anchor(md, &e.anchor);
    md.push_str(&format!("### `{}`\n\n", e.name));
    if let Some(doc) = &e.doc {
        md.push_str(doc);
        md.push_str("\n\n");
    }
    md.push_str("| Code | Name | Description |\n|---|---|---|\n");
    for case in &e.cases {
        md.push_str(&format!(
            "| {} | `{}` | {} |\n",
            case.code,
            case.name,
            case.doc.as_deref().unwrap_or("—")
        ));
    }
    md.push('\n');
}

fn render_storage_key(md: &mut String, k: &StorageKeyDoc) {
    push_anchor(md, &k.anchor);
    md.push_str(&format!(
        "### `{}::{}`\n\n",
        k.key_type,
        k.case.as_deref().unwrap_or("")
    ));
    md.push_str(&format!(
        "Kind: `{}`, shape: `{}` (inferred)\n\n",
        k.kind.as_str(),
        k.shape
    ));
}

fn render_type(md: &mut String, t: &TypeDoc) {
    push_anchor(md, &t.anchor);
    md.push_str(&format!("### `{}`\n\n", t.name));
    if let Some(doc) = &t.doc {
        md.push_str(doc);
        md.push_str("\n\n");
    }
    md.push_str(&format!("```text\n{}\n```\n\n", t.summary));
}

fn render_deployment(md: &mut String, kb: &KnowledgeBase) {
    md.push_str("## Deployment Requirements\n\n");
    let d = &kb.deployment;
    md.push_str(&format!("- WASM size: {} bytes\n", d.wasm_size_bytes));
    if d.env_imports.is_empty() {
        md.push_str("- Host imports (`env`): none\n");
    } else {
        md.push_str(&format!(
            "- Host imports (`env`): {}\n",
            d.env_imports
                .iter()
                .map(|i| format!("`{i}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    match d.memory_min_pages {
        Some(pages) => md.push_str(&format!("- Memory: minimum {pages} page(s)\n")),
        None => md.push_str("- Memory: none declared\n"),
    }
    md.push_str(&format!(
        "- Data segments: {} ({} bytes)\n",
        d.data_segment_count, d.data_segment_bytes
    ));
    match (&d.init_function, d.init_params.is_empty()) {
        (Some(init), true) => md.push_str(&format!("- Constructor: `{init}`\n")),
        (Some(init), false) => {
            md.push_str(&format!("- Constructor: `{init}` with parameters:\n\n"));
            md.push_str("| Parameter | Type | Description |\n|---|---|---|\n");
            for p in &d.init_params {
                md.push_str(&format!(
                    "| `{}` | `{}` | {} |\n",
                    p.name,
                    p.type_name,
                    p.doc.as_deref().unwrap_or("—")
                ));
            }
            md.push('\n');
        }
        (None, _) => md.push_str("- Constructor: not detected\n"),
    }
    if d.source_scanned {
        if d.storage_kinds.is_empty() {
            md.push_str("- Storage durability kinds observed in source: none\n");
        } else {
            md.push_str(&format!(
                "- Storage durability kinds observed in source: {}\n",
                d.storage_kinds
                    .iter()
                    .map(|k| format!("`{k}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    md.push('\n');
}

fn push_anchor(md: &mut String, anchor: &str) {
    md.push_str(&format!("<a id=\"{anchor}\"></a>\n\n"));
}

/// Names of user-defined types and error enums available as link targets.
fn known_type_names(kb: &KnowledgeBase) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = kb.types.iter().map(|t| t.name.clone()).collect();
    names.extend(kb.errors.iter().map(|e| e.name.clone()));
    names.extend(kb.storage_keys.iter().map(|k| k.key_type.clone()));
    names
}

/// Renders a type name, linking user-defined types to their anchors. For
/// composite types only the outermost generic parameter path is considered;
/// primitives are left untouched.
fn linked_type(type_name: &str, known_types: &BTreeSet<String>, kb: &KnowledgeBase) -> String {
    let base = type_name
        .split(['<', '>', ',', '(', ')', ' ', ':'])
        .find(|s| !s.is_empty())
        .unwrap_or(type_name);
    if let Some(t) = kb.types.iter().find(|t| t.name == base) {
        return format!("[`{type_name}`](#{})", t.anchor);
    }
    if let Some(e) = kb.errors.iter().find(|e| e.name == base) {
        return format!("[`{type_name}`](#{})", e.anchor);
    }
    if known_types.contains(base) {
        // Storage-key containers have per-case anchors; link the container
        // heading produced by the first matching key.
        if let Some(k) = kb.storage_keys.iter().find(|k| k.key_type == base) {
            return format!("[`{type_name}`](#{})", k.anchor);
        }
    }
    format!("`{type_name}`")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::docgen::extract::{build_kb, ExtractOptions};
    use crate::utils::docgen::fixtures::{build_spec_wasm, sample_entries};
    use crate::utils::docgen::model::ProjectMeta;
    use std::path::Path;

    fn sample_kb() -> KnowledgeBase {
        // Build a KB from the same synthetic spec used by extract tests.
        let wasm = build_spec_wasm(&sample_entries());
        build_kb(
            Path::new("token.wasm"),
            &wasm,
            &ExtractOptions {
                project: ProjectMeta {
                    name: "token".to_string(),
                    version: Some("1.2.3".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn rendering_is_deterministic() {
        let a = render_markdown(&sample_kb());
        let b = render_markdown(&sample_kb());
        assert_eq!(a, b);
    }

    #[test]
    fn renders_all_sections_with_anchors_and_links() {
        let md = render_markdown(&sample_kb());
        assert!(md.contains("# token Reference"));
        assert!(md.contains("<a id=\"fn-transfer\"></a>"));
        assert!(md.contains("(from: Address, to: Address, amount: i128) -> bool"));
        assert!(md.contains("[Errors](#errors)"));
        assert!(md.contains("## Deployment Requirements"));
        // Primitives stay plain text.
        assert!(md.contains("`Address`"));
        assert!(!md.contains("[`Address`](#"));
        // User-defined types get cross-linked from the Types section listing.
        assert!(md.contains("<a id=\"type-invoice\"></a>"));
        assert!(md.contains("<a id=\"err-contracterror\"></a>"));
        // Error enum table includes codes.
        assert!(md.contains("| 1 | `InsufficientBalance` |"));
    }

    #[test]
    fn empty_kb_renders_header_and_deployment_only() {
        let wasm = build_spec_wasm(&[]);
        let kb = build_kb(Path::new("empty.wasm"), &wasm, &ExtractOptions::default()).unwrap();
        let md = render_markdown(&kb);
        assert!(md.starts_with("# "));
        assert!(!md.contains("## Functions"));
        assert!(md.contains("## Deployment Requirements"));
        assert!(md.contains("Constructor: not detected"));
    }
}
