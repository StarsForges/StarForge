//! Structural diffing of two knowledge bases.
//!
//! Entries are matched by their stable IDs (`fn:transfer`,
//! `err:ContractError::InsufficientBalance`, …) and compared by content
//! hash, so the diff reflects *documentation-relevant* changes only: AI
//! explanations and other regenerable prose never show up as churn.

use crate::utils::docgen::model::{KnowledgeBase, KB_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

impl ChangeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryChange {
    pub kind: ChangeKind,
    /// Stable entry ID such as `fn:transfer`.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<String>,
    /// Whether the change breaks documented consumers. Computed during the
    /// diff (see [`diff_kbs`]) rather than re-derived from the kind, so a
    /// doc-only edit to a function is distinguishable from a signature
    /// change.
    pub breaking: bool,
}

impl EntryChange {
    /// Whether this change breaks documented consumers.
    pub fn is_breaking(&self) -> bool {
        self.breaking
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub breaking: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema_version: String,
    pub baseline_fingerprint: String,
    pub candidate_fingerprint: String,
    pub summary: DiffSummary,
    pub changes: Vec<EntryChange>,
}

/// Diffs `baseline` against `candidate` by stable entry ID.
pub fn diff_kbs(baseline: &KnowledgeBase, candidate: &KnowledgeBase) -> DiffReport {
    let old = baseline.entry_hashes();
    let new = candidate.entry_hashes();

    let mut ids: Vec<String> = old.keys().chain(new.keys()).cloned().collect();
    ids.sort();
    ids.dedup();

    let mut changes = Vec::new();
    for id in ids {
        match (old.get(&id), new.get(&id)) {
            (Some(old_hash), Some(new_hash)) if old_hash != new_hash => {
                // A function entry whose signature is untouched changed only
                // its docs — worth surfacing, but not breaking for callers.
                let breaking = if id.starts_with("fn:") {
                    match (baseline.find_function(&id), candidate.find_function(&id)) {
                        (Some(old_f), Some(new_f)) => old_f.signature != new_f.signature,
                        _ => true,
                    }
                } else {
                    false
                };
                changes.push(EntryChange {
                    kind: ChangeKind::Changed,
                    id,
                    old_hash: Some(old_hash.clone()),
                    new_hash: Some(new_hash.clone()),
                    breaking,
                });
            }
            (Some(old_hash), None) => {
                let breaking = id.starts_with("fn:");
                changes.push(EntryChange {
                    kind: ChangeKind::Removed,
                    id,
                    old_hash: Some(old_hash.clone()),
                    new_hash: None,
                    breaking,
                });
            }
            (None, Some(new_hash)) => changes.push(EntryChange {
                kind: ChangeKind::Added,
                id,
                old_hash: None,
                new_hash: Some(new_hash.clone()),
                breaking: false,
            }),
            _ => {}
        }
    }

    let summary = DiffSummary {
        added: changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Added)
            .count(),
        removed: changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Removed)
            .count(),
        changed: changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Changed)
            .count(),
        breaking: changes.iter().filter(|c| c.is_breaking()).count(),
    };

    DiffReport {
        schema_version: KB_SCHEMA_VERSION.to_string(),
        baseline_fingerprint: baseline.fingerprint(),
        candidate_fingerprint: candidate.fingerprint(),
        summary,
        changes,
    }
}

impl DiffReport {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Renders the report as deterministic Markdown.
    pub fn to_markdown(&self) -> String {
        let mut md = String::from("# Knowledge Base Diff\n\n");
        md.push_str("| Metric | Count |\n|---|---|\n");
        md.push_str(&format!("| Added | {} |\n", self.summary.added));
        md.push_str(&format!("| Removed | {} |\n", self.summary.removed));
        md.push_str(&format!("| Changed | {} |\n", self.summary.changed));
        md.push_str(&format!("| Breaking | {} |\n\n", self.summary.breaking));

        if self.is_empty() {
            md.push_str("No documentation-relevant differences found.\n");
            return md;
        }

        md.push_str("| Change | Entry | Breaking |\n|---|---|---|\n");
        for change in &self.changes {
            md.push_str(&format!(
                "| {} | `{}` | {} |\n",
                change.kind.as_str(),
                change.id,
                if change.is_breaking() { "yes" } else { "no" }
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
    use stellar_xdr::curr::{ScSpecFunctionInputV0, ScSpecTypeDef, ScSymbol, StringM};

    fn kb_from(entries: &[stellar_xdr::curr::ScSpecEntry]) -> KnowledgeBase {
        build_kb(
            Path::new("token.wasm"),
            &build_spec_wasm(entries),
            &ExtractOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn identical_contracts_produce_empty_diff() {
        let entries = sample_entries();
        let report = diff_kbs(&kb_from(&entries), &kb_from(&entries));
        assert!(report.is_empty());
        assert_eq!(report.summary, DiffSummary::default());
        assert!(report.to_markdown().contains("No documentation-relevant"));
    }

    #[test]
    fn removed_function_is_breaking() {
        let base = kb_from(&sample_entries());
        let without_transfer: Vec<_> = sample_entries()
            .into_iter()
            .filter(|e| !matches!(e, stellar_xdr::curr::ScSpecEntry::FunctionV0(f) if f.name.to_string() == "transfer"))
            .collect();
        let candidate = kb_from(&without_transfer);

        let report = diff_kbs(&base, &candidate);
        assert_eq!(report.summary.removed, 1);
        assert_eq!(report.summary.breaking, 1);
        assert_eq!(report.summary.added, 0);
        assert_eq!(
            report.changes[0].id, "fn:transfer",
            "changes are sorted by stable ID"
        );
        assert!(report
            .to_markdown()
            .contains("removed | `fn:transfer` | yes"));
    }

    #[test]
    fn signature_change_is_breaking_doc_only_change_is_not() {
        let mut changed = sample_entries();
        for entry in &mut changed {
            if let stellar_xdr::curr::ScSpecEntry::FunctionV0(f) = entry {
                if f.name.to_string() == "balance" {
                    f.inputs = vec![ScSpecFunctionInputV0 {
                        doc: StringM::default(),
                        name: "holder".try_into().unwrap(),
                        type_: ScSpecTypeDef::Address,
                    }]
                    .try_into()
                    .unwrap();
                }
            }
        }
        let report = diff_kbs(&kb_from(&sample_entries()), &kb_from(&changed));
        assert_eq!(report.summary.changed, 1);
        assert_eq!(report.summary.breaking, 1);
        assert_eq!(report.changes[0].id, "fn:balance");

        // A doc-only edit changes hashes but is not breaking.
        let mut docs_only = sample_entries();
        for entry in &mut docs_only {
            if let stellar_xdr::curr::ScSpecEntry::FunctionV0(f) = entry {
                if f.name.to_string() == "balance" {
                    f.doc = str1024("Updated description.");
                }
            }
        }
        let report = diff_kbs(&kb_from(&sample_entries()), &kb_from(&docs_only));
        assert_eq!(report.summary.changed, 1);
        assert_eq!(report.summary.breaking, 0);
    }

    #[test]
    fn explanation_edits_never_appear_in_diff() {
        let mut base = kb_from(&sample_entries());
        let mut candidate = kb_from(&sample_entries());
        candidate.functions[0].explanation = Some("AI narrative".to_string());
        candidate.functions[0].explanation_source =
            Some(crate::utils::docgen::model::ExplanationSource::Ai);
        base.finalize();
        candidate.finalize();
        assert!(diff_kbs(&base, &candidate).is_empty());
    }

    fn str1024(s: &str) -> StringM<1024> {
        s.try_into().unwrap()
    }

    fn sym(s: &str) -> ScSymbol {
        s.try_into().unwrap()
    }
}
