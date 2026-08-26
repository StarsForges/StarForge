use super::index::source_counts;
use super::model::{
    ContextEntry, ContextKind, GuidanceItem, ProjectIndex, Severity, Workflow, WorkflowRequest,
};

pub fn generate(index: &ProjectIndex, request: &WorkflowRequest) -> (String, Vec<GuidanceItem>) {
    let mut guidance = match request.workflow {
        Workflow::Explain => explain(index, request),
        Workflow::Diagnose => diagnose(index, request),
        Workflow::Suggest => suggest(index, request),
        Workflow::Scaffold => scaffold(index, request),
        Workflow::Review => review(index, request),
    };
    guidance.sort_by_key(|item| severity_rank(item.severity));
    let summary = summary(index, request, &guidance);
    (summary, guidance)
}

fn explain(index: &ProjectIndex, request: &WorkflowRequest) -> Vec<GuidanceItem> {
    let counts = source_counts(&index.entries);
    let manifests = counts
        .get(&ContextKind::CargoManifest)
        .copied()
        .unwrap_or(0);
    let sources = counts
        .get(&ContextKind::ContractSource)
        .copied()
        .unwrap_or(0);
    let tests = counts.get(&ContextKind::Test).copied().unwrap_or(0);
    let mut items = vec![GuidanceItem {
        severity: Severity::Info,
        title: "Project shape".into(),
        detail: format!(
            "{} contains {manifests} Cargo manifest(s), {sources} Rust source file(s), and {tests} indexed test file(s).",
            index.project_name
        ),
        path: None,
        line: None,
    }];

    for entry in contract_entries(index).take(6) {
        let contracts = count_occurrences(&entry.excerpt, "#[contract]");
        let implementations = count_occurrences(&entry.excerpt, "#[contractimpl]");
        let public_functions = entry
            .excerpt
            .lines()
            .filter(|line| line.trim_start().starts_with("pub fn "))
            .count();
        if contracts + implementations + public_functions > 0 {
            items.push(GuidanceItem {
                severity: Severity::Info,
                title: format!("Contract surface in {}", entry.path),
                detail: format!(
                    "Detected {contracts} contract declaration(s), {implementations} implementation block(s), and {public_functions} public function(s). Focus requested: {}.",
                    request.focus.as_deref().unwrap_or("whole project")
                ),
                path: Some(entry.path.clone()),
                line: first_line_containing(&entry.excerpt, "#[contract"),
            });
        }
    }
    if items.len() == 1 {
        items.push(GuidanceItem {
            severity: Severity::Suggestion,
            title: "No Soroban entry point detected".into(),
            detail: "The indexed Rust excerpts do not contain #[contract] or #[contractimpl]. Check exclusions and index size limits if contract sources should be present.".into(),
            path: None,
            line: None,
        });
    }
    items
}

fn diagnose(index: &ProjectIndex, request: &WorkflowRequest) -> Vec<GuidanceItem> {
    let query = request.query.to_ascii_lowercase();
    let mut items = Vec::new();
    if contains_any(
        &query,
        &["compile", "compiler", "rustc", "mismatched", "unresolved"],
    ) {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "Verify SDK and workspace versions".into(),
            detail: "Run `cargo tree -i soroban-sdk` and `cargo check --workspace`. Align soroban-sdk versions across workspace manifests before changing contract logic.".into(),
            path: first_path(index, ContextKind::CargoManifest),
            line: None,
        });
    }
    if contains_any(
        &query,
        &["simulation", "deploy", "transaction", "sequence", "rpc"],
    ) {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "Separate simulation from submission".into(),
            detail: "Confirm the RPC network passphrase, source account sequence, WASM hash, and simulation diagnostics. Re-simulate immediately before signing to avoid stale ledger state.".into(),
            path: first_path(index, ContextKind::DeploymentHistory)
                .or_else(|| first_path(index, ContextKind::Configuration)),
            line: None,
        });
    }
    if contains_any(
        &query,
        &["auth", "unauthorized", "require_auth", "permission"],
    ) {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "Trace authorization identities".into(),
            detail: "Verify the Address passed by the caller is the same identity that invokes require_auth(), and inspect mocked authorization in tests. Do not replace require_auth with caller-supplied booleans.".into(),
            path: find_path_containing(index, "require_auth"),
            line: find_entry_containing(index, "require_auth")
                .and_then(|entry| first_line_containing(&entry.excerpt, "require_auth")),
        });
    }
    if contains_any(
        &query,
        &["budget", "resource", "cpu", "memory", "footprint"],
    ) {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "Inspect resource growth".into(),
            detail: "Measure invocation CPU, memory, event size, and ledger footprint. Bound loops and collection sizes; prefer keyed storage access over scanning stored collections.".into(),
            path: first_path(index, ContextKind::ContractSource),
            line: None,
        });
    }
    if items.is_empty() {
        items.extend(generic_diagnostic_steps(index, request));
    }
    items.push(GuidanceItem {
        severity: Severity::Info,
        title: "Reproduce deterministically".into(),
        detail: "Capture the exact command, sanitized error, network, toolchain versions, and smallest failing test. Compare behavior with `--offline` guidance before involving a provider.".into(),
        path: first_path(index, ContextKind::Test),
        line: None,
    });
    items
}

fn generic_diagnostic_steps(index: &ProjectIndex, request: &WorkflowRequest) -> Vec<GuidanceItem> {
    vec![GuidanceItem {
        severity: Severity::Suggestion,
        title: "Narrow the failing boundary".into(),
        detail: format!(
            "For {:?}, reproduce with the smallest relevant unit test, then distinguish compilation, host execution, RPC simulation, and transaction submission failures. The reported symptom was retained only in this response context.",
            request.workflow
        ),
        path: first_path(index, ContextKind::Test)
            .or_else(|| first_path(index, ContextKind::ContractSource)),
        line: None,
    }]
}

fn suggest(index: &ProjectIndex, request: &WorkflowRequest) -> Vec<GuidanceItem> {
    let mut items = Vec::new();
    let query = request.query.to_ascii_lowercase();
    let manifest = first_path(index, ContextKind::CargoManifest);

    if contains_any(&query, &["token", "balance", "transfer"]) {
        items.push(GuidanceItem {
            severity: Severity::Suggestion,
            title: "Model balances as keyed persistent storage".into(),
            detail: "Use a typed DataKey containing Address, authenticate the debited address with require_auth(), use checked arithmetic, and extend persistent TTL when balances are accessed.".into(),
            path: first_path(index, ContextKind::ContractSource),
            line: None,
        });
    }
    if contains_any(&query, &["admin", "owner", "upgrade", "governance"]) {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "Make privileged transitions explicit".into(),
            detail: "Store the administrator as an Address, require its authorization on every privileged path, emit an event for changes, and test unauthorized, repeated, and transferred-admin cases.".into(),
            path: first_path(index, ContextKind::ContractSource),
            line: None,
        });
    }
    if contains_any(&query, &["event", "index", "history"]) {
        items.push(GuidanceItem {
            severity: Severity::Suggestion,
            title: "Design bounded event topics".into(),
            detail: "Keep topics stable and compact, put large payloads in event data, and document event versioning for downstream indexers.".into(),
            path: first_path(index, ContextKind::ContractSource),
            line: None,
        });
    }
    items.push(GuidanceItem {
        severity: Severity::Info,
        title: "Match the workspace conventions".into(),
        detail: "Add the implementation beside the nearest contract crate, reuse its soroban-sdk version and feature flags, and mirror its unit-test setup. Validate with cargo fmt, check, test, and clippy.".into(),
        path: manifest,
        line: None,
    });
    items
}

fn scaffold(index: &ProjectIndex, request: &WorkflowRequest) -> Vec<GuidanceItem> {
    let requested_name = sanitize_name(request.focus.as_deref().unwrap_or_else(|| {
        request
            .query
            .split_whitespace()
            .last()
            .unwrap_or("contract")
    }));
    let workspace = index.entries.iter().find(|entry| {
        entry.kind == ContextKind::CargoManifest && entry.excerpt.contains("[workspace]")
    });
    let base = if workspace.is_some() {
        format!("contracts/{requested_name}")
    } else {
        requested_name.clone()
    };
    vec![
        GuidanceItem {
            severity: Severity::Suggestion,
            title: format!("Create {base}/Cargo.toml"),
            detail: "Declare a cdylib/rlib crate, inherit compatible workspace dependencies where available, and keep testutils in dev-dependencies or test-only features.".into(),
            path: workspace.map(|entry| entry.path.clone()),
            line: None,
        },
        GuidanceItem {
            severity: Severity::Suggestion,
            title: format!("Create {base}/src/lib.rs"),
            detail: "Define typed DataKey and Error enums, a #[contract] type, and a #[contractimpl] block. Keep authorization, validation, state mutation, and events visible at each entry point.".into(),
            path: None,
            line: None,
        },
        GuidanceItem {
            severity: Severity::Suggestion,
            title: format!("Create {base}/src/test.rs"),
            detail: "Cover initialization, successful calls, authorization failures, boundary arithmetic, duplicate operations, TTL-sensitive state, and emitted events using Env::default().".into(),
            path: first_path(index, ContextKind::Test),
            line: None,
        },
        GuidanceItem {
            severity: Severity::Info,
            title: "Validate the scaffold".into(),
            detail: format!(
                "Run `cargo fmt --all --check`, `cargo test -p {requested_name}`, and `cargo clippy -p {requested_name} --all-targets -- -D warnings`. This command returns a plan and does not write files."
            ),
            path: None,
            line: None,
        },
    ]
}

fn review(index: &ProjectIndex, _request: &WorkflowRequest) -> Vec<GuidanceItem> {
    let mut items = Vec::new();
    for entry in contract_entries(index) {
        review_entry(entry, &mut items);
    }
    if items.is_empty() {
        items.push(GuidanceItem {
            severity: Severity::Info,
            title: "No deterministic high-signal findings".into(),
            detail: "The local rules found no obvious unwrap/panic, unchecked arithmetic, unbounded loop, or privileged mutation patterns in indexed excerpts. This is not proof of safety; run tests and a manual review.".into(),
            path: first_path(index, ContextKind::ContractSource),
            line: None,
        });
    }
    if first_path(index, ContextKind::Test).is_none() {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "No tests indexed".into(),
            detail: "Add tests for authorization failures, invalid state transitions, arithmetic boundaries, repeated calls, events, and storage lifetime.".into(),
            path: None,
            line: None,
        });
    }
    items
}

fn review_entry(entry: &ContextEntry, items: &mut Vec<GuidanceItem>) {
    for (needle, severity, title, detail) in [
        (
            ".unwrap()",
            Severity::Warning,
            "Potential contract panic",
            "Avoid unwrap() on caller-controlled or storage-derived values. Return a typed contract error so failure behavior remains stable.",
        ),
        (
            "panic!(",
            Severity::Warning,
            "Explicit panic path",
            "Prefer panic_with_error! with a documented contract error, or return Result when the public interface permits it.",
        ),
        (
            "unsafe {",
            Severity::Critical,
            "Unsafe Rust in contract source",
            "Remove or tightly justify unsafe code. Review memory assumptions against the WASM target and add focused tests.",
        ),
    ] {
        if let Some(line) = first_line_containing(&entry.excerpt, needle) {
            items.push(GuidanceItem {
                severity,
                title: title.into(),
                detail: detail.into(),
                path: Some(entry.path.clone()),
                line: Some(line),
            });
        }
    }

    for (line_index, line) in entry.excerpt.lines().enumerate() {
        let trimmed = line.trim();
        if (trimmed.starts_with("for ") || trimmed.starts_with("while "))
            && !trimmed.contains(".take(")
        {
            items.push(GuidanceItem {
                severity: Severity::Warning,
                title: "Review loop bounds".into(),
                detail: "Ensure iteration cannot grow with untrusted or permanently accumulated state; Soroban resource limits make unbounded loops a denial-of-service risk.".into(),
                path: Some(entry.path.clone()),
                line: Some(line_index + 1),
            });
            break;
        }
    }

    let has_state_write = entry.excerpt.contains("storage().persistent().set")
        || entry.excerpt.contains("storage().instance().set")
        || entry.excerpt.contains("storage().temporary().set");
    let has_auth = entry.excerpt.contains("require_auth")
        || entry.excerpt.contains("authorize_as_current_contract");
    if has_state_write && !has_auth {
        items.push(GuidanceItem {
            severity: Severity::Warning,
            title: "State mutation without visible authorization".into(),
            detail: "No authorization call appears in this indexed source excerpt. Confirm mutations are intentionally public or require the responsible Address before writing state.".into(),
            path: Some(entry.path.clone()),
            line: first_line_containing(&entry.excerpt, ".set("),
        });
    }
    if entry.excerpt.contains("storage().persistent()")
        && !entry.excerpt.contains("extend_ttl")
        && !entry.excerpt.contains("extend_ttl_for")
    {
        items.push(GuidanceItem {
            severity: Severity::Suggestion,
            title: "Persistent storage TTL is not extended".into(),
            detail: "Define and apply a storage lifetime policy where persistent entries must remain available. Add restoration/expiry tests if expiration is intentional.".into(),
            path: Some(entry.path.clone()),
            line: first_line_containing(&entry.excerpt, "storage().persistent()"),
        });
    }
}

fn summary(index: &ProjectIndex, request: &WorkflowRequest, items: &[GuidanceItem]) -> String {
    let critical = items
        .iter()
        .filter(|item| item.severity == Severity::Critical)
        .count();
    let warnings = items
        .iter()
        .filter(|item| item.severity == Severity::Warning)
        .count();
    format!(
        "Deterministic {} guidance for {} used {} indexed file(s): {} item(s), {warnings} warning(s), {critical} critical finding(s).",
        request.workflow.name(),
        index.project_name,
        index.entries.len(),
        items.len()
    )
}

fn contract_entries(index: &ProjectIndex) -> impl Iterator<Item = &ContextEntry> {
    index
        .entries
        .iter()
        .filter(|entry| entry.kind == ContextKind::ContractSource)
}

fn first_path(index: &ProjectIndex, kind: ContextKind) -> Option<String> {
    index
        .entries
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.path.clone())
}

fn find_entry_containing<'a>(index: &'a ProjectIndex, needle: &str) -> Option<&'a ContextEntry> {
    index
        .entries
        .iter()
        .find(|entry| entry.excerpt.contains(needle))
}

fn find_path_containing(index: &ProjectIndex, needle: &str) -> Option<String> {
    find_entry_containing(index, needle).map(|entry| entry.path.clone())
}

fn first_line_containing(text: &str, needle: &str) -> Option<usize> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|line| line + 1)
}

fn count_occurrences(text: &str, needle: &str) -> usize {
    text.match_indices(needle).count()
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn sanitize_name(value: &str) -> String {
    let value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    value.trim_matches('-').replace('_', "-").to_string()
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::Warning => 1,
        Severity::Suggestion => 2,
        Severity::Info => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ai::assistant::model::IndexSummary;

    fn index_with_source(source: &str) -> ProjectIndex {
        ProjectIndex {
            schema_version: 1,
            generated_at: "now".into(),
            project_name: "demo".into(),
            entries: vec![ContextEntry {
                path: "src/lib.rs".into(),
                kind: ContextKind::ContractSource,
                size_bytes: source.len() as u64,
                digest: "sha256:test".into(),
                excerpt: source.into(),
                redactions: 0,
            }],
            summary: IndexSummary::default(),
        }
    }

    #[test]
    fn review_reports_panic_auth_and_ttl_findings() {
        let index = index_with_source(
            "pub fn set(env: Env) { let x = value.unwrap(); env.storage().persistent().set(&1, &x); }",
        );
        let (_, items) = generate(
            &index,
            &WorkflowRequest {
                workflow: Workflow::Review,
                query: "review".into(),
                focus: None,
            },
        );
        assert!(items.iter().any(|item| item.title.contains("panic")));
        assert!(items
            .iter()
            .any(|item| item.title.contains("authorization")));
        assert!(items.iter().any(|item| item.title.contains("TTL")));
    }

    #[test]
    fn diagnose_is_deterministic() {
        let index = index_with_source("pub fn hello() {}");
        let request = WorkflowRequest {
            workflow: Workflow::Diagnose,
            query: "simulation failed during deploy".into(),
            focus: None,
        };
        assert_eq!(generate(&index, &request), generate(&index, &request));
    }
}
