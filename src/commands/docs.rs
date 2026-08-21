//! `starforge docs` — automated documentation generation and knowledge base
//! workflows for Soroban contracts (issue AI-014).
//!
//! Subcommands map one-to-one onto the stages in [`crate::utils::docgen`]:
//! `generate` extracts and renders, `validate` enforces quality/integrity
//! gates, `diff` compares two knowledge bases, `stale` detects documentation
//! that no longer matches a contract artifact, and `publish-preview` emits a
//! deterministic review bundle.

use crate::commands::ai::impact::redactor::redact_text as ai_redact_text;
use crate::utils::docgen::{self, model};
use crate::utils::{config, print as p};
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_OUT_DIR: &str = "docs";
const DEFAULT_PREVIEW_DIR: &str = "docs-preview";
const KB_FILE: &str = "kb.json";

#[derive(Subcommand)]
pub enum DocsCommands {
    /// Generate a documentation knowledge base from a compiled contract
    Generate {
        /// Path to the compiled contract WASM file
        wasm: PathBuf,

        /// Optional Rust source tree scanned for events and storage kinds
        #[arg(long)]
        source: Option<PathBuf>,

        /// Directory that receives the generated artifacts
        #[arg(long, default_value = DEFAULT_OUT_DIR)]
        out: PathBuf,

        /// Artifact formats to emit: md, json, or both
        #[arg(long, default_value = "both", value_parser = ["md", "json", "both"])]
        format: String,

        /// Project name recorded in the docs (default: WASM file stem)
        #[arg(long)]
        project_name: Option<String>,

        /// Project version recorded in the docs
        #[arg(long)]
        version: Option<String>,

        /// Project license recorded in the docs
        #[arg(long)]
        license: Option<String>,

        /// Project repository recorded in the docs
        #[arg(long)]
        repository: Option<String>,

        /// Embed a generation timestamp (breaks byte-for-byte determinism)
        #[arg(long)]
        timestamp: bool,

        /// Disable redaction of secrets and home paths (explicit opt-out)
        #[arg(long)]
        no_redact: bool,

        /// Augment functions with AI explanations where an API key is
        /// configured; all other functions keep deterministic templates
        #[arg(long)]
        ai: bool,

        /// Model used for AI explanations
        #[arg(long, default_value = "gpt-4")]
        model: String,
    },

    /// Validate a knowledge base: schema integrity plus documentation-quality
    /// gates suitable for CI
    Validate {
        /// Path to a kb.json produced by `docs generate`
        kb_json: PathBuf,

        /// Fail when function documentation coverage is below this percent
        #[arg(long, default_value_t = 0.0)]
        min_coverage: f64,

        /// Treat missing function docs as errors instead of warnings
        #[arg(long)]
        require_function_docs: bool,

        /// Treat missing error-case docs as errors instead of warnings
        #[arg(long)]
        require_error_docs: bool,

        /// Treat missing parameter docs as errors instead of warnings
        #[arg(long)]
        require_param_docs: bool,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
    },

    /// Structurally compare two knowledge bases by stable entry IDs
    Diff {
        /// Baseline kb.json (e.g. the committed docs)
        baseline: PathBuf,

        /// Candidate kb.json (e.g. freshly generated)
        candidate: PathBuf,

        /// Output format: markdown or json
        #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
        format: String,

        /// Exit non-zero when the diff contains breaking changes
        #[arg(long)]
        fail_on_breaking: bool,
    },

    /// Detect documentation that no longer matches a contract artifact
    Stale {
        /// Current contract WASM
        wasm: PathBuf,

        /// Committed kb.json to check against the contract
        kb_json: PathBuf,

        /// Source tree scanned during generation, if any; keeps event and
        /// storage-kind comparisons apples-to-apples
        #[arg(long)]
        source: Option<PathBuf>,

        /// Output format: human or json
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,

        /// Report stale documentation without failing (gate disabled)
        #[arg(long)]
        allow_stale: bool,
    },

    /// Render a deterministic preview bundle (Markdown + JSON + manifest)
    /// for review before publishing
    PublishPreview {
        /// Path to a kb.json produced by `docs generate`
        kb_json: PathBuf,

        /// Directory that receives the preview bundle
        #[arg(long, default_value = DEFAULT_PREVIEW_DIR)]
        out: PathBuf,
    },
}

pub fn handle(cmd: DocsCommands) -> Result<()> {
    match cmd {
        DocsCommands::Generate {
            wasm,
            source,
            out,
            format,
            project_name,
            version,
            license,
            repository,
            timestamp,
            no_redact,
            ai,
            model,
        } => generate(
            &wasm,
            source,
            &out,
            &format,
            project_name,
            version,
            license,
            repository,
            timestamp,
            no_redact,
            ai,
            &model,
        ),
        DocsCommands::Validate {
            kb_json,
            min_coverage,
            require_function_docs,
            require_error_docs,
            require_param_docs,
            format,
        } => validate(
            &kb_json,
            min_coverage,
            require_function_docs,
            require_error_docs,
            require_param_docs,
            &format,
        ),
        DocsCommands::Diff {
            baseline,
            candidate,
            format,
            fail_on_breaking,
        } => diff(&baseline, &candidate, &format, fail_on_breaking),
        DocsCommands::Stale {
            wasm,
            kb_json,
            source,
            format,
            allow_stale,
        } => stale(&wasm, &kb_json, source, &format, allow_stale),
        DocsCommands::PublishPreview { kb_json, out } => publish_preview(&kb_json, &out),
    }
}

#[allow(clippy::too_many_arguments)]
fn generate(
    wasm_path: &Path,
    source: Option<PathBuf>,
    out_dir: &Path,
    format: &str,
    project_name: Option<String>,
    version: Option<String>,
    license: Option<String>,
    repository: Option<String>,
    timestamp: bool,
    no_redact: bool,
    ai: bool,
    model: &str,
) -> Result<()> {
    config::validate_file_path(wasm_path, Some("wasm"))?;
    if let Some(dir) = &source {
        anyhow::ensure!(
            dir.is_dir(),
            "--source must be an existing directory: {}",
            dir.display()
        );
    }

    let wasm = fs::read(wasm_path)
        .with_context(|| format!("Failed to read WASM file {}", wasm_path.display()))?;

    let name = project_name.unwrap_or_else(|| {
        wasm_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "contract".to_string())
    });

    let options = docgen::extract::ExtractOptions {
        project: model::ProjectMeta {
            name,
            version,
            license,
            repository,
        },
        source_dir: source,
        home: dirs_home(),
        no_redact,
        generated_at: if timestamp {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        },
    };

    p::header("Soroban Documentation Generator");
    let mut kb = docgen::extract::build_kb(wasm_path, &wasm, &options)?;

    if ai {
        let attempted =
            tokio_block_on(docgen::explain::maybe_generate_ai_explanations(&kb, model))?;
        match attempted {
            Some(explanations) => {
                let applied = explanations.len();
                for (id, text) in explanations {
                    if let Some(f) = kb.functions.iter_mut().find(|f| f.id == id) {
                        f.explanation = Some(text);
                        f.explanation_source = Some(model::ExplanationSource::Ai);
                    }
                }
                println!(
                    "{} AI explanations applied to {} function(s); remaining functions use \
                     deterministic templates.",
                    "✨".cyan(),
                    applied
                );
            }
            None => {
                println!(
                    "{} AI assistance unavailable/unconfigured; using deterministic templates.",
                    "📊".cyan()
                );
            }
        }
    }
    docgen::explain::apply_template_explanations(&mut kb);
    kb.finalize();

    // Persist artifacts atomically so interrupted runs never leave truncated
    // documentation behind.
    if matches!(format, "md" | "both") {
        let md_path = out_dir.join(format!("{}.md", sanitize_file_stem(&kb.project.name)));
        let markdown = docgen::markdown::render_markdown(&kb);
        let bytes = if no_redact {
            markdown.into_bytes()
        } else {
            ai_redact_text(&markdown).into_bytes()
        };
        docgen::model::write_atomic(&md_path, &bytes)?;
        p::kv("Markdown", &md_path.display().to_string());
    }
    if matches!(format, "json" | "both") {
        let json_path = out_dir.join(KB_FILE);
        docgen::model::save_kb(&kb, &json_path)?;
        p::kv("Knowledge base", &json_path.display().to_string());
    }

    p::kv("Functions", &kb.summary.functions.to_string());
    p::kv(
        "Documented functions",
        &kb.summary.documented_functions.to_string(),
    );
    p::kv("Events", &kb.summary.events.to_string());
    p::kv("Error cases", &kb.summary.error_cases.to_string());
    p::kv("Storage keys", &kb.summary.storage_keys.to_string());
    p::kv("Types", &kb.summary.types.to_string());
    p::success(&format!("Documentation fingerprint {}", kb.fingerprint()));
    Ok(())
}

fn validate(
    kb_json: &Path,
    min_coverage: f64,
    require_function_docs: bool,
    require_error_docs: bool,
    require_param_docs: bool,
    format: &str,
) -> Result<()> {
    config::validate_file_path(kb_json, Some("json"))?;
    let kb = docgen::model::load_kb(kb_json)?;

    let integrity_ok = integrity_check(&kb);
    let policy = docgen::quality::QualityPolicy {
        min_coverage_percent: min_coverage,
        require_function_docs,
        require_error_case_docs: require_error_docs,
        require_param_docs,
    };
    let report = docgen::quality::assess(&kb, &policy);
    let passed = report.passed && integrity_ok;

    if format == "json" {
        let payload = serde_json::json!({
            "quality": report,
            "integrity_ok": integrity_ok,
            "passed": passed,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        p::header("Documentation Validation");
        print!("{}", report.to_markdown());
        if integrity_ok {
            p::success("Content hashes verified: knowledge base is internally consistent.");
        } else {
            p::error("Content hash verification failed; regenerate the knowledge base.");
        }
    }

    if !passed {
        anyhow::bail!(
            "Documentation validation failed for {} ({} error(s), {} warning(s){})",
            kb_json.display(),
            report.error_count,
            report.warning_count,
            if integrity_ok {
                String::new()
            } else {
                "; content hashes do not match".to_string()
            }
        );
    }
    Ok(())
}

fn diff(
    baseline_path: &Path,
    candidate_path: &Path,
    format: &str,
    fail_on_breaking: bool,
) -> Result<()> {
    config::validate_file_path(baseline_path, Some("json"))?;
    config::validate_file_path(candidate_path, Some("json"))?;
    let baseline = docgen::model::load_kb(baseline_path)?;
    let candidate = docgen::model::load_kb(candidate_path)?;

    let report = docgen::diff::diff_kbs(&baseline, &candidate);

    let rendered = if format == "json" {
        serde_json::to_string_pretty(&report)?
    } else {
        report.to_markdown()
    };
    println!("{rendered}");

    if fail_on_breaking && report.summary.breaking > 0 {
        anyhow::bail!(
            "Diff introduces {} breaking documentation change(s)",
            report.summary.breaking
        );
    }
    Ok(())
}

fn stale(
    wasm_path: &Path,
    kb_json: &Path,
    source: Option<PathBuf>,
    format: &str,
    allow_stale: bool,
) -> Result<()> {
    config::validate_file_path(wasm_path, Some("wasm"))?;
    config::validate_file_path(kb_json, Some("json"))?;

    let committed = docgen::model::load_kb(kb_json)?;
    let wasm = fs::read(wasm_path)
        .with_context(|| format!("Failed to read WASM file {}", wasm_path.display()))?;

    // Rebuild with the committed metadata so only API/content changes — not
    // project-name edits — can surface as staleness.
    let options = docgen::extract::ExtractOptions {
        project: committed.project.clone(),
        source_dir: source,
        home: dirs_home(),
        no_redact: false,
        generated_at: None,
    };
    let fresh = docgen::extract::build_kb(wasm_path, &wasm, &options)?;
    let report = docgen::diff::diff_kbs(&committed, &fresh);

    let stale_count = report
        .changes
        .iter()
        .filter(|c| c.kind != docgen::diff::ChangeKind::Added)
        .count();

    if format == "json" {
        let payload = serde_json::json!({
            "stale_entries": stale_count,
            "orphaned_entries": report.summary.removed,
            "changed_entries": report.summary.changed,
            "new_entries": report.summary.added,
            "breaking": report.summary.breaking,
            "up_to_date": stale_count == 0,
            "changes": report.changes,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        p::header("Stale Documentation Check");
        p::kv("Contract", &wasm_path.display().to_string());
        p::kv("Docs", &kb_json.display().to_string());
        if report.is_empty() {
            p::success("Documentation is up to date with the contract.");
        } else {
            p::warn(&format!(
                "{} stale/orphaned entr(y/ies), {} new",
                stale_count, report.summary.added
            ));
            for change in &report.changes {
                let label = match change.kind {
                    docgen::diff::ChangeKind::Added => "new".green(),
                    docgen::diff::ChangeKind::Removed => "orphaned".red(),
                    docgen::diff::ChangeKind::Changed => "stale".yellow(),
                };
                println!("  • [{label}] {}", change.id);
            }
        }
    }

    if stale_count > 0 && !allow_stale {
        anyhow::bail!(
            "{} documented entrie(s) are stale or orphaned relative to {}. \
             Regenerate the docs or pass --allow-stale.",
            stale_count,
            wasm_path.display()
        );
    }
    Ok(())
}

fn publish_preview(kb_json: &Path, out_dir: &Path) -> Result<()> {
    config::validate_file_path(kb_json, Some("json"))?;
    let kb = docgen::model::load_kb(kb_json)?;

    let index_path = out_dir.join("index.md");
    let markdown = docgen::markdown::render_markdown(&kb);
    docgen::model::write_atomic(&index_path, markdown.as_bytes())?;

    // Copy the machine-readable KB next to the preview so reviewers and CI
    // consume both representations of exactly the same revision.
    let kb_copy = out_dir.join(KB_FILE);
    docgen::model::save_kb(&kb, &kb_copy)?;
    let files = [index_path.clone(), kb_copy.clone()];

    let manifest = serde_json::json!({
        "schema_version": kb.schema_version,
        "generator": kb.generator,
        "generator_version": kb.generator_version,
        "project": kb.project,
        "fingerprint": kb.fingerprint(),
        "files": files.iter().map(|path| serde_json::json!({
            "path": path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            "sha256": docgen::extract::sha256_hex(
                &fs::read(path).unwrap_or_default(),
            ),
        })).collect::<Vec<_>>(),
    });
    let manifest_path = out_dir.join("manifest.json");
    docgen::model::write_atomic(
        &manifest_path,
        serde_json::to_string_pretty(&manifest)?.as_bytes(),
    )?;

    p::header("Documentation Preview Bundle");
    p::kv("Index", &index_path.display().to_string());
    p::kv("Knowledge base", &kb_copy.display().to_string());
    p::kv("Manifest", &manifest_path.display().to_string());
    p::success(&format!("Fingerprint {}", kb.fingerprint()));
    Ok(())
}

/// Verifies every stored content hash still matches a recomputation. Catches
/// hand-edits and partial writes that would otherwise silently poison diffs.
fn integrity_check(kb: &model::KnowledgeBase) -> bool {
    let mut recomputed = kb.clone();
    recomputed.finalize();
    let expected = recomputed.entry_hashes();
    kb.entry_hashes()
        .into_iter()
        .all(|(id, stored)| expected.get(&id) == Some(&stored))
}

fn dirs_home() -> Option<String> {
    dirs::home_dir().and_then(|h| h.to_str().map(str::to_string))
}

fn sanitize_file_stem(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "contract".to_string()
    } else {
        cleaned
    }
}

/// Runs the docgen async AI helper on a short-lived runtime; docs commands
/// are otherwise synchronous.
fn tokio_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new()
        .expect("failed to create async runtime")
        .block_on(fut)
}
