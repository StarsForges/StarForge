mod index;
mod model;
mod offline;
mod privacy;
mod prompt;

use super::execute_chat;
use crate::utils::ai_telemetry;
use anyhow::{Context, Result};
use async_openai::{
    config::OpenAIConfig,
    types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role},
    Client,
};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use index::{build_index, load_config, save_index};
use model::{
    AssistantResponse, GuidanceItem, IndexOptions, PrivacyReport, ProviderReport, ResponseMode,
    Severity, SourceReference, Workflow, WorkflowRequest, RESPONSE_SCHEMA_VERSION,
};
use privacy::redact_text;
use prompt::{assemble_prompt, estimate_tokens};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Args)]
#[command(about = "Context-aware Soroban development workflows")]
pub struct AssistantArgs {
    #[command(subcommand)]
    command: AssistantCommands,
}

impl AssistantArgs {
    pub fn is_json(&self) -> bool {
        match &self.command {
            AssistantCommands::Index(options) => options.common.format == OutputFormat::Json,
            AssistantCommands::Explain(options)
            | AssistantCommands::Diagnose(options)
            | AssistantCommands::Suggest(options)
            | AssistantCommands::Review(options) => options.common.format == OutputFormat::Json,
            AssistantCommands::Scaffold(options) => options.common.format == OutputFormat::Json,
        }
    }
}

#[derive(Subcommand)]
enum AssistantCommands {
    /// Build and safely persist the project context index
    Index(IndexCommand),
    /// Explain project architecture or selected Soroban behavior
    Explain(QueryCommand),
    /// Diagnose a build, runtime, RPC, or deployment problem
    Diagnose(QueryCommand),
    /// Suggest an implementation that matches the current project
    Suggest(QueryCommand),
    /// Produce a project-aware contract scaffold plan
    Scaffold(ScaffoldCommand),
    /// Review indexed contracts for security and maintainability risks
    Review(QueryCommand),
}

#[derive(Debug, Clone, Args)]
struct CommonOptions {
    /// Project root to index
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// Output format for humans or automation
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Additional relative path or pattern to exclude (repeatable)
    #[arg(long = "exclude", value_name = "RELATIVE_PATH")]
    excluded_paths: Vec<String>,

    /// Disable secret redaction (unsafe; explicit opt-in)
    #[arg(long)]
    no_redact: bool,
}

#[derive(Debug, Clone, Args)]
struct IndexCommand {
    #[command(flatten)]
    common: CommonOptions,

    /// Build without writing .starforge/assistant-index.json
    #[arg(long)]
    no_persist: bool,
}

#[derive(Debug, Clone, Args)]
struct QueryCommand {
    /// Question, symptom, desired change, or review objective
    #[arg(value_name = "REQUEST")]
    query: String,

    /// Relative path, function, or concept to emphasize
    #[arg(long)]
    focus: Option<String>,

    #[command(flatten)]
    common: CommonOptions,

    #[command(flatten)]
    execution: ExecutionOptions,
}

#[derive(Debug, Clone, Args)]
struct ScaffoldCommand {
    /// What the new contract or component should do
    #[arg(value_name = "REQUEST")]
    query: String,

    /// Contract crate name
    #[arg(long, default_value = "new-contract")]
    name: String,

    #[command(flatten)]
    common: CommonOptions,

    #[command(flatten)]
    execution: ExecutionOptions,
}

#[derive(Debug, Clone, Args)]
struct ExecutionOptions {
    /// Use only deterministic local guidance; never contact a provider
    #[arg(long)]
    offline: bool,

    /// Print the exact redacted prompt and do not contact a provider
    #[arg(long)]
    preview: bool,

    /// AI model used when online
    #[arg(long, default_value = "gpt-4o-mini")]
    model: String,

    /// Do not persist the refreshed project index
    #[arg(long)]
    no_persist: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct IndexCommandResponse {
    schema_version: u16,
    project_name: String,
    persisted: bool,
    index_path: Option<String>,
    summary: model::IndexSummary,
    entries: Vec<IndexEntrySummary>,
}

#[derive(Debug, Serialize)]
struct IndexEntrySummary {
    path: String,
    kind: model::ContextKind,
    size_bytes: u64,
    digest: String,
    redactions: usize,
}

#[derive(Debug, Deserialize)]
struct ProviderPayload {
    summary: String,
    #[serde(default)]
    guidance: Vec<ProviderGuidance>,
}

#[derive(Debug, Deserialize)]
struct ProviderGuidance {
    #[serde(default = "default_provider_severity")]
    severity: String,
    title: String,
    detail: String,
    path: Option<String>,
    line: Option<usize>,
}

fn default_provider_severity() -> String {
    "suggestion".to_string()
}

pub async fn handle(args: AssistantArgs) -> Result<()> {
    match args.command {
        AssistantCommands::Index(command) => handle_index(command),
        AssistantCommands::Explain(command) => {
            handle_workflow(query_request(Workflow::Explain, command)).await
        }
        AssistantCommands::Diagnose(command) => {
            handle_workflow(query_request(Workflow::Diagnose, command)).await
        }
        AssistantCommands::Suggest(command) => {
            handle_workflow(query_request(Workflow::Suggest, command)).await
        }
        AssistantCommands::Review(command) => {
            handle_workflow(query_request(Workflow::Review, command)).await
        }
        AssistantCommands::Scaffold(command) => {
            let invocation = WorkflowInvocation {
                request: WorkflowRequest {
                    workflow: Workflow::Scaffold,
                    query: command.query,
                    focus: Some(command.name),
                },
                common: command.common,
                execution: command.execution,
            };
            handle_workflow(invocation).await
        }
    }
}

struct WorkflowInvocation {
    request: WorkflowRequest,
    common: CommonOptions,
    execution: ExecutionOptions,
}

fn query_request(workflow: Workflow, command: QueryCommand) -> WorkflowInvocation {
    WorkflowInvocation {
        request: WorkflowRequest {
            workflow,
            query: command.query,
            focus: command.focus,
        },
        common: command.common,
        execution: command.execution,
    }
}

fn handle_index(command: IndexCommand) -> Result<()> {
    warn_for_unsafe_privacy(&command.common);
    let root = canonical_root(&command.common.root)?;
    let options = resolve_index_options(&root, &command.common)?;
    let project_index = build_index(&options)?;
    let persisted = !command.no_persist;
    let persisted_path = if persisted {
        let path = save_index(&root, &project_index)?;
        Some(relative_persistence_path(&root, &path))
    } else {
        None
    };
    let response = IndexCommandResponse {
        schema_version: RESPONSE_SCHEMA_VERSION,
        project_name: project_index.project_name,
        persisted,
        index_path: persisted_path,
        summary: project_index.summary,
        entries: project_index
            .entries
            .into_iter()
            .map(|entry| IndexEntrySummary {
                path: entry.path,
                kind: entry.kind,
                size_bytes: entry.size_bytes,
                digest: entry.digest,
                redactions: entry.redactions,
            })
            .collect(),
    };
    render_index(&response, command.common.format)
}

async fn handle_workflow(invocation: WorkflowInvocation) -> Result<()> {
    warn_for_unsafe_privacy(&invocation.common);
    let start = Instant::now();
    let root = canonical_root(&invocation.common.root)?;
    let index_options = resolve_index_options(&root, &invocation.common)?;
    let project_index = build_index(&index_options)?;
    if !invocation.execution.no_persist {
        save_index(&root, &project_index)?;
    }

    let prompt = assemble_prompt(&project_index, &invocation.request, index_options.redact);
    let selected_sources: Vec<SourceReference> = prompt
        .selected
        .iter()
        .map(|entry| SourceReference {
            path: entry.path.clone(),
            kind: entry.kind,
            digest: entry.digest.clone(),
        })
        .collect();
    let redactions = project_index.summary.redactions + prompt.redactions;

    let response = if invocation.execution.preview {
        let (summary, guidance) = offline::generate(&project_index, &invocation.request);
        AssistantResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            workflow: invocation.request.workflow,
            mode: ResponseMode::Preview,
            summary,
            guidance,
            sources: selected_sources,
            privacy: privacy_report(&index_options, redactions, false),
            prompt_preview: Some(prompt.preview()),
            provider: None,
        }
    } else if invocation.execution.offline {
        let (summary, guidance) = offline::generate(&project_index, &invocation.request);
        let response = AssistantResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            workflow: invocation.request.workflow,
            mode: ResponseMode::Offline,
            summary,
            guidance,
            sources: selected_sources,
            privacy: privacy_report(&index_options, redactions, false),
            prompt_preview: None,
            provider: Some(ProviderReport {
                name: "starforge-local".into(),
                model: "deterministic-v1".into(),
                fallback_reason: None,
            }),
        };
        track_local(
            &response,
            prompt.estimated_input_tokens,
            start.elapsed().as_millis() as u64,
        );
        response
    } else {
        match request_provider(
            &prompt,
            &invocation.execution.model,
            invocation.request.workflow,
        )
        .await
        {
            Ok(payload) => AssistantResponse {
                schema_version: RESPONSE_SCHEMA_VERSION,
                workflow: invocation.request.workflow,
                mode: ResponseMode::Online,
                summary: payload.summary,
                guidance: normalize_provider_guidance(payload.guidance, &selected_sources),
                sources: selected_sources,
                privacy: privacy_report(&index_options, redactions, true),
                prompt_preview: None,
                provider: Some(ProviderReport {
                    name: "openai".into(),
                    model: invocation.execution.model,
                    fallback_reason: None,
                }),
            },
            Err(error) => {
                let reason = safe_error(&error);
                let (summary, guidance) = offline::generate(&project_index, &invocation.request);
                let response = AssistantResponse {
                    schema_version: RESPONSE_SCHEMA_VERSION,
                    workflow: invocation.request.workflow,
                    mode: ResponseMode::Fallback,
                    summary,
                    guidance,
                    sources: selected_sources,
                    privacy: privacy_report(
                        &index_options,
                        redactions,
                        provider_was_contacted(&error),
                    ),
                    prompt_preview: None,
                    provider: Some(ProviderReport {
                        name: "starforge-local".into(),
                        model: "deterministic-v1".into(),
                        fallback_reason: Some(reason),
                    }),
                };
                track_fallback(
                    &response,
                    prompt.estimated_input_tokens,
                    start.elapsed().as_millis() as u64,
                );
                response
            }
        }
    };

    render_response(&response, invocation.common.format)
}

fn resolve_index_options(root: &Path, common: &CommonOptions) -> Result<IndexOptions> {
    let config = load_config(root)?;
    let mut exclusions = config.excluded_paths;
    for path in &common.excluded_paths {
        validate_exclusion(path)?;
        exclusions.push(path.clone());
    }
    Ok(IndexOptions {
        root: root.to_path_buf(),
        excluded_paths: exclusions,
        redact: config.redact && !common.no_redact,
        max_file_bytes: config.max_file_bytes.clamp(1024, 1024 * 1024),
        max_total_bytes: config.max_total_bytes.clamp(4096, 8 * 1024 * 1024),
    })
}

fn validate_exclusion(path: &str) -> Result<()> {
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        anyhow::bail!("--exclude must be a project-relative path or pattern without `..`");
    }
    Ok(())
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    root.canonicalize()
        .with_context(|| format!("project root does not exist: {}", root.display()))
}

fn privacy_report(
    options: &IndexOptions,
    redactions: usize,
    provider_contacted: bool,
) -> PrivacyReport {
    PrivacyReport {
        redaction_enabled: options.redact,
        excluded_path_count: options.excluded_paths.len(),
        redactions_applied: redactions,
        absolute_paths_shared: false,
        provider_contacted,
    }
}

async fn request_provider(
    prompt: &prompt::AssembledPrompt,
    model: &str,
    workflow: Workflow,
) -> Result<ProviderPayload> {
    let api_key = std::env::var("OPENAI_API_KEY")
        .or_else(|_| std::env::var("STARFORGE_AI_API_KEY"))
        .context("provider not configured: set OPENAI_API_KEY or use --offline")?;
    let client = Client::with_config(OpenAIConfig::new().with_api_key(api_key));
    let user = format!(
        "{}\n\nReturn JSON only with this shape: {{\"summary\":\"...\",\"guidance\":[{{\"severity\":\"info|suggestion|warning|critical\",\"title\":\"...\",\"detail\":\"...\",\"path\":\"optional relative indexed path\",\"line\":1}}]}}",
        prompt.user
    );
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages: vec![
            ChatCompletionRequestMessage {
                role: Role::System,
                content: Some(prompt.system.clone()),
                name: None,
                function_call: None,
            },
            ChatCompletionRequestMessage {
                role: Role::User,
                content: Some(user),
                name: None,
                function_call: None,
            },
        ],
        ..Default::default()
    };
    let response = execute_chat(
        &client,
        &format!("assistant_{}", workflow.name()),
        model,
        request,
    )
    .await?;
    let content = response
        .choices
        .first()
        .and_then(|choice| choice.message.content.as_deref())
        .context("provider returned no assistant content")?;
    parse_provider_payload(content)
}

fn parse_provider_payload(content: &str) -> Result<ProviderPayload> {
    let trimmed = content.trim();
    let json = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed)
        .strip_suffix("```")
        .unwrap_or(trimmed)
        .trim();
    let payload: ProviderPayload =
        serde_json::from_str(json).context("provider returned an invalid structured response")?;
    if payload.summary.trim().is_empty() {
        anyhow::bail!("provider returned an empty summary");
    }
    Ok(payload)
}

fn normalize_provider_guidance(
    guidance: Vec<ProviderGuidance>,
    sources: &[SourceReference],
) -> Vec<GuidanceItem> {
    guidance
        .into_iter()
        .filter(|item| !item.title.trim().is_empty() && !item.detail.trim().is_empty())
        .map(|item| {
            let path = item.path.filter(|path| {
                !Path::new(path).is_absolute() && sources.iter().any(|source| source.path == *path)
            });
            GuidanceItem {
                severity: parse_severity(&item.severity),
                title: item.title,
                detail: item.detail,
                path,
                line: item.line.filter(|line| *line > 0),
            }
        })
        .collect()
}

fn parse_severity(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" | "high" => Severity::Critical,
        "warning" | "warn" | "medium" => Severity::Warning,
        "info" | "informational" => Severity::Info,
        _ => Severity::Suggestion,
    }
}

fn safe_error(error: &anyhow::Error) -> String {
    let redacted = redact_text(&format!("{error:#}")).text;
    redacted.chars().take(300).collect()
}

fn provider_was_contacted(error: &anyhow::Error) -> bool {
    !error.to_string().starts_with("provider not configured")
}

fn track_local(response: &AssistantResponse, input_tokens: u32, duration_ms: u64) {
    let output_tokens = estimate_tokens(&format!("{} {:?}", response.summary, response.guidance));
    let _ = ai_telemetry::track_ai_event(ai_telemetry::AiCallOutcome {
        provider: "local",
        model: "deterministic-v1",
        feature: &format!("assistant_{}", response.workflow.name()),
        input_tokens,
        output_tokens,
        duration_ms,
        success: true,
        error_type: None,
    });
}

fn track_fallback(response: &AssistantResponse, input_tokens: u32, duration_ms: u64) {
    let output_tokens = estimate_tokens(&format!("{} {:?}", response.summary, response.guidance));
    let _ = ai_telemetry::track_ai_event(ai_telemetry::AiCallOutcome {
        provider: "local",
        model: "deterministic-v1",
        feature: &format!("assistant_{}_fallback", response.workflow.name()),
        input_tokens,
        output_tokens,
        duration_ms,
        success: true,
        error_type: Some("provider_fallback".into()),
    });
}

fn render_index(response: &IndexCommandResponse, format: OutputFormat) -> Result<()> {
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    println!("{} Context index ready", "✓".green());
    println!("  Project:       {}", response.project_name.bold());
    println!("  Files:         {}", response.summary.files_indexed);
    println!("  Bytes:         {}", response.summary.bytes_indexed);
    println!("  Redactions:    {}", response.summary.redactions);
    println!("  Skipped:       {}", response.summary.skipped_files);
    println!("  Truncated:     {}", response.summary.truncated_files);
    println!(
        "  Persistence:   {}",
        response.index_path.as_deref().unwrap_or("disabled")
    );
    Ok(())
}

fn render_response(response: &AssistantResponse, format: OutputFormat) -> Result<()> {
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    println!(
        "{} {} ({})",
        "StarForge Assistant".bold(),
        response.workflow.name().cyan(),
        format!("{:?}", response.mode).to_ascii_lowercase()
    );
    println!("\n{}", response.summary);
    for item in &response.guidance {
        let location = item
            .path
            .as_deref()
            .map(|path| match item.line {
                Some(line) => format!(" [{path}:{line}]"),
                None => format!(" [{path}]"),
            })
            .unwrap_or_default();
        println!(
            "\n  {} {}{}\n    {}",
            severity_marker(item.severity),
            item.title.bold(),
            location.dimmed(),
            item.detail
        );
    }
    if let Some(preview) = &response.prompt_preview {
        println!("\n{}\n{}", "System prompt".bold(), preview.system);
        println!("\n{}\n{}", "User prompt".bold(), preview.user);
        println!(
            "\nEstimated input tokens: {}",
            preview.estimated_input_tokens
        );
    }
    if let Some(provider) = &response.provider {
        println!("\nProvider: {} / {}", provider.name, provider.model);
        if let Some(reason) = &provider.fallback_reason {
            println!("Fallback reason: {}", reason);
        }
    }
    println!(
        "Privacy: {} redaction(s); provider contacted: {}",
        response.privacy.redactions_applied, response.privacy.provider_contacted
    );
    Ok(())
}

fn severity_marker(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::Warning => "WARNING".yellow().bold(),
        Severity::Suggestion => "SUGGEST".cyan(),
        Severity::Info => "INFO".blue(),
    }
}

fn warn_for_unsafe_privacy(common: &CommonOptions) {
    if common.no_redact {
        eprintln!(
            "{} --no-redact allows secrets in the local index and provider prompt; use only with trusted input.",
            "Warning:".yellow().bold()
        );
    }
}

fn relative_persistence_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_and_markdown_wrapped_provider_payloads() {
        let raw = r#"{"summary":"ok","guidance":[{"severity":"warning","title":"Auth","detail":"Call require_auth"}]}"#;
        assert_eq!(parse_provider_payload(raw).unwrap().summary, "ok");
        let wrapped = format!("```json\n{raw}\n```");
        assert_eq!(parse_provider_payload(&wrapped).unwrap().guidance.len(), 1);
    }

    #[test]
    fn rejects_absolute_provider_source_paths() {
        let guidance = normalize_provider_guidance(
            vec![ProviderGuidance {
                severity: "high".into(),
                title: "finding".into(),
                detail: "detail".into(),
                path: Some("/home/user/project/src/lib.rs".into()),
                line: Some(1),
            }],
            &[],
        );
        assert_eq!(guidance[0].severity, Severity::Critical);
        assert_eq!(guidance[0].path, None);
    }
}
