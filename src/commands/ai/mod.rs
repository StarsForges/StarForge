pub mod assistant;
pub mod impact;
mod security_training;
mod telemetry;

use crate::utils::{ai_telemetry, confirmation, optimizer};
use anyhow::{Context, Result};
use async_openai::{
    config::OpenAIConfig,
    error::OpenAIError,
    types::{
        ChatCompletionRequestMessage, CreateChatCompletionRequest, CreateChatCompletionResponse,
        Role,
    },
    Client,
};
use clap::{Parser, Subcommand};
use colored::*;
use similar::{ChangeTag, TextDiff};
use std::env;
use std::time::Instant;

#[derive(Parser)]
#[command(about = "AI-powered development assistance for Soroban contracts")]
pub struct AiArgs {
    #[command(subcommand)]
    command: AiCommands,
}

impl AiArgs {
    pub fn is_machine_readable(&self) -> bool {
        matches!(&self.command, AiCommands::Assistant(args) if args.is_json())
    }
}

#[derive(Subcommand)]
enum AiCommands {
    /// Context-aware project assistance with privacy controls and offline fallback
    Assistant(assistant::AssistantArgs),
    /// Generate Soroban contract code from natural language description
    Generate {
        /// Natural language description of the contract
        #[arg(long)]
        prompt: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
        /// Model to use (default: gpt-4)
        #[arg(long, default_value = "gpt-4")]
        model: String,
    },
    /// Analyze existing Soroban contract for security vulnerabilities
    Analyze {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Analysis type (security, gas, optimization)
        #[arg(long, default_value = "security")]
        analysis_type: String,
    },
    /// Generate test cases for a Soroban contract
    GenerateTests {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Output directory for tests
        #[arg(long)]
        output: Option<String>,
    },
    /// Explain Soroban contract code in natural language
    Explain {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Specific function to explain (optional)
        #[arg(long)]
        function: Option<String>,
    },
    /// Optimize Soroban contract code, with before/after comparison
    Optimize {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Output file path. Writing is gated behind confirmation unless --yes.
        #[arg(long)]
        output: Option<String>,
        /// Skip the write confirmation prompt (still requires --output)
        #[arg(long)]
        yes: bool,
    },
    /// Explain an error message in plain language with fix suggestions
    ExplainError {
        /// Raw error message text to explain
        #[arg(long, conflicts_with = "file")]
        message: Option<String>,
        /// Path to a file containing error/log output
        #[arg(long)]
        file: Option<String>,
        /// Force a specific category instead of auto-detecting
        #[arg(long, value_parser = ["compilation", "runtime", "network", "configuration", "deployment"])]
        error_type: Option<String>,
    },
    /// Manage AI usage telemetry (API calls, tokens, cost, latency)
    #[command(subcommand)]
    Telemetry(telemetry::AiTelemetryCommands),
    /// Interactive AI security training: lessons, quizzes, and progress tracking
    #[command(subcommand)]
    SecurityTraining(security_training::SecurityTrainingCommands),
    /// Analyze social and economic impact of a Soroban contract
    Impact {
        /// Path to the contract metadata or WASM/Rust source file
        #[arg(long, short)]
        file: String,

        /// Policy profile to evaluate: community, enterprise, public-sector, protocol-maintainer (default: community)
        #[arg(long, short, default_value = "community", value_parser = ["community", "enterprise", "public-sector", "protocol-maintainer"])]
        profile: String,

        /// Optional path to a previous report JSON to compare versions
        #[arg(long)]
        compare: Option<String>,

        /// Report output format: json or markdown (default: markdown)
        #[arg(long, short, default_value = "markdown", value_parser = ["json", "markdown"])]
        format: String,

        /// Optional output path to write the generated report
        #[arg(long, short)]
        output: Option<String>,

        /// Run using the local deterministic engine only, bypassing AI call
        #[arg(long)]
        deterministic: bool,
    },
}

pub async fn handle(args: AiArgs) -> Result<()> {
    // These subcommands are fully local and must work without an API key.
    match args.command {
        AiCommands::Assistant(command) => return assistant::handle(command).await,
        AiCommands::Telemetry(cmd) => return telemetry::handle(cmd),
        AiCommands::SecurityTraining(cmd) => return security_training::handle(cmd),
        AiCommands::Impact {
            file,
            profile,
            compare,
            format,
            output,
            deterministic,
        } => {
            return impact::handle_impact(
                &file,
                &profile,
                compare.as_deref(),
                &format,
                output.as_deref(),
                deterministic,
            )
            .await;
        }
        _ => {}
    }

    let api_key = env::var("OPENAI_API_KEY")
        .or_else(|_| env::var("STARFORGE_AI_API_KEY"))
        .context("OPENAI_API_KEY or STARFORGE_AI_API_KEY environment variable not set")?;

    let client = Client::with_config(OpenAIConfig::new().with_api_key(api_key));

    match args.command {
        AiCommands::Generate {
            prompt,
            output,
            model,
        } => generate_contract(&client, &prompt, output.as_deref(), &model).await,
        AiCommands::Analyze {
            file,
            analysis_type,
        } => analyze_contract(&client, &file, &analysis_type).await,
        AiCommands::GenerateTests { file, output } => {
            generate_tests(&client, &file, output.as_deref()).await
        }
        AiCommands::Explain { file, function } => {
            explain_contract(&client, &file, function.as_deref()).await
        }
        AiCommands::Optimize { file, output, yes } => {
            optimize_contract(&client, &file, output.as_deref(), yes).await
        }
        AiCommands::ExplainError {
            message,
            file,
            error_type,
        } => explain_error(&client, message, file, error_type).await,
        AiCommands::Assistant(_)
        | AiCommands::Telemetry(_)
        | AiCommands::SecurityTraining(_)
        | AiCommands::Impact { .. } => {
            unreachable!()
        }
    }
}

// ── Shared telemetry-instrumented request helper ────────────────────────────────

/// Send a chat completion request and record an AI telemetry event for the
/// outcome (tokens, latency, success/error type), regardless of the calling
/// feature. Centralizing this means every AI subcommand is measured
/// uniformly, satisfying the AI telemetry requirements without duplicating
/// instrumentation in each handler.
pub(crate) async fn execute_chat(
    client: &Client<OpenAIConfig>,
    feature: &str,
    model: &str,
    request: CreateChatCompletionRequest,
) -> Result<CreateChatCompletionResponse> {
    let start = Instant::now();
    let result = client.chat().create(request).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    let outcome = match &result {
        Ok(resp) => {
            let usage = resp.usage.as_ref();
            ai_telemetry::AiCallOutcome {
                provider: "openai",
                model,
                feature,
                input_tokens: usage.map(|u| u.prompt_tokens).unwrap_or(0),
                output_tokens: usage.map(|u| u.completion_tokens).unwrap_or(0),
                duration_ms,
                success: true,
                error_type: None,
            }
        }
        Err(e) => ai_telemetry::AiCallOutcome {
            provider: "openai",
            model,
            feature,
            input_tokens: 0,
            output_tokens: 0,
            duration_ms,
            success: false,
            error_type: Some(classify_openai_error(e)),
        },
    };
    let _ = ai_telemetry::track_ai_event(outcome);

    result.map_err(|e| anyhow::anyhow!("{} request failed: {}", feature, e))
}

fn classify_openai_error(err: &OpenAIError) -> String {
    let text = err.to_string().to_lowercase();
    match err {
        OpenAIError::ApiError(_) => {
            if text.contains("rate_limit") || text.contains("rate limit") {
                "rate_limit".to_string()
            } else if text.contains("invalid_api_key")
                || text.contains("authentication")
                || text.contains("unauthorized")
            {
                "auth".to_string()
            } else if text.contains("insufficient_quota") || text.contains("quota") {
                "quota".to_string()
            } else {
                "api_error".to_string()
            }
        }
        OpenAIError::Reqwest(_) => {
            if text.contains("timed out") || text.contains("timeout") {
                "timeout".to_string()
            } else {
                "network".to_string()
            }
        }
        OpenAIError::JSONDeserialize(_) => "response_parse_error".to_string(),
        _ => "client_error".to_string(),
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────────

async fn generate_contract(
    client: &Client<OpenAIConfig>,
    prompt: &str,
    output: Option<&str>,
    model: &str,
) -> Result<()> {
    println!("{} Generating Soroban contract...", "✨".cyan());

    let system_prompt = "You are an expert Soroban smart contract developer. Generate complete, compilable Soroban contract code in Rust based on the user's description. Include proper error handling, comments, and follow Soroban best practices. Return only the code without markdown formatting.";

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(prompt.to_string()),
            name: None,
            function_call: None,
        },
    ];

    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = execute_chat(client, "generate", model, request).await?;

    if let Some(choice) = response.choices.first() {
        let code = choice.message.content.as_deref().unwrap_or("").trim();

        if let Some(output_path) = output {
            std::fs::write(output_path, code).context("Failed to write generated code to file")?;
            println!(
                "{} Contract generated and saved to {}",
                "✓".green(),
                output_path
            );
        } else {
            println!("{}", "Generated contract:".bold());
            println!("{}", code);
        }
    }

    Ok(())
}

async fn analyze_contract(
    client: &Client<OpenAIConfig>,
    file: &str,
    analysis_type: &str,
) -> Result<()> {
    println!(
        "{} Analyzing contract for {}...",
        "🔍".cyan(),
        analysis_type
    );

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = match analysis_type {
        "security" => "You are a Soroban smart contract security expert. Analyze the provided Soroban contract code for security vulnerabilities, potential attack vectors, and best practice violations. Provide specific recommendations for each issue found.",
        "gas" => "You are a Soroban gas optimization expert. Analyze the provided Soroban contract code for gas inefficiencies and provide specific optimization recommendations.",
        "optimization" => "You are a Soroban code optimization expert. Analyze the provided Soroban contract code for performance improvements and provide specific recommendations.",
        _ => "You are a Soroban smart contract expert. Analyze the provided contract code.",
    };

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(format!("Analyze this Soroban contract:\n\n{}", code)),
            name: None,
            function_call: None,
        },
    ];

    let model = "gpt-4";
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = execute_chat(client, "analyze", model, request).await?;

    if let Some(choice) = response.choices.first() {
        println!("{}", "Analysis results:".bold());
        println!("{}", choice.message.content.as_deref().unwrap_or(""));
    }

    Ok(())
}

async fn generate_tests(
    client: &Client<OpenAIConfig>,
    file: &str,
    output: Option<&str>,
) -> Result<()> {
    println!("{} Generating test cases...", "🧪".cyan());

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = "You are a Soroban testing expert. Generate comprehensive test cases for the provided Soroban contract. Include unit tests, edge cases, and integration tests. Use the Soroban SDK testing framework. Return only the test code without markdown formatting.";

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(format!(
                "Generate tests for this Soroban contract:\n\n{}",
                code
            )),
            name: None,
            function_call: None,
        },
    ];

    let model = "gpt-4";
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = execute_chat(client, "generate_tests", model, request).await?;

    if let Some(choice) = response.choices.first() {
        let test_code = choice.message.content.as_deref().unwrap_or("").trim();

        if let Some(output_path) = output {
            std::fs::write(output_path, test_code).context("Failed to write test code to file")?;
            println!(
                "{} Tests generated and saved to {}",
                "✓".green(),
                output_path
            );
        } else {
            println!("{}", "Generated test cases:".bold());
            println!("{}", test_code);
        }
    }

    Ok(())
}

async fn explain_contract(
    client: &Client<OpenAIConfig>,
    file: &str,
    function: Option<&str>,
) -> Result<()> {
    println!("{} Explaining contract...", "📖".cyan());

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = "You are a Soroban smart contract educator. Explain the provided Soroban contract code in clear, natural language. Break down complex concepts and provide examples. If a specific function is requested, focus your explanation on that function.";

    let user_prompt = if let Some(func_name) = function {
        format!(
            "Explain this Soroban contract, focusing on the '{}' function:\n\n{}",
            func_name, code
        )
    } else {
        format!("Explain this Soroban contract:\n\n{}", code)
    };

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(user_prompt),
            name: None,
            function_call: None,
        },
    ];

    let model = "gpt-4";
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = execute_chat(client, "explain", model, request).await?;

    if let Some(choice) = response.choices.first() {
        println!("{}", "Contract explanation:".bold());
        println!("{}", choice.message.content.as_deref().unwrap_or(""));
    }

    Ok(())
}

async fn optimize_contract(
    client: &Client<OpenAIConfig>,
    file: &str,
    output: Option<&str>,
    yes: bool,
) -> Result<()> {
    println!("{} Optimizing contract...", "⚡".cyan());

    let original_code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = "You are a Soroban optimization expert. Optimize the provided Soroban contract code for gas efficiency, storage layout, and performance while preserving the exact public interface and functionality. Apply techniques such as storage packing, function inlining, loop optimization, constant folding, and dead-code removal where appropriate. Return only the optimized Rust code without markdown formatting or commentary.";

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(format!(
                "Optimize this Soroban contract:\n\n{}",
                original_code
            )),
            name: None,
            function_call: None,
        },
    ];

    let model = "gpt-4";
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = execute_chat(client, "optimize", model, request).await?;

    let Some(choice) = response.choices.first() else {
        anyhow::bail!("No optimization result returned");
    };
    let optimized_code = choice
        .message
        .content
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();

    // Before/after comparison (heuristic gas proxy — see estimate_source_gas_score).
    let before_score = optimizer::estimate_source_gas_score(&original_code);
    let after_score = optimizer::estimate_source_gas_score(&optimized_code);
    let reduction_pct = optimizer::percent_change(before_score, after_score);

    println!();
    println!("{}", "Before / After Comparison".bold());
    println!(
        "  Heuristic gas-weight score: {} → {} ({:+.1}%)",
        before_score, after_score, -reduction_pct
    );
    println!(
        "  {}",
        "(Heuristic estimate based on storage ops, loops, and cross-contract calls — not a substitute for on-chain gas profiling.)"
            .dimmed()
    );

    println!();
    println!("{}", "Diff".bold());
    print_diff(&original_code, &optimized_code);

    // Safety check: the optimized contract should not silently drop public functions.
    let original_fns = optimizer::extract_pub_fn_names(&original_code);
    let optimized_fns = optimizer::extract_pub_fn_names(&optimized_code);
    let missing_fns: Vec<&String> = original_fns.difference(&optimized_fns).collect();

    println!();
    if missing_fns.is_empty() {
        println!(
            "{} All {} public function signature(s) preserved.",
            "✓".green(),
            original_fns.len()
        );
    } else {
        println!(
            "{} Public function(s) missing from optimized output: {}",
            "⚠".yellow().bold(),
            missing_fns
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  {}",
            "Review carefully — this may indicate a functional regression, not just a rename."
                .yellow()
        );
    }

    let Some(output_path) = output else {
        println!();
        println!("{}", "Optimized contract (preview only):".bold());
        println!("{}", optimized_code);
        return Ok(());
    };

    let risk_level = if missing_fns.is_empty() {
        confirmation::RiskLevel::Medium
    } else {
        confirmation::RiskLevel::High
    };

    let approved = if yes {
        true
    } else {
        let mut summary = confirmation::OperationSummary::new(
            "Apply AI-Optimized Contract".to_string(),
            "local".to_string(),
            risk_level,
        )
        .add("Source File", file)
        .add("Output File", output_path)
        .add("Gas-Weight Change", format!("{:+.1}%", -reduction_pct));
        if !missing_fns.is_empty() {
            summary = summary.add(
                "Warning",
                format!("{} public function(s) missing", missing_fns.len()),
            );
        }
        confirmation::confirm_operation(
            &summary,
            &confirmation::ConfirmationConfig {
                skip_confirm: false,
                require_type_confirmation: !missing_fns.is_empty(),
                network: "local".to_string(),
                risk_level,
                ..Default::default()
            },
        )?
    };

    if !approved {
        return Ok(());
    }

    std::fs::write(output_path, &optimized_code)
        .context("Failed to write optimized code to file")?;
    println!(
        "{} Optimized contract saved to {}",
        "✓".green(),
        output_path
    );

    Ok(())
}

fn print_diff(before: &str, after: &str) {
    let diff = TextDiff::from_lines(before, after);
    for change in diff.iter_all_changes() {
        let line = change.to_string();
        match change.tag() {
            ChangeTag::Delete => print!("  {}{}", "-".red(), line.red()),
            ChangeTag::Insert => print!("  {}{}", "+".green(), line.green()),
            ChangeTag::Equal => print!("  {}{}", " ".normal(), line.dimmed()),
        }
    }
}

// ── AI error explanation (#511) ─────────────────────────────────────────────────

async fn explain_error(
    client: &Client<OpenAIConfig>,
    message: Option<String>,
    file: Option<String>,
    error_type: Option<String>,
) -> Result<()> {
    let raw_text = match (message, file) {
        (Some(m), None) => m,
        (None, Some(f)) => std::fs::read_to_string(&f).context("Failed to read error log file")?,
        (Some(_), Some(_)) => anyhow::bail!("Pass either --message or --file, not both"),
        (None, None) => anyhow::bail!("Provide an error to explain via --message or --file"),
    };

    let category = error_type.unwrap_or_else(|| classify_error_type(&raw_text).to_string());

    println!(
        "{} Explaining {} error...",
        "🩺".cyan(),
        category.to_string().bold()
    );

    let system_prompt = system_prompt_for_error_type(&category);
    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(format!(
                "Error category: {}\n\nError output:\n{}\n\nRespond with these sections, each on its own line prefixed exactly as shown:\nEXPLANATION: <plain language explanation>\nROOT CAUSE: <most likely root cause>\nFIXES: <numbered list of concrete fixes>\nTROUBLESHOOTING: <numbered list of steps to narrow down the issue further>",
                category, raw_text
            )),
            name: None,
            function_call: None,
        },
    ];

    let model = "gpt-4";
    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = execute_chat(client, "explain_error", model, request).await?;

    if let Some(choice) = response.choices.first() {
        println!();
        println!("{}", choice.message.content.as_deref().unwrap_or(""));
    }

    Ok(())
}

/// Heuristic classifier used when `--error-type` isn't provided. Matches the
/// error categories from issue #511: compilation, runtime, network,
/// configuration, deployment.
fn classify_error_type(text: &str) -> &'static str {
    let t = text.to_lowercase();

    let compilation_hits = [
        "error[e",
        "expected `",
        "cannot find",
        "mismatched types",
        "unresolved import",
        "rustc",
    ];
    let network_hits = [
        "connection refused",
        "could not connect",
        "timed out",
        "dns error",
        "network is unreachable",
        "tls handshake",
    ];
    let deployment_hits = [
        "simulation failed",
        "insufficient balance",
        "wasm hash",
        "transaction failed",
        "tx failed",
        "sequence number",
        "fee bump",
    ];
    let configuration_hits = [
        "missing field",
        "invalid value",
        "failed to parse config",
        "toml",
        "environment variable",
        "config.toml",
    ];

    if compilation_hits.iter().any(|h| t.contains(h)) {
        "compilation"
    } else if deployment_hits.iter().any(|h| t.contains(h)) {
        "deployment"
    } else if network_hits.iter().any(|h| t.contains(h)) {
        "network"
    } else if configuration_hits.iter().any(|h| t.contains(h)) {
        "configuration"
    } else {
        // Panics, overflow/underflow, and other runtime failures don't have a
        // single distinctive substring, so "runtime" is the default category.
        "runtime"
    }
}

fn system_prompt_for_error_type(category: &str) -> String {
    let base = "You are a Soroban/Stellar developer troubleshooting assistant. You explain errors in plain, non-condescending language, identify the most likely root cause, and give concrete, actionable fixes.";
    let specific = match category {
        "compilation" => "Focus on Rust/Soroban compiler errors: type mismatches, borrow checker issues, missing trait implementations, and SDK version mismatches.",
        "runtime" => "Focus on panics and runtime failures: overflow/underflow, out-of-bounds access, unwraps on None/Err, and Soroban host errors.",
        "network" => "Focus on connectivity issues: RPC/Horizon endpoint reachability, timeouts, TLS issues, and DNS problems.",
        "configuration" => "Focus on starforge/Soroban configuration issues: malformed config.toml, missing environment variables, and invalid network settings.",
        "deployment" => "Focus on deployment and transaction issues: simulation failures, insufficient balance, invalid WASM, sequence number and fee-bump problems.",
        _ => "",
    };
    format!("{} {}", base, specific)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_error_type_detects_compilation_errors() {
        let text = "error[E0308]: mismatched types\n --> src/lib.rs:10:5";
        assert_eq!(classify_error_type(text), "compilation");
    }

    #[test]
    fn classify_error_type_detects_network_errors() {
        let text = "Error: Connection refused (os error 111) while contacting soroban RPC";
        assert_eq!(classify_error_type(text), "network");
    }

    #[test]
    fn classify_error_type_detects_deployment_errors() {
        let text = "Simulation failed: insufficient balance for transaction fee";
        assert_eq!(classify_error_type(text), "deployment");
    }

    #[test]
    fn classify_error_type_detects_configuration_errors() {
        let text = "Failed to parse config: missing field `network` in config.toml";
        assert_eq!(classify_error_type(text), "configuration");
    }

    #[test]
    fn classify_error_type_detects_runtime_errors() {
        let text = "thread 'main' panicked at 'attempt to subtract with overflow'";
        assert_eq!(classify_error_type(text), "runtime");
    }

    #[test]
    fn classify_error_type_defaults_to_runtime_for_unknown_text() {
        assert_eq!(classify_error_type("something weird happened"), "runtime");
    }
}
