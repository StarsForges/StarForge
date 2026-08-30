//! AI client for recovery narratives — calls the OpenAI-compatible API
//! with fully redacted prompts and redacts the response before returning.

use anyhow::Result;
use async_openai::{config::OpenAIConfig, types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role}, Client};

use super::model::{RecoveryPlan, RecoveryReport};
use crate::commands::ai::impact::redactor::redact_text;

/// Request a narrative risk assessment from the AI provider for `plan`.
/// The prompt is fully redacted before transmission; the response is redacted
/// before being returned to the caller.
pub async fn request_narrative(
    client: &Client<OpenAIConfig>,
    plan: &RecoveryPlan,
    model: &str,
) -> Result<String> {
    let summary = format!(
        "Recovery plan summary: network={}, artifacts={}, risk_score={}, risk_level={}, factors=[{}]",
        plan.network,
        plan.artifacts.len(),
        plan.risk_score,
        plan.risk_level.as_str(),
        plan.risk_factors.iter().map(|f| format!("{} (+{})", f.description, f.points)).collect::<Vec<_>>().join("; ")
    );
    let prompt = redact_text(&summary);

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some("You are a Soroban contract disaster-recovery expert. Given a recovery plan summary, provide a concise narrative risk assessment and the top remediation steps. Do not include any secret keys or sensitive paths.".to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(prompt),
            name: None,
            function_call: None,
        },
    ];

    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = crate::commands::ai::execute_chat(client, "recovery_narrative", model, request).await?;
    let raw = response.choices.first()
        .and_then(|c| c.message.content.as_deref())
        .unwrap_or("")
        .to_string();

    Ok(redact_text(&raw))
}

/// Request remediation suggestions from the AI provider for `report`.
pub async fn request_remediation(
    client: &Client<OpenAIConfig>,
    report: &RecoveryReport,
    model: &str,
) -> Result<String> {
    let summary = format!(
        "Recovery report: risk_score={}, risk_level={}, recommendations=[{}]",
        report.plan.risk_score,
        report.plan.risk_level.as_str(),
        report.recommendations.iter().map(|r| r.description.as_str()).collect::<Vec<_>>().join("; ")
    );
    let prompt = redact_text(&summary);

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some("You are a Soroban contract disaster-recovery expert. Given a recovery report summary, provide a concise narrative with prioritized remediation steps. Do not include secret keys or sensitive paths.".to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(prompt),
            name: None,
            function_call: None,
        },
    ];

    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = crate::commands::ai::execute_chat(client, "recovery_remediation", model, request).await?;
    let raw = response.choices.first()
        .and_then(|c| c.message.content.as_deref())
        .unwrap_or("")
        .to_string();

    Ok(redact_text(&raw))
}
