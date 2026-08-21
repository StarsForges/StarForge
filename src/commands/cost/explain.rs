//! AI-assisted cost explanations with a deterministic fallback.
//!
//! Mirrors the `commands::ai::impact` shape: the deterministic engine always
//! computes a complete, usable explanation first; an AI narrative (when
//! enabled and reachable) only augments it. A failed or disabled AI call
//! never blocks the estimate from being useful.

use crate::commands::ai::impact::redactor::redact_text;
use crate::commands::cost::model::CostEstimate;
use anyhow::{Context, Result};
use async_openai::{
    config::OpenAIConfig,
    types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role},
    Client,
};
use std::env;

/// Builds the deterministic, rule-based explanation of cost drivers,
/// optimization opportunities, and budget risk. This always succeeds and
/// requires no network access, so it is safe to run in CI and as the
/// fallback when AI assistance is disabled or unavailable.
pub fn deterministic_explanation(estimate: &CostEstimate) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Cost drivers for {} on {} ({} stroops / {:.7} XLM total):",
        estimate.operation.as_str(),
        estimate.network,
        estimate.total_fee_stroops,
        estimate.total_fee_xlm
    ));

    for (name, amount) in estimate.breakdown.ranked_components() {
        let pct = (amount as f64 / estimate.total_fee_stroops.max(1) as f64) * 100.0;
        lines.push(format!("  - {}: {} stroops ({:.1}%)", name, amount, pct));
    }

    lines.push(String::new());
    lines.push("Optimization opportunities:".to_string());
    let mut suggestions = Vec::new();
    if estimate.breakdown.write_fee_stroops > estimate.breakdown.read_fee_stroops * 2 {
        suggestions.push(
            "Ledger writes dominate; consider batching writes or reducing persisted entry size."
                .to_string(),
        );
    }
    if estimate.resource_usage.event_bytes > 0 && estimate.breakdown.event_fee_stroops > 0 {
        suggestions.push(
            "Contract emits sizeable event payloads; trimming event data reduces fee linearly."
                .to_string(),
        );
    }
    if estimate.batch_size > 1 {
        suggestions.push(format!(
            "Already batching {} items — verify this is the optimal batch size for your \
             throughput/fee tradeoff.",
            estimate.batch_size
        ));
    }
    if suggestions.is_empty() {
        suggestions.push(
            "No obvious optimization opportunities detected from resource usage alone.".to_string(),
        );
    }
    for s in suggestions {
        lines.push(format!("  - {}", s));
    }

    lines.push(String::new());
    lines.push("Budget risk:".to_string());
    match estimate.archival_ledgers_until_expiry {
        Some(n) if n <= 0 => lines.push(
            "  - HIGH: target entry is archived; every access now carries a restore penalty."
                .to_string(),
        ),
        Some(n) => lines.push(format!(
            "  - Entry has {} ledgers until expiry; monitor for archival-driven cost increases.",
            n
        )),
        None => {
            lines.push("  - No archival/TTL data supplied; unable to assess rent risk.".to_string())
        }
    }

    lines.join("\n")
}

/// Attempts to generate an AI narrative that augments the deterministic
/// explanation with free-form commentary. Returns `Ok(None)` (never an error
/// visible to the caller as a hard failure) when no API key is configured, so
/// callers can decide how to present "AI unavailable" vs. an actual API
/// error. Prompts and responses are redacted before leaving/entering this
/// function.
pub async fn maybe_generate_ai_narrative(
    estimate: &CostEstimate,
    model: &str,
) -> Result<Option<String>> {
    let api_key = match env::var("OPENAI_API_KEY").or_else(|_| env::var("STARFORGE_AI_API_KEY")) {
        Ok(key) => key,
        Err(_) => return Ok(None),
    };

    let client = Client::with_config(OpenAIConfig::new().with_api_key(api_key));
    let narrative = generate_ai_narrative(&client, estimate, model).await?;
    Ok(Some(narrative))
}

async fn generate_ai_narrative(
    client: &Client<OpenAIConfig>,
    estimate: &CostEstimate,
    model: &str,
) -> Result<String> {
    let breakdown_str = estimate
        .breakdown
        .ranked_components()
        .iter()
        .map(|(name, amount)| format!("- {}: {} stroops", name, amount))
        .collect::<Vec<_>>()
        .join("\n");

    let notes_str = estimate.notes.join("\n- ");

    let prompt = format!(
        "Explain the economics of the following Soroban {} operation on {}:\n\n\
        Total fee: {} stroops ({:.7} XLM)\n\
        Batch size: {}\n\
        Cost breakdown:\n{}\n\n\
        Deterministic engine notes:\n- {}\n\n\
        Write a concise explanation (3-5 short paragraphs) covering: (1) what is driving this \
        cost, (2) concrete optimization opportunities specific to this resource profile, and \
        (3) any budget or archival risk a developer should plan for.",
        estimate.operation.as_str(),
        estimate.network,
        estimate.total_fee_stroops,
        estimate.total_fee_xlm,
        estimate.batch_size,
        breakdown_str,
        notes_str,
    );
    let redacted_prompt = redact_text(&prompt);

    let system_prompt = "You are a Soroban smart-contract cost and economics advisor. Be concrete \
        and quantitative; do not restate the raw numbers without interpreting them.";

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(redacted_prompt),
            name: None,
            function_call: None,
        },
    ];

    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = crate::commands::ai::execute_chat(client, "cost_estimation", model, request)
        .await
        .context("Failed to generate AI cost narrative")?;

    let text = response
        .choices
        .first()
        .and_then(|c| c.message.content.as_deref())
        .unwrap_or("No narrative generated by the AI provider.")
        .trim();

    Ok(redact_text(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cost::model::{estimate_cost, OperationKind, ResourceUsage};

    #[test]
    fn deterministic_explanation_mentions_dominant_driver() {
        let usage = ResourceUsage {
            write_entries: 5,
            write_bytes: 1000,
            ..Default::default()
        };
        let estimate = estimate_cost(&usage, OperationKind::Invoke, "testnet", 1, None);
        let explanation = deterministic_explanation(&estimate);
        assert!(explanation.contains("Cost drivers"));
        assert!(explanation.contains("Optimization opportunities"));
        assert!(explanation.contains("Budget risk"));
    }

    #[test]
    fn deterministic_explanation_flags_archived_entry_as_high_risk() {
        let usage = ResourceUsage::default();
        let estimate = estimate_cost(&usage, OperationKind::Archival, "testnet", 1, Some(-10));
        let explanation = deterministic_explanation(&estimate);
        assert!(explanation.contains("HIGH"));
    }

    #[tokio::test]
    async fn missing_api_key_yields_none_not_error() {
        // SAFETY: test-only env var mutation, scoped to this process; no
        // other test in this crate reads/writes these two variables.
        unsafe {
            env::remove_var("OPENAI_API_KEY");
            env::remove_var("STARFORGE_AI_API_KEY");
        }
        let usage = ResourceUsage::default();
        let estimate = estimate_cost(&usage, OperationKind::Invoke, "testnet", 1, None);
        let result = maybe_generate_ai_narrative(&estimate, "gpt-4")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
