//! AI-assisted incident explanations with a deterministic fallback.
//!
//! Mirrors `commands::cost::explain`: the deterministic engine always
//! produces a complete, usable incident summary first; an AI narrative (when
//! enabled and reachable) only augments it. A missing API key, network
//! failure, or disabled AI never blocks an incident report from being useful
//! — it just falls back to the deterministic summary alone.

use super::model::Alert;
use crate::commands::ai::impact::redactor::redact_text;
use anyhow::{Context, Result};
use async_openai::{
    config::OpenAIConfig,
    types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role},
    Client,
};
use std::env;

/// Builds a deterministic, rule-based incident explanation from a set of
/// alerts covering one incident window. Always succeeds and requires no
/// network access.
pub fn deterministic_explanation(alerts: &[Alert]) -> String {
    if alerts.is_empty() {
        return "No anomalies were detected in the selected window.".to_string();
    }

    let mut lines = Vec::new();
    let contract = &alerts[0].contract_id;
    let network = &alerts[0].network;
    lines.push(format!(
        "Incident summary for {} on {}: {} anomaly alert(s) detected.",
        contract,
        network,
        alerts.len()
    ));
    lines.push(String::new());

    let critical = alerts
        .iter()
        .filter(|a| a.severity == super::model::Severity::Critical)
        .count();
    let high = alerts
        .iter()
        .filter(|a| a.severity == super::model::Severity::High)
        .count();
    if critical > 0 || high > 0 {
        lines.push(format!(
            "Severity breakdown: {} critical, {} high, {} other.",
            critical,
            high,
            alerts.len() - critical - high
        ));
    } else {
        lines.push(format!(
            "Severity breakdown: {} low/medium alert(s), no critical or high findings.",
            alerts.len()
        ));
    }
    lines.push(String::new());

    lines.push("Alerts:".to_string());
    for alert in alerts {
        lines.push(format!(
            "  - [{}] {} ({}): {}{}",
            alert.severity,
            alert.kind.as_str(),
            alert.metric,
            alert.message,
            if alert.used_fallback_threshold {
                " (deterministic fallback threshold — baseline still warming up)"
            } else {
                ""
            }
        ));
    }
    lines.push(String::new());

    lines.push("Suggested next steps:".to_string());
    let mut steps = Vec::new();
    if alerts
        .iter()
        .any(|a| a.kind == super::model::AnomalyKind::SuspiciousPayload)
    {
        steps.push(
            "Inspect the flagged event payloads directly; suspicious-pattern matches warrant \
             manual review before assuming they are benign."
                .to_string(),
        );
    }
    if alerts
        .iter()
        .any(|a| a.kind == super::model::AnomalyKind::UnusualCallers)
    {
        steps.push(
            "Cross-reference the new callers against known integrators/allowlists to rule out \
             a compromised key or unexpected integration."
                .to_string(),
        );
    }
    if alerts
        .iter()
        .any(|a| a.kind == super::model::AnomalyKind::ErrorRateShift)
    {
        steps.push(
            "Check recent contract or dependency upgrades that may have introduced regressions \
             causing the elevated error rate."
                .to_string(),
        );
    }
    if alerts
        .iter()
        .any(|a| a.kind == super::model::AnomalyKind::FeeResourceRegression)
    {
        steps.push(
            "Profile the contract (`starforge profile run`) to confirm whether resource usage \
             has genuinely regressed or a caller is passing pathological inputs."
                .to_string(),
        );
    }
    if alerts
        .iter()
        .any(|a| a.kind == super::model::AnomalyKind::HealthDegradation)
    {
        steps.push(
            "Verify RPC endpoint availability independently; this may be an infrastructure issue \
             rather than a contract-level anomaly."
                .to_string(),
        );
    }
    if steps.is_empty() {
        steps.push("Continue monitoring; no specific remediation is indicated yet.".to_string());
    }
    for s in steps {
        lines.push(format!("  - {}", s));
    }

    lines.join("\n")
}

/// Attempts to generate an AI narrative augmenting the deterministic
/// explanation. Returns `Ok(None)` (never a hard error) when no API key is
/// configured. Prompts and responses are redacted before leaving/entering
/// this function.
pub async fn maybe_generate_ai_narrative(alerts: &[Alert], model: &str) -> Result<Option<String>> {
    if alerts.is_empty() {
        return Ok(None);
    }
    let api_key = match env::var("OPENAI_API_KEY").or_else(|_| env::var("STARFORGE_AI_API_KEY")) {
        Ok(key) => key,
        Err(_) => return Ok(None),
    };

    let client = Client::with_config(OpenAIConfig::new().with_api_key(api_key));
    let narrative = generate_ai_narrative(&client, alerts, model).await?;
    Ok(Some(narrative))
}

async fn generate_ai_narrative(
    client: &Client<OpenAIConfig>,
    alerts: &[Alert],
    model: &str,
) -> Result<String> {
    let alerts_str = alerts
        .iter()
        .map(|a| {
            format!(
                "- [{}] {} on metric '{}': observed={:.2}, expected_mean={}, z_score={}. {}",
                a.severity,
                a.kind.as_str(),
                a.metric,
                a.observed_value,
                a.expected_mean
                    .map(|v| format!("{:.2}", v))
                    .unwrap_or_else(|| "n/a".to_string()),
                a.deviation_score
                    .map(|v| format!("{:.2}", v))
                    .unwrap_or_else(|| "n/a".to_string()),
                a.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let prompt = format!(
        "A Soroban smart contract monitoring system detected the following anomalies for \
         contract {} on {}:\n\n{}\n\n\
         Write a concise incident explanation (3-5 short paragraphs) covering: (1) what is most \
         likely happening operationally or from a security perspective, (2) how urgently a \
         human should investigate, and (3) concrete next diagnostic steps specific to these \
         findings.",
        alerts[0].contract_id, alerts[0].network, alerts_str,
    );
    let redacted_prompt = redact_text(&prompt);

    let system_prompt = "You are a Soroban smart-contract security and reliability incident \
        responder. Be concrete, avoid restating raw numbers without interpreting them, and do \
        not speculate beyond what the data supports.";

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

    let response = crate::commands::ai::execute_chat(client, "anomaly_incident", model, request)
        .await
        .context("Failed to generate AI incident narrative")?;

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
    use crate::commands::anomaly::model::{AnomalyKind, Severity};
    use chrono::Utc;

    fn sample_alert(kind: AnomalyKind, severity: Severity) -> Alert {
        Alert {
            schema_version: 1,
            id: "id-1".to_string(),
            timestamp: Utc::now(),
            contract_id: "CFOO".to_string(),
            network: "testnet".to_string(),
            kind,
            severity,
            metric: "event_count".to_string(),
            observed_value: 1000.0,
            expected_mean: Some(100.0),
            deviation_score: Some(5.0),
            message: "volume spike detected".to_string(),
            used_fallback_threshold: false,
            dedup_key: "key".to_string(),
        }
    }

    #[test]
    fn deterministic_explanation_handles_empty_alerts() {
        let explanation = deterministic_explanation(&[]);
        assert!(explanation.contains("No anomalies"));
    }

    #[test]
    fn deterministic_explanation_summarizes_severity_and_steps() {
        let alerts = vec![sample_alert(
            AnomalyKind::SuspiciousPayload,
            Severity::Critical,
        )];
        let explanation = deterministic_explanation(&alerts);
        assert!(explanation.contains("Incident summary"));
        assert!(explanation.contains("critical"));
        assert!(explanation.contains("Inspect the flagged event payloads"));
    }

    #[test]
    fn deterministic_explanation_flags_fallback_threshold_alerts() {
        let mut alert = sample_alert(AnomalyKind::VolumeSpike, Severity::Medium);
        alert.used_fallback_threshold = true;
        let explanation = deterministic_explanation(&[alert]);
        assert!(explanation.contains("deterministic fallback threshold"));
    }

    #[tokio::test]
    async fn missing_api_key_yields_none_not_error() {
        // SAFETY: test-only env var mutation, scoped to this process.
        unsafe {
            env::remove_var("OPENAI_API_KEY");
            env::remove_var("STARFORGE_AI_API_KEY");
        }
        let alerts = vec![sample_alert(AnomalyKind::VolumeSpike, Severity::Medium)];
        let result = maybe_generate_ai_narrative(&alerts, "gpt-4").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn empty_alerts_yields_none_without_checking_api_key() {
        let result = maybe_generate_ai_narrative(&[], "gpt-4").await.unwrap();
        assert!(result.is_none());
    }
}
