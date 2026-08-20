//! Optional AI-assisted narrative explanations for compliance findings.
//!
//! This layer is strictly additive: it produces a human-friendly
//! explanation string attached to a report, and is never consulted to
//! decide a control's pass/fail status. The deterministic scanner
//! (`super::scanner`) remains the sole authority for that; see
//! `explain_findings`'s tests for a check that explanations cannot mutate a
//! finding's status.
//!
//! `ComplianceExplainer` is a plain (non-`dyn`) trait using native
//! async-fn-in-trait (stable since Rust 1.75), so callers are monomorphized
//! over either [`OpenAiExplainer`] (the real, network-backed implementation)
//! or a test double — no `async-trait` dependency needed, and no network
//! access anywhere in the test suite.

use super::scanner::{ControlFinding, ControlStatus};
use anyhow::{Context, Result};
use async_openai::{
    config::OpenAIConfig,
    types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role},
    Client,
};
use std::collections::BTreeMap;
use std::env;

/// Produces a plain-language explanation for one compliance finding.
///
/// Declared with the explicit `-> impl Future<...> + Send` desugaring
/// (rather than bare `async fn`) so the trait doesn't trigger the
/// `async_fn_in_trait` lint — implementors can still just write a normal
/// `async fn explain(...)`, which satisfies this signature automatically.
pub trait ComplianceExplainer {
    fn explain(
        &self,
        finding: &ControlFinding,
    ) -> impl std::future::Future<Output = Result<String>> + Send;
}

/// Real, network-backed explainer using the same OpenAI-compatible client
/// and environment variables as `starforge ai` (`OPENAI_API_KEY` /
/// `STARFORGE_AI_API_KEY`).
pub struct OpenAiExplainer {
    client: Client<OpenAIConfig>,
    model: String,
}

impl OpenAiExplainer {
    /// Builds a client from the environment, failing fast with a clear
    /// message if no API key is configured. This check happens before any
    /// network client is constructed, so a missing key can never turn into
    /// a hang or a confusing network error.
    pub fn from_env(model: impl Into<String>) -> Result<Self> {
        let api_key = env::var("OPENAI_API_KEY")
            .or_else(|_| env::var("STARFORGE_AI_API_KEY"))
            .context(
                "OPENAI_API_KEY or STARFORGE_AI_API_KEY environment variable not set; \
                 --explain requires an AI provider key. Omit --explain to run a fully local, \
                 deterministic check.",
            )?;
        Ok(Self {
            client: Client::with_config(OpenAIConfig::new().with_api_key(api_key)),
            model: model.into(),
        })
    }
}

impl ComplianceExplainer for OpenAiExplainer {
    async fn explain(&self, finding: &ControlFinding) -> Result<String> {
        let system_prompt = "You are a compliance engineer explaining automated Soroban \
             contract compliance findings to a developer. Be concise (2-4 sentences), \
             plain-language, and actionable. Do not invent legal conclusions; if the finding \
             needs a human legal review, say so explicitly.";
        let user_prompt = format!(
            "Control {} ({}): {}\nSeverity: {}\nStatus: {}\nDetail: {}\nExplain this finding and suggest a concrete next step.",
            finding.control_id, finding.family, finding.title, finding.severity, finding.status, finding.detail
        );

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

        let request = CreateChatCompletionRequest {
            model: self.model.clone(),
            messages,
            ..Default::default()
        };

        let response = self
            .client
            .chat()
            .create(request)
            .await
            .map_err(|e| anyhow::anyhow!("AI explanation request failed: {}", e))?;

        let text = response
            .choices
            .first()
            .and_then(|choice| choice.message.content.clone())
            .unwrap_or_default();
        Ok(text.trim().to_string())
    }
}

/// Generates explanations for every finding that isn't a clean pass or
/// not-applicable — an explanation isn't useful for something that already
/// passed, and this never overrides `finding.status`.
pub async fn explain_findings<E: ComplianceExplainer>(
    explainer: &E,
    findings: &[ControlFinding],
) -> Result<BTreeMap<String, String>> {
    let mut explanations = BTreeMap::new();
    for finding in findings {
        if matches!(
            finding.status,
            ControlStatus::Pass | ControlStatus::NotApplicable
        ) {
            continue;
        }
        let explanation = explainer.explain(finding).await?;
        explanations.insert(finding.control_id.clone(), explanation);
    }
    Ok(explanations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::compliance::framework::{ControlFamily, Severity};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct MockExplainer;

    impl ComplianceExplainer for MockExplainer {
        async fn explain(&self, finding: &ControlFinding) -> Result<String> {
            Ok(format!("mock explanation for {}", finding.control_id))
        }
    }

    struct FailingExplainer;

    impl ComplianceExplainer for FailingExplainer {
        async fn explain(&self, _finding: &ControlFinding) -> Result<String> {
            anyhow::bail!("provider unavailable")
        }
    }

    fn finding(id: &str, status: ControlStatus) -> ControlFinding {
        ControlFinding {
            control_id: id.to_string(),
            family: ControlFamily::AccessControl,
            severity: Severity::High,
            title: "Example".into(),
            status,
            detail: "detail".into(),
        }
    }

    #[tokio::test]
    async fn explain_findings_skips_passing_and_not_applicable() {
        let findings = vec![
            finding("A", ControlStatus::Pass),
            finding("B", ControlStatus::NotApplicable),
            finding("C", ControlStatus::Fail),
        ];
        let explanations = explain_findings(&MockExplainer, &findings).await.unwrap();
        assert_eq!(explanations.len(), 1);
        assert!(explanations.contains_key("C"));
    }

    #[tokio::test]
    async fn explain_findings_does_not_change_finding_status() {
        let findings = vec![finding("C", ControlStatus::Fail)];
        let before = findings[0].status;
        let _ = explain_findings(&MockExplainer, &findings).await.unwrap();
        assert_eq!(findings[0].status, before);
    }

    #[tokio::test]
    async fn explain_findings_propagates_provider_errors() {
        let findings = vec![finding("C", ControlStatus::Fail)];
        let result = explain_findings(&FailingExplainer, &findings).await;
        assert!(result.is_err());
    }

    #[test]
    fn from_env_fails_fast_without_api_key() {
        // Guarded and restored so this never races other tests that read
        // these same process-wide environment variables.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let saved_openai = env::var("OPENAI_API_KEY").ok();
        let saved_starforge = env::var("STARFORGE_AI_API_KEY").ok();
        unsafe {
            env::remove_var("OPENAI_API_KEY");
            env::remove_var("STARFORGE_AI_API_KEY");
        }

        // No network call should ever be attempted: the key check happens
        // before any client is constructed.
        let result = OpenAiExplainer::from_env("gpt-4");
        assert!(result.is_err());

        unsafe {
            if let Some(v) = saved_openai {
                env::set_var("OPENAI_API_KEY", v);
            }
            if let Some(v) = saved_starforge {
                env::set_var("STARFORGE_AI_API_KEY", v);
            }
        }
    }
}
