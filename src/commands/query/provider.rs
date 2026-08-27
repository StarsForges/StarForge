//! Optional AI interpretation with deterministic fallback.

use super::model::{AiPlanEnvelope, PlanSource, PlannedOperation, QueryPlan, ReadOnlyQuery};
use super::{parser, safety};
use anyhow::{Context, Result};
use serde_json::{json, Value};

const DEFAULT_MODEL: &str = "gpt-4";
const DEFAULT_ENDPOINT: &str = "https://api.openai.com/v1/chat/completions";

pub trait PlanProvider {
    fn create_plan(&self, question: &str, network: &str) -> Result<QueryPlan>;
}

pub struct HttpAiProvider {
    endpoint: String,
    api_key: String,
    model: String,
}

impl HttpAiProvider {
    pub fn from_env(model: Option<&str>) -> Result<Self> {
        let api_key = std::env::var("STARFORGE_QUERY_AI_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .context(
                "AI planning requested but STARFORGE_QUERY_AI_API_KEY or OPENAI_API_KEY is not set",
            )?;
        let endpoint = std::env::var("STARFORGE_QUERY_AI_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        validate_provider_endpoint(&endpoint)?;
        Ok(Self {
            endpoint,
            api_key,
            model: model.unwrap_or(DEFAULT_MODEL).to_string(),
        })
    }

    fn request_body(&self, question: &str, network: &str) -> Value {
        let system = r#"You plan read-only Soroban RPC queries. Return JSON only, with shape {"operations":[...]}. Each operation has kind (latest_ledger, contract_state, contract_storage, contract_events, or transaction), rationale, and applicable contract_id, transaction_hash, key, topic, or limit. Never request files, environment variables, credentials, wallets, signing, simulation, submission, invocation, or state changes. Do not invent IDs."#;
        json!({
            "model": self.model,
            "temperature": 0,
            "response_format": { "type": "json_object" },
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": format!("Network: {}\nQuestion: {}", network, question) }
            ]
        })
    }

    fn decode_response(&self, response: Value, question: &str, network: &str) -> Result<QueryPlan> {
        let content = response
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!("AI provider response did not contain message content")
            })?;
        let envelope: AiPlanEnvelope = serde_json::from_str(strip_json_fence(content))
            .context("AI provider returned an invalid query plan")?;
        plan_from_envelope(envelope, question, network)
    }
}

impl PlanProvider for HttpAiProvider {
    fn create_plan(&self, question: &str, network: &str) -> Result<QueryPlan> {
        safety::validate_question(question)?;
        let response: Value = ureq::post(&self.endpoint)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(self.request_body(question, network))
            .context("AI query-planning request failed")?
            .into_json()
            .context("AI query-planning response was not valid JSON")?;
        self.decode_response(response, question, network)
    }
}

/// AI failure is non-fatal when the deterministic parser understands the
/// question. The returned source and warning make the fallback observable.
pub fn plan_with_fallback(
    question: &str,
    network: &str,
    provider: &dyn PlanProvider,
) -> Result<QueryPlan> {
    safety::validate_question(question)?;
    match provider.create_plan(question, network) {
        Ok(plan) => Ok(plan),
        Err(provider_error) => {
            let mut plan = parser::plan(question, network).with_context(|| {
                format!(
                    "AI planning failed ({provider_error:#}) and deterministic fallback could not parse the question"
                )
            })?;
            plan.source = PlanSource::AiFallback;
            plan.warnings.push(format!(
                "AI provider unavailable; deterministic parser used: {}",
                concise_error(&provider_error)
            ));
            Ok(plan)
        }
    }
}

fn plan_from_envelope(
    envelope: AiPlanEnvelope,
    question: &str,
    network: &str,
) -> Result<QueryPlan> {
    if envelope.operations.is_empty() {
        anyhow::bail!("AI provider returned an empty query plan");
    }
    let mut operations = Vec::with_capacity(envelope.operations.len());
    for (index, operation) in envelope.operations.into_iter().enumerate() {
        let missing = |field: &str| {
            anyhow::anyhow!(
                "AI operation {} ({}) is missing {}",
                index + 1,
                operation.kind,
                field
            )
        };
        let query = match operation.kind.as_str() {
            "latest_ledger" => ReadOnlyQuery::LatestLedger,
            "contract_state" => ReadOnlyQuery::ContractState {
                contract_id: operation.contract_id.ok_or_else(|| missing("contract_id"))?,
            },
            "contract_storage" => ReadOnlyQuery::ContractStorage {
                contract_id: operation.contract_id.ok_or_else(|| missing("contract_id"))?,
                key: operation.key,
            },
            "contract_events" => ReadOnlyQuery::ContractEvents {
                contract_id: operation.contract_id.ok_or_else(|| missing("contract_id"))?,
                topic: operation.topic,
                limit: operation.limit.unwrap_or(20),
            },
            "transaction" => ReadOnlyQuery::Transaction {
                hash: operation
                    .transaction_hash
                    .ok_or_else(|| missing("transaction_hash"))?,
            },
            other => anyhow::bail!(
                "AI provider proposed unsupported operation '{}'; only read-only query kinds are accepted",
                other
            ),
        };
        operations.push(PlannedOperation {
            id: format!("op-{}", index + 1),
            query,
            rationale: operation.rationale,
        });
    }
    let plan = QueryPlan::new(question, network, PlanSource::Ai, operations);
    safety::validate_plan(&plan).context("AI query plan failed safety validation")?;
    Ok(plan)
}

fn strip_json_fence(content: &str) -> &str {
    let trimmed = content.trim();
    trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|value| value.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed)
}

fn validate_provider_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.contains('@') {
        anyhow::bail!("AI provider endpoint must not contain embedded credentials.");
    }
    let lower = endpoint.to_ascii_lowercase();
    if !(lower.starts_with("https://")
        || lower.starts_with("http://127.0.0.1:")
        || lower.starts_with("http://localhost:"))
    {
        anyhow::bail!(
            "AI provider endpoint must use HTTPS (plain HTTP is allowed only for localhost test fixtures)."
        );
    }
    Ok(())
}

fn concise_error(error: &anyhow::Error) -> String {
    safety::redact_text(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    struct FailingProvider;
    impl PlanProvider for FailingProvider {
        fn create_plan(&self, _question: &str, _network: &str) -> Result<QueryPlan> {
            anyhow::bail!("fixture provider offline")
        }
    }

    #[test]
    fn falls_back_to_deterministic_parser() {
        let question = format!("inspect contract {}", CONTRACT);
        let plan = plan_with_fallback(&question, "testnet", &FailingProvider).unwrap();
        assert_eq!(plan.source, PlanSource::AiFallback);
        assert!(plan.warnings[0].contains("fixture provider offline"));
    }

    #[test]
    fn rejects_non_tls_remote_provider() {
        assert!(validate_provider_endpoint("http://example.com/v1").is_err());
        assert!(validate_provider_endpoint("http://127.0.0.1:1234/v1").is_ok());
    }
}
