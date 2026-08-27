//! Validation and redaction at every trust boundary.

use super::model::{QueryPlan, ReadOnlyQuery, PLAN_SCHEMA_VERSION};
use crate::utils::config;
use anyhow::{Context, Result};
use serde_json::Value;

const MAX_QUESTION_BYTES: usize = 8 * 1024;
const MAX_OPERATIONS: usize = 12;
const MAX_EVENT_LIMIT: u32 = 200;

/// Reject questions that request secrets, local environment data, or a
/// state-changing action. This happens before an AI provider is contacted.
pub fn validate_question(question: &str) -> Result<()> {
    let trimmed = question.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Question cannot be empty.");
    }
    if trimmed.len() > MAX_QUESTION_BYTES {
        anyhow::bail!(
            "Question is too long ({} bytes; maximum is {}).",
            trimmed.len(),
            MAX_QUESTION_BYTES
        );
    }

    let normalized = trimmed.to_ascii_lowercase();
    let secret_phrases = [
        "private key",
        "secret key",
        "seed phrase",
        "recovery phrase",
        "mnemonic",
        "api key",
        "access token",
        "environment variable",
        ".env",
        "wallet password",
    ];
    if let Some(phrase) = secret_phrases
        .iter()
        .find(|phrase| normalized.contains(**phrase))
    {
        anyhow::bail!(
            "Unsafe query rejected: requests involving '{}' may expose secrets. Query only public on-chain data.",
            phrase
        );
    }

    let mutating_phrases = [
        " transfer ",
        " send ",
        " submit ",
        " deploy ",
        " invoke ",
        " mint ",
        " burn ",
        " approve ",
        " upgrade ",
        " write ",
        " change ",
        " update ",
        " delete ",
    ];
    let padded = format!(" {} ", normalized.replace(['\n', '\t'], " "));
    if let Some(phrase) = mutating_phrases
        .iter()
        .find(|phrase| padded.contains(**phrase))
    {
        anyhow::bail!(
            "Unsafe query rejected: '{}' indicates a state-changing operation. `starforge query` is read-only.",
            phrase.trim()
        );
    }
    Ok(())
}

pub fn validate_plan(plan: &QueryPlan) -> Result<()> {
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        anyhow::bail!(
            "Unsupported query plan schema '{}'; expected '{}'. Regenerate the plan with this StarForge version.",
            plan.schema_version,
            PLAN_SCHEMA_VERSION
        );
    }
    validate_question(&plan.question).context("Query plan contains an unsafe question")?;
    config::validate_network(&plan.network).context("Query plan contains an invalid network")?;
    if plan.operations.is_empty() {
        anyhow::bail!("Query plan contains no operations.");
    }
    if plan.operations.len() > MAX_OPERATIONS {
        anyhow::bail!(
            "Query plan contains {} operations; maximum is {}.",
            plan.operations.len(),
            MAX_OPERATIONS
        );
    }

    let mut ids = std::collections::HashSet::new();
    for operation in &plan.operations {
        if operation.id.trim().is_empty() || !ids.insert(operation.id.as_str()) {
            anyhow::bail!("Every planned operation must have a unique, non-empty id.");
        }
        if operation.rationale.trim().is_empty() {
            anyhow::bail!("Operation '{}' is missing its rationale.", operation.id);
        }
        match &operation.query {
            ReadOnlyQuery::LatestLedger => {}
            ReadOnlyQuery::ContractState { contract_id }
            | ReadOnlyQuery::ContractStorage { contract_id, .. }
            | ReadOnlyQuery::ContractEvents { contract_id, .. } => {
                config::validate_contract_id(contract_id).with_context(|| {
                    format!("Operation '{}' has an invalid contract ID", operation.id)
                })?;
            }
            ReadOnlyQuery::Transaction { hash } => validate_transaction_hash(hash)
                .with_context(|| format!("Operation '{}' has an invalid hash", operation.id))?,
        }
        if let ReadOnlyQuery::ContractEvents { limit, .. } = operation.query {
            if limit == 0 || limit > MAX_EVENT_LIMIT {
                anyhow::bail!(
                    "Operation '{}' event limit must be between 1 and {}.",
                    operation.id,
                    MAX_EVENT_LIMIT
                );
            }
        }
    }
    Ok(())
}

pub fn validate_transaction_hash(hash: &str) -> Result<()> {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Expected a 64-character hexadecimal transaction hash.");
    }
    Ok(())
}

/// Recursively redact values before they leave the subsystem. Public contract
/// IDs and transaction hashes are retained because they are query evidence.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut output = serde_json::Map::new();
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("secret")
                    || lower.contains("private_key")
                    || lower.contains("seed")
                    || lower.contains("mnemonic")
                    || lower.contains("authorization")
                    || lower == "token"
                    || lower == "api_key"
                {
                    output.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    output.insert(key.clone(), redact_json(value));
                }
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_json).collect()),
        Value::String(text) => Value::String(redact_text(text)),
        other => other.clone(),
    }
}

pub fn redact_text(text: &str) -> String {
    text.split_whitespace()
        .map(|word| {
            let candidate = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            if candidate.len() == 56 && candidate.starts_with('S') {
                word.replace(candidate, "[REDACTED_SECRET]")
            } else if looks_like_sensitive_path(word) {
                "[REDACTED_PATH]".to_string()
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_like_sensitive_path(text: &str) -> bool {
    text.starts_with("/home/") || text.starts_with("/Users/") || text.starts_with("C:\\Users\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_secret_and_mutating_questions() {
        assert!(validate_question("show my seed phrase").is_err());
        assert!(validate_question("transfer tokens to GABC").is_err());
        assert!(validate_question("show contract storage key").is_ok());
    }

    #[test]
    fn recursively_redacts_sensitive_fields_and_paths() {
        let value = serde_json::json!({
            "secret_key": "SABC",
            "nested": { "message": "/home/alice/private.json" }
        });
        let redacted = redact_json(&value);
        assert_eq!(redacted["secret_key"], "[REDACTED]");
        assert_eq!(redacted["nested"]["message"], "[REDACTED_PATH]");
    }
}
