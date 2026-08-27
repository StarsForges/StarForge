//! Deterministic intent parsing for common Soroban questions.

use super::model::{PlanSource, PlannedOperation, QueryPlan, ReadOnlyQuery};
use super::safety;
use anyhow::{Context, Result};

pub fn plan(question: &str, network: &str) -> Result<QueryPlan> {
    safety::validate_question(question)?;
    crate::utils::config::validate_network(network)?;

    let normalized = question.to_ascii_lowercase();
    let contract_id = find_contract_id(question);
    let transaction_hash = find_transaction_hash(question);
    let mut operations = Vec::new();

    if contains_any(
        &normalized,
        &["latest ledger", "ledger height", "current ledger"],
    ) {
        push(
            &mut operations,
            ReadOnlyQuery::LatestLedger,
            "Read the latest ledger sequence from Soroban RPC.",
        );
    }

    if contains_any(&normalized, &["event", "emitted", "log"])
        && !normalized.contains("ledger event")
    {
        let id = require_contract_id(contract_id.as_deref(), "event")?;
        push(
            &mut operations,
            ReadOnlyQuery::ContractEvents {
                contract_id: id.to_string(),
                topic: extract_quoted_value(question, &["topic"]),
                limit: extract_limit(question).unwrap_or(20),
            },
            "Fetch recent contract events with a bounded read-only filter.",
        );
    }

    if contains_any(
        &normalized,
        &["storage", "state", "data", "value", "balance"],
    ) && contract_id.is_some()
    {
        let id = contract_id.as_deref().expect("checked above");
        let explicit_storage = contains_any(&normalized, &["storage", "key", "value", "balance"]);
        let query = if explicit_storage {
            ReadOnlyQuery::ContractStorage {
                contract_id: id.to_string(),
                key: extract_quoted_value(question, &["key", "storage"]),
            }
        } else {
            ReadOnlyQuery::ContractState {
                contract_id: id.to_string(),
            }
        };
        push(
            &mut operations,
            query,
            "Inspect the public contract instance ledger entry without simulating or submitting a transaction.",
        );
    }

    if contains_any(
        &normalized,
        &["contract info", "contract details", "inspect contract"],
    ) && contract_id.is_some()
        && !operations.iter().any(|op| {
            matches!(
                op.query,
                ReadOnlyQuery::ContractState { .. } | ReadOnlyQuery::ContractStorage { .. }
            )
        })
    {
        push(
            &mut operations,
            ReadOnlyQuery::ContractState {
                contract_id: contract_id.clone().expect("checked above"),
            },
            "Inspect the public contract instance ledger entry.",
        );
    }

    if contains_any(&normalized, &["transaction", "tx status", "tx hash"])
        || (transaction_hash.is_some() && operations.is_empty())
    {
        let hash = transaction_hash.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "Transaction query needs a 64-character hexadecimal hash. Include it in the question."
            )
        })?;
        push(
            &mut operations,
            ReadOnlyQuery::Transaction {
                hash: hash.to_string(),
            },
            "Read transaction status and result from Soroban RPC.",
        );
    }

    if operations.is_empty() {
        if let Some(id) = contract_id {
            push(
                &mut operations,
                ReadOnlyQuery::ContractState { contract_id: id },
                "Inspect the referenced public contract instance.",
            );
        } else {
            anyhow::bail!(
                "Could not map the question to a safe deterministic query. Ask about contract state, storage, events, a transaction hash, or the latest ledger; include a contract ID where applicable. Use --ai for assisted interpretation."
            );
        }
    }

    let plan = QueryPlan::new(
        question.trim(),
        network,
        PlanSource::Deterministic,
        operations,
    );
    safety::validate_plan(&plan).context("Generated query plan failed safety validation")?;
    Ok(plan)
}

fn push(operations: &mut Vec<PlannedOperation>, query: ReadOnlyQuery, rationale: &str) {
    operations.push(PlannedOperation {
        id: format!("op-{}", operations.len() + 1),
        query,
        rationale: rationale.to_string(),
    });
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn require_contract_id<'a>(id: Option<&'a str>, intent: &str) -> Result<&'a str> {
    id.ok_or_else(|| {
        anyhow::anyhow!(
            "{} query needs a 56-character Soroban contract ID beginning with C.",
            intent
        )
    })
}

pub fn find_contract_id(text: &str) -> Option<String> {
    tokens(text).find(|token| {
        token.len() == 56
            && token.starts_with('C')
            && token.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
    })
}

pub fn find_transaction_hash(text: &str) -> Option<String> {
    tokens(text).find(|token| token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
}

fn tokens(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split_whitespace().map(|token| {
        token
            .trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_string()
    })
}

fn extract_quoted_value(question: &str, labels: &[&str]) -> Option<String> {
    let lower = question.to_ascii_lowercase();
    for label in labels {
        let start = lower.find(label)? + label.len();
        let suffix = question.get(start..)?.trim_start();
        let quote = suffix.chars().next()?;
        if quote != '\'' && quote != '"' {
            continue;
        }
        let rest = &suffix[quote.len_utf8()..];
        if let Some(end) = rest.find(quote) {
            let value = rest[..end].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_limit(question: &str) -> Option<u32> {
    let words: Vec<_> = question.split_whitespace().collect();
    words.windows(2).find_map(|pair| {
        if pair[0].eq_ignore_ascii_case("limit") || pair[0].eq_ignore_ascii_case("last") {
            pair[1]
                .trim_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn maps_multi_intent_question_deterministically() {
        let question = format!("show the last 5 events and storage for {}", CONTRACT);
        let plan = plan(&question, "testnet").unwrap();
        assert_eq!(plan.operations.len(), 2);
        assert!(matches!(
            plan.operations[0].query,
            ReadOnlyQuery::ContractEvents { limit: 5, .. }
        ));
        assert!(matches!(
            plan.operations[1].query,
            ReadOnlyQuery::ContractStorage { .. }
        ));
    }

    #[test]
    fn maps_transaction_hash() {
        let plan = plan(
            &format!("what happened to transaction {}?", HASH),
            "testnet",
        )
        .unwrap();
        assert!(matches!(
            plan.operations[0].query,
            ReadOnlyQuery::Transaction { .. }
        ));
    }

    #[test]
    fn asks_for_missing_required_identifier() {
        let error = plan("show recent contract events", "testnet").unwrap_err();
        assert!(error.to_string().contains("contract ID"));
    }
}
