//! Local, offline security training curriculum: lessons with short
//! explanations plus interactive multiple-choice exercises, and persisted
//! per-topic progress used to power personalized "what to study next"
//! recommendations.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizQuestion {
    pub prompt: String,
    pub options: Vec<String>,
    /// 0-based index into `options`.
    pub correct_index: usize,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lesson {
    pub topic: String,
    pub title: String,
    pub summary: String,
    pub content: Vec<String>,
    pub questions: Vec<QuizQuestion>,
}

/// The built-in curriculum. Kept in code (rather than loaded from disk) so
/// `starforge ai security-training` works offline out of the box.
pub fn all_lessons() -> Vec<Lesson> {
    vec![
        Lesson {
            topic: "secure-coding".into(),
            title: "Secure Coding Practices for Soroban".into(),
            summary: "Foundational habits that prevent whole classes of contract bugs.".into(),
            content: vec![
                "Prefer checked arithmetic (`checked_add`, `checked_sub`) over raw operators; Soroban integers can overflow/underflow.".into(),
                "Validate every external input (amounts, addresses, indexes) before using it in storage keys or arithmetic.".into(),
                "Use `require_auth()` on every function that moves funds or changes privileged state — never infer authorization from `invoker()` alone.".into(),
                "Keep secrets and admin keys out of contract storage in plaintext; store only public keys and verify signatures.".into(),
            ],
            questions: vec![
                QuizQuestion {
                    prompt: "Why prefer `checked_add` over `+` for token amounts in a Soroban contract?".into(),
                    options: vec![
                        "It is required by the Rust compiler".into(),
                        "It returns `None` on overflow instead of silently wrapping or panicking in release mode".into(),
                        "It is faster than `+`".into(),
                        "It automatically logs the operation".into(),
                    ],
                    correct_index: 1,
                    explanation: "Checked arithmetic surfaces overflow as a value you must handle, closing off a common source of accounting bugs.".into(),
                },
                QuizQuestion {
                    prompt: "What is the safest way to authorize a fund-moving function?".into(),
                    options: vec![
                        "Trust the `from` address passed as an argument".into(),
                        "Call `from.require_auth()` so the invoker must have signed for that address".into(),
                        "Check that `env.invoker()` is not the zero address".into(),
                        "Log the caller and review logs later".into(),
                    ],
                    correct_index: 1,
                    explanation: "`require_auth()` cryptographically ties the call to the address's signature — arguments alone can be spoofed by any caller.".into(),
                },
            ],
        },
        Lesson {
            topic: "vulnerability-patterns".into(),
            title: "Common Vulnerability Patterns".into(),
            summary: "Recognize the shapes of bugs that show up again and again in smart contracts.".into(),
            content: vec![
                "Reentrancy: an external call (e.g. cross-contract invoke) can re-enter your contract before state updates finish. Update state before making external calls.".into(),
                "Access-control gaps: forgetting `require_auth()` on an admin-only function lets anyone call it.".into(),
                "Integer overflow/underflow: unchecked math on balances or counters can wrap around to huge or negative-looking values.".into(),
                "Front-running: predictable outcomes of pending transactions can be exploited by observers submitting their own transaction first.".into(),
            ],
            questions: vec![
                QuizQuestion {
                    prompt: "What is the standard mitigation for reentrancy?".into(),
                    options: vec![
                        "Disable all cross-contract calls".into(),
                        "Follow checks-effects-interactions: update your own state before calling out to another contract".into(),
                        "Add more comments explaining the risk".into(),
                        "Increase the gas limit".into(),
                    ],
                    correct_index: 1,
                    explanation: "If state is already updated before the external call, a reentrant call sees consistent state and can't double-spend.".into(),
                },
                QuizQuestion {
                    prompt: "A function that changes the contract admin has no `require_auth()` call. What's the risk?".into(),
                    options: vec![
                        "None, Soroban blocks unauthorized writes automatically".into(),
                        "Slightly slower execution".into(),
                        "Any caller can reassign the admin role, taking over the contract".into(),
                        "The function will fail to compile".into(),
                    ],
                    correct_index: 2,
                    explanation: "Without an auth check, privileged functions are open to anyone who can submit a transaction.".into(),
                },
            ],
        },
        Lesson {
            topic: "threat-modeling".into(),
            title: "Threat Modeling for Contract Design".into(),
            summary: "Think like an attacker before you write the first line of code.".into(),
            content: vec![
                "Enumerate trust boundaries: who can call each function, and what do they need to already control to abuse it?".into(),
                "List your contract's assets (funds, admin rights, data) and rank them by impact if compromised.".into(),
                "Consider economic attackers, not just technical ones — is there a profitable way to misuse legitimate functionality?".into(),
                "Model upgrade and migration paths as attack surface too: who can trigger an upgrade, and what could a malicious upgrade do?".into(),
            ],
            questions: vec![
                QuizQuestion {
                    prompt: "What is the first step in threat modeling a new contract?".into(),
                    options: vec![
                        "Write the test suite".into(),
                        "Identify assets and trust boundaries before implementation".into(),
                        "Deploy to mainnet and observe".into(),
                        "Optimize for gas".into(),
                    ],
                    correct_index: 1,
                    explanation: "Understanding what's valuable and who can touch it shapes every subsequent design and review decision.".into(),
                },
            ],
        },
        Lesson {
            topic: "security-testing".into(),
            title: "Security Testing Techniques".into(),
            summary: "Go beyond happy-path unit tests.".into(),
            content: vec![
                "Write negative tests: calls that should fail (unauthorized caller, invalid amount, double-spend attempt) and assert they do.".into(),
                "Fuzz numeric inputs at the boundaries: 0, 1, max value, max value + 1.".into(),
                "Use `starforge lint` and `starforge ai analyze --analysis-type security` as automated first passes, not replacements for manual review.".into(),
                "Test upgrade paths explicitly: deploy v1, exercise it, upgrade to v2, and verify state and invariants survive.".into(),
            ],
            questions: vec![
                QuizQuestion {
                    prompt: "Why are 'negative' tests (expected failures) important for contract security?".into(),
                    options: vec![
                        "They increase code coverage numbers only".into(),
                        "They prove that invalid or unauthorized operations are correctly rejected, not just that valid ones succeed".into(),
                        "They are required by the Soroban SDK".into(),
                        "They replace the need for an audit".into(),
                    ],
                    correct_index: 1,
                    explanation: "A contract that only ever proves the happy path works can still be wide open to misuse it never tested against.".into(),
                },
            ],
        },
        Lesson {
            topic: "incident-response".into(),
            title: "Incident Response Basics".into(),
            summary: "What to do in the first hour after something goes wrong.".into(),
            content: vec![
                "Have a pause/circuit-breaker mechanism designed in from day one if your contract can hold significant value.".into(),
                "Know in advance who can trigger an emergency pause and how quickly (multisig quorum, timelock, etc.).".into(),
                "Prepare a communication plan: users need accurate, fast updates more than a perfect root-cause explanation.".into(),
                "After containment, preserve on-chain evidence (transaction hashes, block heights) before writing the post-mortem.".into(),
            ],
            questions: vec![
                QuizQuestion {
                    prompt: "Why design a pause mechanism before it's needed rather than during an incident?".into(),
                    options: vec![
                        "It's a regulatory requirement everywhere".into(),
                        "Adding privileged controls under pressure, during a live incident, is itself a security risk".into(),
                        "It makes the contract cheaper to deploy".into(),
                        "It removes the need for monitoring".into(),
                    ],
                    correct_index: 1,
                    explanation: "Rushed, unreviewed changes to a live contract during an incident can introduce new bugs or new attack surface.".into(),
                },
            ],
        },
        Lesson {
            topic: "compliance".into(),
            title: "Compliance-Aware Development".into(),
            summary: "Understand the non-technical constraints that shape contract design.".into(),
            content: vec![
                "Know what data your contract stores on-chain — on-chain data is permanent and public, which has privacy implications.".into(),
                "If your project touches regulated activity (payments, securities-like tokens), involve legal review early, not after launch.".into(),
                "Keep an audit trail: telemetry and logs (see `starforge telemetry`) help demonstrate operational diligence after the fact.".into(),
                "Document upgrade governance clearly — regulators and auditors both want to know who can change contract behavior.".into(),
            ],
            questions: vec![
                QuizQuestion {
                    prompt: "Why does on-chain data storage carry compliance risk?".into(),
                    options: vec![
                        "On-chain data is encrypted by default".into(),
                        "On-chain data is public and effectively permanent, so storing personal data on-chain can violate privacy regulations".into(),
                        "It has no compliance relevance".into(),
                        "It only matters for mainnet, not testnet".into(),
                    ],
                    correct_index: 1,
                    explanation: "Once written, on-chain data can't be deleted the way a database row can — plan data minimization accordingly.".into(),
                },
            ],
        },
    ]
}

pub fn find_lesson(topic: &str) -> Option<Lesson> {
    all_lessons().into_iter().find(|l| l.topic == topic)
}

pub fn topic_slugs() -> Vec<String> {
    all_lessons().into_iter().map(|l| l.topic).collect()
}

// ── Progress tracking ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopicProgress {
    pub attempts: usize,
    pub correct: usize,
    pub completed: bool,
    pub last_studied_at: Option<String>,
}

impl TopicProgress {
    pub fn accuracy(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            self.correct as f64 / self.attempts as f64 * 100.0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrainingStatus {
    pub active_topic: Option<String>,
    pub current_question: usize,
    #[serde(default)]
    pub progress: BTreeMap<String, TopicProgress>,
}

fn status_path() -> Result<PathBuf> {
    let base =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Unable to resolve home directory"))?;
    Ok(base
        .join(".starforge")
        .join("security_training_status.json"))
}

pub fn load_status() -> Result<TrainingStatus> {
    let path = status_path()?;
    if !path.exists() {
        return Ok(TrainingStatus::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes).unwrap_or_default())
}

pub fn save_status(status: &TrainingStatus) -> Result<()> {
    let path = status_path()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(status)?;
    fs::write(&path, bytes)?;
    Ok(())
}

/// Recommend the next topic to study: unattempted topics first (in
/// curriculum order), then the attempted-but-not-completed topic with the
/// lowest quiz accuracy. Returns `None` once everything is completed.
pub fn recommend_topic(status: &TrainingStatus) -> Option<String> {
    let lessons = all_lessons();

    if let Some(l) = lessons.iter().find(|l| {
        !status
            .progress
            .get(&l.topic)
            .map(|p| p.attempts > 0)
            .unwrap_or(false)
    }) {
        return Some(l.topic.clone());
    }

    lessons
        .iter()
        .filter(|l| {
            !status
                .progress
                .get(&l.topic)
                .map(|p| p.completed)
                .unwrap_or(false)
        })
        .min_by(|a, b| {
            let acc_a = status
                .progress
                .get(&a.topic)
                .map(|p| p.accuracy())
                .unwrap_or(0.0);
            let acc_b = status
                .progress
                .get(&b.topic)
                .map(|p| p.accuracy())
                .unwrap_or(0.0);
            acc_a
                .partial_cmp(&acc_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|l| l.topic.clone())
}

/// Overall completion percentage across the whole curriculum.
pub fn overall_completion_percent(status: &TrainingStatus) -> f64 {
    let total = all_lessons().len();
    if total == 0 {
        return 0.0;
    }
    let completed = status.progress.values().filter(|p| p.completed).count();
    completed as f64 / total as f64 * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_lesson_has_at_least_one_question() {
        for lesson in all_lessons() {
            assert!(
                !lesson.questions.is_empty(),
                "lesson '{}' has no questions",
                lesson.topic
            );
            for q in &lesson.questions {
                assert!(q.correct_index < q.options.len());
            }
        }
    }

    #[test]
    fn topic_slugs_are_unique() {
        let slugs = topic_slugs();
        let mut deduped = slugs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(slugs.len(), deduped.len());
    }

    #[test]
    fn find_lesson_returns_none_for_unknown_topic() {
        assert!(find_lesson("not-a-real-topic").is_none());
    }

    #[test]
    fn recommend_prioritizes_unattempted_topics() {
        let status = TrainingStatus::default();
        let rec = recommend_topic(&status).unwrap();
        assert_eq!(rec, topic_slugs()[0]);
    }

    #[test]
    fn recommend_falls_back_to_lowest_accuracy_incomplete_topic() {
        let mut status = TrainingStatus::default();
        for topic in topic_slugs() {
            status.progress.insert(
                topic.clone(),
                TopicProgress {
                    attempts: 2,
                    correct: 2,
                    completed: false,
                    last_studied_at: None,
                },
            );
        }
        let weak_topic = topic_slugs()[2].clone();
        status.progress.insert(
            weak_topic.clone(),
            TopicProgress {
                attempts: 4,
                correct: 1,
                completed: false,
                last_studied_at: None,
            },
        );
        assert_eq!(recommend_topic(&status), Some(weak_topic));
    }

    #[test]
    fn recommend_returns_none_when_everything_completed() {
        let mut status = TrainingStatus::default();
        for topic in topic_slugs() {
            status.progress.insert(
                topic,
                TopicProgress {
                    attempts: 1,
                    correct: 1,
                    completed: true,
                    last_studied_at: None,
                },
            );
        }
        assert!(recommend_topic(&status).is_none());
    }

    #[test]
    fn overall_completion_tracks_completed_topics() {
        let mut status = TrainingStatus::default();
        assert_eq!(overall_completion_percent(&status), 0.0);
        let total = topic_slugs().len();
        status.progress.insert(
            topic_slugs()[0].clone(),
            TopicProgress {
                attempts: 1,
                correct: 1,
                completed: true,
                last_studied_at: None,
            },
        );
        let expected = 1.0 / total as f64 * 100.0;
        assert!((overall_completion_percent(&status) - expected).abs() < 1e-9);
    }
}
