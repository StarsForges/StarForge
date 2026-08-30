//! Routing rules for event notification
//!
//! Defines routing rules, delivery adapters, retry policies, quiet hours,
//! escalation paths, payload transforms, throttling, and grouping configurations.

use crate::utils::notify_router::events::{Event, Severity};
use crate::utils::notify_router::filters::{is_in_quiet_hours, Filter};
use anyhow::{bail, Result};
use chrono::NaiveTime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A routing rule that determines how events are delivered
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingRule {
    /// Unique rule identifier
    pub id: Uuid,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Filter conditions for matching events
    pub filter: Filter,
    /// Delivery adapter type
    pub adapter: AdapterType,
    /// Adapter-specific configuration (URLs, paths, headers, commands)
    pub adapter_config: HashMap<String, String>,
    /// Retry policy for failed deliveries
    pub retry_policy: RetryPolicy,
    /// Whether to redact secrets from payloads
    pub redact_secrets: bool,
    /// Optional payload transformation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_transform: Option<Transform>,
    /// Grouping configuration for batching events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grouping: Option<GroupingConfig>,
    /// Throttling configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttling: Option<ThrottlingConfig>,
    /// Dedicated deduplication window in seconds (overrides router default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dedup_window_seconds: Option<u64>,
    /// Quiet hours suppression window
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_hours: Option<QuietHoursConfig>,
    /// Severity mapping / translation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_mapping: Option<SeverityMappingConfig>,
    /// Escalation policy for retried or high-severity events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation: Option<EscalationConfig>,
    /// Priority for rule evaluation (higher = evaluated first)
    #[serde(default = "default_priority")]
    pub priority: i32,
}

impl Default for RoutingRule {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            description: String::new(),
            enabled: true,
            filter: Filter::default(),
            adapter: AdapterType::Stdout,
            adapter_config: HashMap::new(),
            retry_policy: RetryPolicy::default(),
            redact_secrets: true,
            payload_transform: None,
            grouping: None,
            throttling: None,
            dedup_window_seconds: None,
            quiet_hours: None,
            severity_mapping: None,
            escalation: None,
            priority: default_priority(),
        }
    }
}

fn default_priority() -> i32 {
    0
}

/// Delivery adapter types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AdapterType {
    /// Print to stdout
    Stdout,
    /// Write to file
    File,
    /// Send to webhook (JSON POST)
    Webhook,
    /// Execute external subprocess hook
    Subprocess,
    /// Send email (via webhook-compatible endpoint)
    Email,
    /// Send to chat platform (Slack, Discord webhook)
    Chat,
}

/// Retry policy for failed deliveries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial backoff delay in seconds
    pub initial_backoff_secs: u64,
    /// Backoff multiplier (exponential)
    pub backoff_multiplier: f64,
    /// Maximum backoff delay in seconds
    pub max_backoff_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_secs: 5,
            backoff_multiplier: 2.0,
            max_backoff_secs: 300,
        }
    }
}

impl RetryPolicy {
    /// Calculate backoff delay in seconds for a given attempt index (1-based)
    pub fn calculate_backoff_secs(&self, attempt: u32) -> u64 {
        if attempt <= 1 {
            return self.initial_backoff_secs;
        }

        let factor = self.backoff_multiplier.powi((attempt - 1) as i32);
        let delay = (self.initial_backoff_secs as f64) * factor;
        let delay_u64 = delay.round() as u64;

        delay_u64.min(self.max_backoff_secs).max(1)
    }
}

/// Payload transformation options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// Template-based string substitution
    Template(String),
    /// Keep only specified fields in the payload
    IncludeFields(Vec<String>),
    /// Remove specified fields from the payload
    ExcludeFields(Vec<String>),
    /// Inject custom metadata into payload
    AddMetadata(HashMap<String, String>),
}

/// Grouping configuration for batching events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupingConfig {
    /// Group events by field (e.g., "correlation_id", "source")
    pub group_by: String,
    /// Maximum number of events to batch
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing batch (seconds)
    pub max_wait_secs: u64,
}

/// Throttling / rate-limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThrottlingConfig {
    /// Maximum number of deliveries per window
    pub max_deliveries: u32,
    /// Time window in seconds
    pub window_secs: u64,
}

/// Quiet hours suppression configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuietHoursConfig {
    /// Start time in "HH:MM" 24h format (e.g. "22:00")
    pub start: String,
    /// End time in "HH:MM" 24h format (e.g. "07:00")
    pub end: String,
    /// Whether critical events bypass quiet hours suppression
    #[serde(default = "default_allow_critical")]
    pub allow_critical: bool,
}

fn default_allow_critical() -> bool {
    true
}

/// Severity mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeverityMappingConfig {
    /// Map event severity to a fixed target severity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_severity: Option<Severity>,
    /// Minimum severity floor (elevates lower severities to this floor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
}

/// Escalation configuration for deliveries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EscalationConfig {
    /// Escalate if delivery fails after N attempts
    pub escalate_after_attempts: u32,
    /// Escalate severity to this level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalated_severity: Option<Severity>,
    /// Alternative adapter to escalate delivery to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_adapter: Option<AdapterType>,
    /// Alternative adapter configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_adapter_config: Option<HashMap<String, String>>,
}

/// Find all rules that match an event, taking quiet hours into account, sorted by priority (descending)
pub fn find_matching_rules(event: &Event, rules: &[RoutingRule]) -> Result<Vec<RoutingRule>> {
    let mut matched: Vec<RoutingRule> = rules
        .iter()
        .filter(|rule| {
            if !rule.enabled {
                return false;
            }

            // Check if event matches filter
            if !rule.filter.matches(event) {
                return false;
            }

            // Check quiet hours
            if let Some(ref qh) = rule.quiet_hours {
                let in_quiet = is_in_quiet_hours(&event.timestamp, &qh.start, &qh.end);
                if in_quiet {
                    if qh.allow_critical && event.severity == Severity::Critical {
                        // Allow critical events through quiet hours
                        return true;
                    }
                    return false;
                }
            }

            true
        })
        .cloned()
        .collect();

    // Sort by priority (descending, highest first)
    matched.sort_by(|a, b| b.priority.cmp(&a.priority));

    Ok(matched)
}

/// Validate a routing rule definition
pub fn validate_rule(rule: &RoutingRule) -> Result<()> {
    if rule.name.trim().is_empty() {
        bail!("Rule name cannot be empty");
    }

    if rule.retry_policy.max_attempts == 0 {
        bail!("Retry policy max_attempts must be at least 1");
    }

    if rule.retry_policy.initial_backoff_secs == 0 {
        bail!("Retry policy initial_backoff_secs must be at least 1");
    }

    if rule.retry_policy.backoff_multiplier < 1.0 {
        bail!("Retry policy backoff_multiplier must be >= 1.0");
    }

    // Validate adapter configuration based on type
    match rule.adapter {
        AdapterType::File => {
            let path = rule
                .adapter_config
                .get("path")
                .map(|s| s.trim())
                .unwrap_or("");
            if path.is_empty() {
                bail!("File adapter requires a non-empty 'path' in adapter_config");
            }
        }
        AdapterType::Webhook | AdapterType::Email | AdapterType::Chat => {
            let url = rule
                .adapter_config
                .get("url")
                .map(|s| s.trim())
                .unwrap_or("");
            if url.is_empty() {
                bail!("Webhook/Email/Chat adapter requires a non-empty 'url' in adapter_config");
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                bail!("Adapter URL must begin with 'http://' or 'https://'");
            }
        }
        AdapterType::Subprocess => {
            let command = rule
                .adapter_config
                .get("command")
                .map(|s| s.trim())
                .unwrap_or("");
            if command.is_empty() {
                bail!("Subprocess adapter requires a non-empty 'command' in adapter_config");
            }
        }
        AdapterType::Stdout => {
            // No required fields
        }
    }

    // Validate quiet hours format if specified
    if let Some(ref qh) = rule.quiet_hours {
        if NaiveTime::parse_from_str(&qh.start, "%H:%M").is_err() {
            bail!(
                "Quiet hours start time '{}' must be in HH:MM format",
                qh.start
            );
        }
        if NaiveTime::parse_from_str(&qh.end, "%H:%M").is_err() {
            bail!("Quiet hours end time '{}' must be in HH:MM format", qh.end);
        }
    }

    // Validate throttling if specified
    if let Some(ref th) = rule.throttling {
        if th.max_deliveries == 0 {
            bail!("Throttling max_deliveries must be > 0");
        }
        if th.window_secs == 0 {
            bail!("Throttling window_secs must be > 0");
        }
    }

    // Validate grouping if specified
    if let Some(ref grp) = rule.grouping {
        if grp.group_by.trim().is_empty() {
            bail!("Grouping group_by cannot be empty");
        }
        if grp.max_batch_size == 0 {
            bail!("Grouping max_batch_size must be > 0");
        }
        if grp.max_wait_secs == 0 {
            bail!("Grouping max_wait_secs must be > 0");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::notify_router::events::{Event, EventType};

    #[test]
    fn test_rule_default() {
        let rule = RoutingRule::default();
        assert!(rule.enabled);
        assert_eq!(rule.adapter, AdapterType::Stdout);
        assert_eq!(rule.retry_policy.max_attempts, 3);
    }

    #[test]
    fn test_validate_rule() {
        let mut rule = RoutingRule {
            name: "test".to_string(),
            ..Default::default()
        };
        assert!(validate_rule(&rule).is_ok());

        rule.name = "".to_string();
        assert!(validate_rule(&rule).is_err());

        // File adapter without path
        rule.name = "file-rule".to_string();
        rule.adapter = AdapterType::File;
        assert!(validate_rule(&rule).is_err());

        rule.adapter_config
            .insert("path".to_string(), "/tmp/out.log".to_string());
        assert!(validate_rule(&rule).is_ok());

        // Webhook without valid url
        rule.adapter = AdapterType::Webhook;
        rule.adapter_config.clear();
        rule.adapter_config
            .insert("url".to_string(), "not-a-url".to_string());
        assert!(validate_rule(&rule).is_err());

        rule.adapter_config
            .insert("url".to_string(), "https://example.com/hook".to_string());
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_retry_backoff_calculation() {
        let policy = RetryPolicy {
            max_attempts: 5,
            initial_backoff_secs: 2,
            backoff_multiplier: 2.0,
            max_backoff_secs: 20,
        };

        assert_eq!(policy.calculate_backoff_secs(1), 2);
        assert_eq!(policy.calculate_backoff_secs(2), 4);
        assert_eq!(policy.calculate_backoff_secs(3), 8);
        assert_eq!(policy.calculate_backoff_secs(4), 16);
        assert_eq!(policy.calculate_backoff_secs(5), 20); // capped at max_backoff
    }

    #[test]
    fn test_find_matching_rules_priority() {
        let event = Event::new(EventType::CommandOutcome, "Test");

        let rule1 = RoutingRule {
            id: Uuid::new_v4(),
            name: "rule1".to_string(),
            description: String::new(),
            enabled: true,
            filter: Filter::default(),
            adapter: AdapterType::Stdout,
            adapter_config: HashMap::new(),
            retry_policy: RetryPolicy::default(),
            redact_secrets: true,
            payload_transform: None,
            grouping: None,
            throttling: None,
            dedup_window_seconds: None,
            quiet_hours: None,
            severity_mapping: None,
            escalation: None,
            priority: 5,
        };

        let rule2 = RoutingRule {
            id: Uuid::new_v4(),
            name: "rule2".to_string(),
            description: String::new(),
            enabled: true,
            filter: Filter::default(),
            adapter: AdapterType::Stdout,
            adapter_config: HashMap::new(),
            retry_policy: RetryPolicy::default(),
            redact_secrets: true,
            payload_transform: None,
            grouping: None,
            throttling: None,
            dedup_window_seconds: None,
            quiet_hours: None,
            severity_mapping: None,
            escalation: None,
            priority: 100,
        };

        let rules = vec![rule1, rule2];
        let matched = find_matching_rules(&event, &rules).unwrap();

        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].name, "rule2");
        assert_eq!(matched[1].name, "rule1");
    }
}
