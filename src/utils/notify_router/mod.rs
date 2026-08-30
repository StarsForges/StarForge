//! Notification Router - Rules-based event routing with deduplication and delivery guarantees
//!
//! This module provides production-grade notification routing for StarForge events,
//! supporting multiple delivery adapters, deduplication windows, retry backoff,
//! dead-letter handling, audit logging, secret redaction, quiet hours, and escalation.

pub mod adapters;
pub mod dedup;
pub mod events;
pub mod filters;
pub mod outbox;
pub mod redaction;
pub mod rules;
#[cfg(test)]
pub mod tests;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

/// Current schema version of the notification router
pub const ROUTER_VERSION: &str = "1";

/// Core notification router orchestrator
#[derive(Clone)]
pub struct NotificationRouter {
    pub config: RouterConfig,
    pub outbox: Arc<outbox::Outbox>,
    pub dedup: Arc<RwLock<dedup::Deduplicator>>,
}

impl NotificationRouter {
    /// Create a new notification router with the given configuration
    pub fn new(config: RouterConfig) -> Result<Self> {
        let data_dir = config.data_dir.clone();
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)
                .with_context(|| format!("Failed to create router directory: {:?}", data_dir))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700));
            }
        }

        let outbox = Arc::new(outbox::Outbox::new(data_dir.clone())?);
        let dedup = Arc::new(RwLock::new(
            dedup::Deduplicator::new(data_dir.clone())?.with_window(config.dedup_window_seconds),
        ));

        Ok(Self {
            config,
            outbox,
            dedup,
        })
    }

    /// Route an event through the rule engine and queue for delivery
    pub fn route_event(&self, event: events::Event) -> Result<Vec<Uuid>> {
        // Validate event structure
        event.validate()?;

        // Append to events history log
        self.record_event_log(&event)?;

        // Check for deduplication
        {
            let dedup = self.dedup.read().unwrap();
            if dedup.is_duplicate(&event, None)? {
                tracing::debug!("Event {} is duplicate, skipping", event.id);
                return Ok(vec![]);
            }
        }

        // Find matching rules (respecting quiet hours and priority)
        let matched_rules = rules::find_matching_rules(&event, &self.config.rules)?;

        if matched_rules.is_empty() {
            tracing::debug!("No rules matched event {}", event.id);
            return Ok(vec![]);
        }

        let mut enqueued_task_ids = Vec::new();

        // Create delivery tasks for each matched rule
        for rule in &matched_rules {
            // Check if rule has its own dedup window override
            if let Some(rule_dedup_window) = rule.dedup_window_seconds {
                let dedup = self.dedup.read().unwrap();
                if dedup.is_duplicate(&event, Some(rule_dedup_window))? {
                    tracing::debug!(
                        "Event {} duplicate under rule {} window, skipping rule",
                        event.id,
                        rule.name
                    );
                    continue;
                }
            }

            let task_id = Uuid::new_v4();
            let payload = self.prepare_payload(&event, rule)?;

            let task = outbox::DeliveryTask {
                id: task_id,
                event_id: event.id,
                rule_id: rule.id,
                idempotency_key: event.idempotency_key.clone(),
                adapter: rule.adapter.clone(),
                adapter_config: rule.adapter_config.clone(),
                payload,
                status: outbox::DeliveryStatus::Pending,
                attempts: 0,
                max_attempts: rule.retry_policy.max_attempts,
                next_attempt_at: Some(Utc::now()),
                created_at: Utc::now(),
                last_attempt_at: None,
                completed_at: None,
                error_message: None,
                audit_trail: Vec::new(),
            };

            self.outbox.enqueue(task)?;
            enqueued_task_ids.push(task_id);
        }

        // Mark event as processed for deduplication
        {
            let mut dedup = self.dedup.write().unwrap();
            dedup.mark_processed(&event)?;
        }

        tracing::info!(
            "Routed event {} to {} rules ({} tasks)",
            event.id,
            matched_rules.len(),
            enqueued_task_ids.len()
        );

        Ok(enqueued_task_ids)
    }

    /// Prepare the event payload for delivery with transformations and redaction
    pub fn prepare_payload(
        &self,
        event: &events::Event,
        rule: &rules::RoutingRule,
    ) -> Result<serde_json::Value> {
        let mut modified_event = event.clone();

        // Apply severity mapping if rule specifies it
        if let Some(ref sm) = rule.severity_mapping {
            if let Some(target) = sm.target_severity {
                modified_event.severity = target;
            } else if let Some(min) = sm.min_severity {
                if modified_event.severity < min {
                    modified_event.severity = min;
                }
            }
        }

        let mut payload = serde_json::to_value(&modified_event)?;

        // Apply secret redaction
        if rule.redact_secrets {
            redaction::redact_secrets(&mut payload);
            redaction::redact_stellar_secrets(&mut payload);
        }

        // Apply any payload transformations from the rule
        if let Some(ref transform) = rule.payload_transform {
            payload = self.apply_transform(payload, transform)?;
        }

        Ok(payload)
    }

    /// Apply a payload transformation
    fn apply_transform(
        &self,
        payload: serde_json::Value,
        transform: &rules::Transform,
    ) -> Result<serde_json::Value> {
        match transform {
            rules::Transform::Template(template) => {
                let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let ev_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let severity = payload
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let title = payload.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let source = payload.get("source").and_then(|v| v.as_str()).unwrap_or("");

                let rendered = template
                    .replace("{{id}}", id)
                    .replace("{{type}}", ev_type)
                    .replace("{{event_type}}", ev_type)
                    .replace("{{severity}}", severity)
                    .replace("{{title}}", title)
                    .replace("{{source}}", source);

                Ok(serde_json::json!({
                    "rendered_message": rendered,
                    "event": payload
                }))
            }
            rules::Transform::IncludeFields(fields) => {
                if let serde_json::Value::Object(map) = payload {
                    let mut filtered = serde_json::Map::new();
                    for field in fields {
                        if let Some(val) = map.get(field) {
                            filtered.insert(field.clone(), val.clone());
                        }
                    }
                    Ok(serde_json::Value::Object(filtered))
                } else {
                    Ok(payload)
                }
            }
            rules::Transform::ExcludeFields(fields) => {
                if let serde_json::Value::Object(mut map) = payload {
                    for field in fields {
                        map.remove(field);
                    }
                    Ok(serde_json::Value::Object(map))
                } else {
                    Ok(payload)
                }
            }
            rules::Transform::AddMetadata(meta) => {
                let mut p = payload;
                if let Some(obj) = p.as_object_mut() {
                    let metadata = obj
                        .entry("metadata")
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                    if let Some(m_obj) = metadata.as_object_mut() {
                        for (k, v) in meta {
                            m_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
                        }
                    }
                }
                Ok(p)
            }
        }
    }

    /// Process all pending delivery tasks in outbox
    pub fn process_deliveries(&self) -> Result<Vec<outbox::DeliveryResult>> {
        let pending = self.outbox.get_pending_tasks()?;
        let mut results = Vec::new();

        for task in pending {
            let result = self.deliver_task(&task);
            results.push(result);
        }

        Ok(results)
    }

    /// Deliver a single task with timing and retry/escalation backoff
    pub fn deliver_task(&self, task: &outbox::DeliveryTask) -> outbox::DeliveryResult {
        let start = Instant::now();

        let matching_rule = self.config.rules.iter().find(|r| r.id == task.rule_id);
        let fallback_config_storage;
        let (active_adapter_type, active_config) = if let Some(rule) = matching_rule {
            if let Some(ref esc) = rule.escalation {
                if task.attempts >= esc.escalate_after_attempts {
                    if let Some(ref fallback) = esc.fallback_adapter {
                        fallback_config_storage = esc
                            .fallback_adapter_config
                            .clone()
                            .unwrap_or_else(|| task.adapter_config.clone());
                        (fallback, &fallback_config_storage)
                    } else {
                        (&task.adapter, &task.adapter_config)
                    }
                } else {
                    (&task.adapter, &task.adapter_config)
                }
            } else {
                (&task.adapter, &task.adapter_config)
            }
        } else {
            (&task.adapter, &task.adapter_config)
        };

        let adapter = adapters::create_adapter(active_adapter_type, active_config);

        match adapter.deliver(&task.payload) {
            Ok(_) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let _ = self.outbox.mark_success(&task.id, duration_ms);
                outbox::DeliveryResult {
                    task_id: task.id,
                    success: true,
                    error: None,
                    duration_ms,
                }
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let err_msg = e.to_string();

                // Compute retry policy delay
                let retry_policy = matching_rule
                    .map(|r| &r.retry_policy)
                    .cloned()
                    .unwrap_or_default();

                let should_retry = task.attempts < task.max_attempts;
                let backoff_secs = retry_policy.calculate_backoff_secs(task.attempts);

                let _ = self.outbox.mark_failure(
                    &task.id,
                    &err_msg,
                    should_retry,
                    duration_ms,
                    backoff_secs,
                );

                outbox::DeliveryResult {
                    task_id: task.id,
                    success: false,
                    error: Some(err_msg),
                    duration_ms,
                }
            }
        }
    }

    /// Append event to the local events.jsonl audit log
    fn record_event_log(&self, event: &events::Event) -> Result<()> {
        let events_file = self.config.data_dir.join("events.jsonl");

        let mut file_opts = OpenOptions::new();
        file_opts.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file_opts.mode(0o600);
        }

        let mut file = file_opts
            .open(&events_file)
            .with_context(|| format!("Failed to open events log file: {:?}", events_file))?;

        let line = serde_json::to_string(event)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Get router statistics
    pub fn stats(&self) -> Result<RouterStats> {
        let dedup = self.dedup.read().unwrap();
        Ok(RouterStats {
            pending_tasks: self.outbox.pending_count()?,
            completed_tasks: self.outbox.completed_count()?,
            dead_letter_count: self.outbox.dead_letter_count()?,
            quarantine_count: self.outbox.quarantine_count()?,
            dedup_window_size: dedup.window_size(),
            active_rules_count: self.config.rules.iter().filter(|r| r.enabled).count(),
        })
    }
}

/// Router configuration file schema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouterConfig {
    pub version: String,
    pub data_dir: PathBuf,
    pub rules: Vec<rules::RoutingRule>,
    pub dedup_window_seconds: u64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            version: ROUTER_VERSION.to_string(),
            data_dir: default_data_dir(),
            rules: Vec::new(),
            dedup_window_seconds: 3600, // 1 hour default
        }
    }
}

/// Get the default storage data directory `~/.starforge/notify`
pub fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".starforge")
        .join("notify")
}

/// Router runtime statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterStats {
    pub pending_tasks: usize,
    pub completed_tasks: usize,
    pub dead_letter_count: usize,
    pub quarantine_count: usize,
    pub dedup_window_size: usize,
    pub active_rules_count: usize,
}

/// Load and migrate router configuration from disk if needed
pub fn load_or_init_config(path: &Path) -> Result<RouterConfig> {
    if !path.exists() {
        let default_config = RouterConfig::default();
        save_config(path, &default_config)?;
        return Ok(default_config);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read router configuration from {:?}", path))?;

    let val: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| "Failed to parse router configuration JSON")?;

    // Migration logic
    let config: RouterConfig = serde_json::from_value(val)
        .with_context(|| "Failed to deserialize router configuration")?;

    Ok(config)
}

/// Save router configuration atomically with restrictive permissions
pub fn save_config(path: &Path, config: &RouterConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }

    let content = serde_json::to_string_pretty(config)?;
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, &content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&temp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_router_config_default() {
        let config = RouterConfig::default();
        assert_eq!(config.version, ROUTER_VERSION);
        assert_eq!(config.dedup_window_seconds, 3600);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("router_config.json");

        let config = RouterConfig {
            dedup_window_seconds: 1800,
            ..Default::default()
        };

        save_config(&config_path, &config).unwrap();
        let loaded = load_or_init_config(&config_path).unwrap();

        assert_eq!(loaded.dedup_window_seconds, 1800);
    }
}
