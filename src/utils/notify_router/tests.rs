//! Integration tests for the notification router

use crate::utils::notify_router::events::{
    CommandOutcomeData, Event, EventData, EventType, Severity,
};
use crate::utils::notify_router::filters::{
    self, FieldFilter, FieldOp, Filter, SeverityFilter, StringFilter,
};
use crate::utils::notify_router::outbox::{self, DeliveryStatus, Outbox};
use crate::utils::notify_router::redaction::{redact_secrets, redact_stellar_secrets, redact_text};
use crate::utils::notify_router::rules::{
    self, AdapterType, QuietHoursConfig, RetryPolicy, RoutingRule, Transform,
};
use crate::utils::notify_router::{
    load_or_init_config, save_config, NotificationRouter, RouterConfig,
};
use chrono::{Duration, TimeZone, Utc};
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;
use uuid::Uuid;

#[test]
fn test_router_full_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let config = RouterConfig {
        version: "1".to_string(),
        data_dir,
        rules: vec![],
        dedup_window_seconds: 3600,
    };

    let router = NotificationRouter::new(config).unwrap();

    let event = Event::new(EventType::CommandOutcome, "Test deployment")
        .with_severity(Severity::Info)
        .with_description("Deployment completed successfully")
        .with_correlation_id("test-deploy-123");

    let result = router.route_event(event);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0); // No rules matched
}

#[test]
fn test_router_with_matching_rule_and_delivery() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();
    let output_file = temp_dir.path().join("output.log");

    let mut adapter_config = HashMap::new();
    adapter_config.insert(
        "path".to_string(),
        output_file.to_str().unwrap().to_string(),
    );

    let rule = RoutingRule {
        id: Uuid::new_v4(),
        name: "test-rule".to_string(),
        description: "Test rule".to_string(),
        enabled: true,
        filter: Filter {
            event_type: Some(filters::EventTypeFilter::Equals(
                "command_outcome".to_string(),
            )),
            ..Default::default()
        },
        adapter: AdapterType::File,
        adapter_config,
        retry_policy: RetryPolicy::default(),
        redact_secrets: true,
        payload_transform: None,
        grouping: None,
        throttling: None,
        dedup_window_seconds: None,
        quiet_hours: None,
        severity_mapping: None,
        escalation: None,
        priority: 0,
    };

    let config = RouterConfig {
        version: "1".to_string(),
        data_dir,
        rules: vec![rule],
        dedup_window_seconds: 3600,
    };

    let router = NotificationRouter::new(config).unwrap();

    let event = Event::new(EventType::CommandOutcome, "Build successful")
        .with_severity(Severity::Info)
        .with_description("All crates compiled");

    let enqueued = router.route_event(event).unwrap();
    assert_eq!(enqueued.len(), 1);

    let stats = router.stats().unwrap();
    assert_eq!(stats.pending_tasks, 1);

    // Process delivery
    let delivery_results = router.process_deliveries().unwrap();
    assert_eq!(delivery_results.len(), 1);
    assert!(delivery_results[0].success);

    let stats_after = router.stats().unwrap();
    assert_eq!(stats_after.pending_tasks, 0);
    assert_eq!(stats_after.completed_tasks, 1);

    // Verify file output was written
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("Build successful"));
}

#[test]
fn test_deduplication_prevents_duplicates() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let mut dedup = crate::utils::notify_router::dedup::Deduplicator::new(data_dir).unwrap();

    let event = Event::new(EventType::CommandOutcome, "Test").with_correlation_id("dedup-test-123");

    assert!(!dedup.is_duplicate(&event, None).unwrap());
    dedup.mark_processed(&event).unwrap();
    assert!(dedup.is_duplicate(&event, None).unwrap());
}

#[test]
fn test_outbox_retry_and_dead_letter_logic() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let outbox = Outbox::new(data_dir).unwrap();

    let task_id = Uuid::new_v4();
    let task = outbox::DeliveryTask {
        id: task_id,
        event_id: Uuid::new_v4(),
        rule_id: Uuid::new_v4(),
        idempotency_key: None,
        adapter: AdapterType::Stdout,
        adapter_config: HashMap::new(),
        payload: serde_json::json!({"test": "data"}),
        status: DeliveryStatus::Pending,
        attempts: 0,
        max_attempts: 3,
        next_attempt_at: Some(Utc::now()),
        created_at: Utc::now(),
        last_attempt_at: None,
        completed_at: None,
        error_message: None,
        audit_trail: vec![],
    };

    outbox.enqueue(task).unwrap();

    // Mark retryable failure
    outbox
        .mark_failure(&task_id, "Temporary network timeout", true, 50, 5)
        .unwrap();

    assert_eq!(outbox.pending_count().unwrap(), 1);
    assert_eq!(outbox.dead_letter_count().unwrap(), 0);

    // Exhaust attempts
    let mut t = outbox.get_task(&task_id).unwrap();
    t.attempts = 3;
    outbox.update_task(&t).unwrap();

    outbox
        .mark_failure(&task_id, "Fatal network timeout", false, 50, 5)
        .unwrap();
    assert_eq!(outbox.pending_count().unwrap(), 0);
    assert_eq!(outbox.dead_letter_count().unwrap(), 1);
}

#[test]
fn test_secret_redaction_comprehensive() {
    let mut payload = serde_json::json!({
        "username": "alice",
        "password": "supersecretpassword",
        "api_key": "api_key_12345",
        "auth": {
            "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "access_token": "tok_xyz"
        },
        "nested_array": [
            {"private_key": "privkey123"},
            {"public_key": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT"}
        ],
        "log_message": "Failed auth for user alice with token secret_token_xyz"
    });

    redact_secrets(&mut payload);

    assert_eq!(payload["username"], "alice");
    assert_eq!(payload["password"], "[REDACTED]");
    assert_eq!(payload["api_key"], "[REDACTED]");
    assert_eq!(payload["auth"]["bearer_token"], "[REDACTED]");
    assert_eq!(payload["auth"]["access_token"], "[REDACTED]");
    assert_eq!(payload["nested_array"][0]["private_key"], "[REDACTED]");
    assert_eq!(
        payload["nested_array"][1]["public_key"],
        "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT"
    );
}

#[test]
fn test_stellar_secret_seed_redaction() {
    let seed = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
    let mut payload = serde_json::json!({
        "seed": seed,
        "wallet": "main"
    });

    redact_stellar_secrets(&mut payload);
    let redacted = payload["seed"].as_str().unwrap();
    assert!(redacted.starts_with("SAAZI4TC"));
    assert!(redacted.ends_with("****"));

    let text_with_seed = format!("Signing error with secret {}", seed);
    let sanitized = redact_text(&text_with_seed);
    assert!(!sanitized.contains(seed));
    assert!(sanitized.contains("SAAZ****[REDACTED]"));
}

#[test]
fn test_filter_complex_matching() {
    let event = Event::new(EventType::CommandOutcome, "Deploy contract")
        .with_severity(Severity::Error)
        .with_source("starforge".to_string())
        .with_data(EventData::CommandOutcome(CommandOutcomeData {
            command: "deploy".to_string(),
            exit_code: 1,
            duration_ms: 5000,
            success: false,
            error_message: Some("Contract failed".to_string()),
        }));

    let filter = Filter {
        event_type: Some(filters::EventTypeFilter::Equals(
            "command_outcome".to_string(),
        )),
        severity: Some(SeverityFilter::AtLeast(Severity::Warning)),
        source: Some(StringFilter::Equals("starforge".to_string())),
        fields: Some(vec![FieldFilter {
            path: "data.command".to_string(),
            op: FieldOp::Equals("deploy".to_string()),
        }]),
        ..Default::default()
    };

    assert!(filter.matches(&event));
}

#[test]
fn test_quiet_hours_suppression_and_critical_override() {
    let qh = QuietHoursConfig {
        start: "22:00".to_string(),
        end: "07:00".to_string(),
        allow_critical: true,
    };

    let rule = RoutingRule {
        id: Uuid::new_v4(),
        name: "quiet-rule".to_string(),
        description: "Quiet hours rule".to_string(),
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
        quiet_hours: Some(qh),
        severity_mapping: None,
        escalation: None,
        priority: 0,
    };

    let rules = vec![rule];

    // Info event at 23:30 (during quiet hours) -> should NOT match
    let mut info_event =
        Event::new(EventType::CommandOutcome, "Info at night").with_severity(Severity::Info);
    info_event.timestamp = Utc.with_ymd_and_hms(2026, 8, 30, 23, 30, 0).unwrap();

    let matched_info = rules::find_matching_rules(&info_event, &rules).unwrap();
    assert_eq!(matched_info.len(), 0);

    // Critical event at 23:30 (during quiet hours) -> SHOULD match because allow_critical is true
    let mut crit_event =
        Event::new(EventType::CommandOutcome, "Critical outage").with_severity(Severity::Critical);
    crit_event.timestamp = Utc.with_ymd_and_hms(2026, 8, 30, 23, 30, 0).unwrap();

    let matched_crit = rules::find_matching_rules(&crit_event, &rules).unwrap();
    assert_eq!(matched_crit.len(), 1);
}

#[test]
fn test_corrupt_outbox_entry_quarantine_resilience() {
    let temp_dir = TempDir::new().unwrap();
    let outbox = Outbox::new(temp_dir.path().to_path_buf()).unwrap();

    // Enqueue one valid task
    let valid_id = Uuid::new_v4();
    let task = outbox::DeliveryTask {
        id: valid_id,
        event_id: Uuid::new_v4(),
        rule_id: Uuid::new_v4(),
        idempotency_key: None,
        adapter: AdapterType::Stdout,
        adapter_config: HashMap::new(),
        payload: serde_json::json!({"status": "ok"}),
        status: DeliveryStatus::Pending,
        attempts: 0,
        max_attempts: 3,
        next_attempt_at: Some(Utc::now() - Duration::seconds(10)),
        created_at: Utc::now(),
        last_attempt_at: None,
        completed_at: None,
        error_message: None,
        audit_trail: vec![],
    };
    outbox.enqueue(task).unwrap();

    // Plant a corrupted non-JSON file in outbox/
    let corrupt_file = outbox.outbox_dir().join("bad_task.json");
    fs::write(corrupt_file, "INVALID NOT JSON { [").unwrap();

    assert_eq!(outbox.pending_count().unwrap(), 2);

    // get_pending_tasks should safely quarantine the bad file and return the valid task
    let pending = outbox.get_pending_tasks().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, valid_id);

    assert_eq!(outbox.quarantine_count().unwrap(), 1);
    assert_eq!(outbox.pending_count().unwrap(), 1);
}

#[test]
fn test_payload_transformations() {
    let temp_dir = TempDir::new().unwrap();
    let config = RouterConfig {
        version: "1".to_string(),
        data_dir: temp_dir.path().to_path_buf(),
        rules: vec![],
        dedup_window_seconds: 3600,
    };
    let router = NotificationRouter::new(config).unwrap();

    let event = Event::new(EventType::Deployment, "Mainnet contract deployed")
        .with_severity(Severity::Info)
        .with_source("deploy-tool");

    // Test template transform
    let template_rule = RoutingRule {
        payload_transform: Some(Transform::Template(
            "Alert: [{{severity}}] {{title}} from {{source}}".to_string(),
        )),
        ..Default::default()
    };
    let transformed = router.prepare_payload(&event, &template_rule).unwrap();
    assert_eq!(
        transformed["rendered_message"],
        "Alert: [info] Mainnet contract deployed from deploy-tool"
    );

    // Test include fields transform
    let include_rule = RoutingRule {
        payload_transform: Some(Transform::IncludeFields(vec![
            "id".to_string(),
            "title".to_string(),
        ])),
        ..Default::default()
    };
    let included = router.prepare_payload(&event, &include_rule).unwrap();
    assert!(included.get("id").is_some());
    assert!(included.get("title").is_some());
    assert!(included.get("description").is_none());
}

#[test]
fn test_config_persistence_and_load() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("router_config.json");

    let rule = RoutingRule {
        name: "prod-alerts".to_string(),
        priority: 50,
        ..Default::default()
    };

    let config = RouterConfig {
        version: "1".to_string(),
        data_dir: temp_dir.path().to_path_buf(),
        rules: vec![rule],
        dedup_window_seconds: 7200,
    };

    save_config(&config_path, &config).unwrap();
    let loaded = load_or_init_config(&config_path).unwrap();

    assert_eq!(loaded.version, "1");
    assert_eq!(loaded.dedup_window_seconds, 7200);
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.rules[0].name, "prod-alerts");
    assert_eq!(loaded.rules[0].priority, 50);
}
