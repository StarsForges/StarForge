//! Notification router CLI commands
//!
//! Provides CLI subcommands for routing rules management, event testing/emission,
//! outbox retry orchestration, dead-letter inspections, and metrics.

use crate::utils::notify_router::events::{Event, EventData, EventType, Severity};
use crate::utils::notify_router::filters::{EventTypeFilter, Filter, SeverityFilter, StringFilter};
use crate::utils::notify_router::outbox::Outbox;
use crate::utils::notify_router::rules::{
    validate_rule, AdapterType, EscalationConfig, GroupingConfig, QuietHoursConfig, RetryPolicy,
    RoutingRule, ThrottlingConfig,
};
use crate::utils::notify_router::{
    default_data_dir, load_or_init_config, save_config, NotificationRouter,
};
use crate::utils::print as p;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Subcommand)]
pub enum NotifyCommands {
    /// Manage notification routing rules
    #[command(subcommand)]
    Routes(RoutesCommands),
    /// Test event delivery against rules without emitting
    Test(TestArgs),
    /// List, inspect, and emit operational events
    #[command(subcommand)]
    Events(EventsCommands),
    /// Retry failed outbox deliveries
    #[command(subcommand)]
    Retry(RetryCommands),
    /// Inspect and manage dead-letter queue
    #[command(subcommand)]
    DeadLetter(DeadLetterCommands),
    /// Show router statistics and queue metrics
    Stats(StatsArgs),
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum RoutesCommands {
    /// List all configured routing rules
    List {
        /// Output results in JSON format for automation
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Add a new notification routing rule
    Add {
        /// Unique rule name
        #[arg(long)]
        name: String,
        /// Rule description
        #[arg(long, default_value = "")]
        description: String,
        /// Event type filter (e.g. command_outcome, transaction_state, deployment, health_change)
        #[arg(long)]
        event_type: Option<String>,
        /// Minimum severity filter (info, warning, error, critical)
        #[arg(long)]
        severity: Option<String>,
        /// Source filter pattern
        #[arg(long)]
        source: Option<String>,
        /// Delivery adapter (stdout, file, webhook, subprocess, email, chat)
        #[arg(long)]
        adapter: String,
        /// Adapter configuration (key=value pairs, e.g. --adapter-config url=https://... --adapter-config timeout_secs=10)
        #[arg(long, value_parser = parse_key_value)]
        adapter_config: Vec<(String, String)>,
        /// Maximum retry attempts on failure
        #[arg(long, default_value = "3")]
        max_attempts: u32,
        /// Initial backoff delay in seconds
        #[arg(long, default_value = "5")]
        initial_backoff: u64,
        /// Whether to redact secrets from notification payloads
        #[arg(long, default_value = "true")]
        redact_secrets: bool,
        /// Rule priority (higher value = evaluated first)
        #[arg(long, default_value = "0")]
        priority: i32,
        /// Quiet hours start time (HH:MM format, e.g. 22:00)
        #[arg(long)]
        quiet_start: Option<String>,
        /// Quiet hours end time (HH:MM format, e.g. 07:00)
        #[arg(long)]
        quiet_end: Option<String>,
        /// Whether critical events bypass quiet hours
        #[arg(long, default_value = "true")]
        allow_critical_in_quiet: bool,
        /// Throttling: max deliveries per window
        #[arg(long)]
        throttle_max: Option<u32>,
        /// Throttling: window size in seconds
        #[arg(long)]
        throttle_window: Option<u64>,
        /// Grouping: field name to group events by (e.g. correlation_id)
        #[arg(long)]
        group_by: Option<String>,
        /// Grouping: maximum batch size
        #[arg(long, default_value = "10")]
        group_max_batch: usize,
        /// Grouping: maximum wait time in seconds
        #[arg(long, default_value = "60")]
        group_max_wait: u64,
        /// Deduplication window in seconds (overrides global default)
        #[arg(long)]
        dedup_window: Option<u64>,
        /// Escalation: retry threshold to trigger fallback adapter
        #[arg(long)]
        escalate_attempts: Option<u32>,
        /// Escalation: fallback adapter type
        #[arg(long)]
        escalate_adapter: Option<String>,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Remove a routing rule by ID or name
    Remove {
        /// Rule ID or name
        identifier: String,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Enable a routing rule
    Enable {
        /// Rule ID or name
        identifier: String,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Disable a routing rule
    Disable {
        /// Rule ID or name
        identifier: String,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Test a specific routing rule against a synthetic event
    TestRule {
        /// Rule ID or name
        identifier: String,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum EventsCommands {
    /// List recent events from audit log
    List {
        /// Number of events to show
        #[arg(long, default_value = "10")]
        limit: usize,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Show details of a specific event
    Show {
        /// Event ID (UUID)
        event_id: String,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Emit a new operational event into the router
    Emit {
        /// Event type (command_outcome, transaction_state, deployment, health_change, etc.)
        #[arg(long)]
        event_type: String,
        /// Event title
        #[arg(long)]
        title: String,
        /// Event severity (info, warning, error, critical)
        #[arg(long, default_value = "info")]
        severity: String,
        /// Event description
        #[arg(long)]
        description: Option<String>,
        /// Event source
        #[arg(long, default_value = "starforge-cli")]
        source: String,
        /// Correlation ID
        #[arg(long)]
        correlation_id: Option<String>,
        /// Idempotency key
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Raw JSON data payload
        #[arg(long)]
        data: Option<String>,
        /// Immediately process deliveries synchronously
        #[arg(long, default_value = "true")]
        process: bool,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum RetryCommands {
    /// Retry all failed dead-letter deliveries
    All {
        /// Process immediately after reenqueuing
        #[arg(long, default_value = "true")]
        process: bool,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Retry a specific task from dead-letter queue
    Task {
        /// Task ID (UUID)
        task_id: String,
        /// Process immediately after reenqueuing
        #[arg(long, default_value = "true")]
        process: bool,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum DeadLetterCommands {
    /// List all dead-letter tasks
    List {
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Show full details of a dead-letter task
    Show {
        /// Task ID (UUID)
        task_id: String,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Retry a dead-letter task
    Retry {
        /// Task ID (UUID)
        task_id: String,
        /// Process immediately
        #[arg(long, default_value = "true")]
        process: bool,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Purge all tasks from the dead-letter queue
    Purge {
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
    /// Prune completed and dead-letter tasks older than N days
    Prune {
        /// Age threshold in days
        #[arg(long, default_value = "30")]
        days: u64,
        /// Output in JSON format
        #[arg(long, default_value = "false")]
        json: bool,
    },
}

#[derive(Parser)]
pub struct TestArgs {
    /// Event type to test
    #[arg(long)]
    pub event_type: String,
    /// Event severity
    #[arg(long, default_value = "info")]
    pub severity: String,
    /// Event title
    #[arg(long)]
    pub title: String,
    /// Event description
    #[arg(long)]
    pub description: Option<String>,
    /// Event source
    #[arg(long, default_value = "starforge-test")]
    pub source: String,
    /// Test against a specific rule ID or name only
    #[arg(long)]
    pub rule_id: Option<String>,
    /// Output in JSON format
    #[arg(long, default_value = "false")]
    pub json: bool,
}

#[derive(Parser)]
pub struct StatsArgs {
    /// Output in JSON format
    #[arg(long, default_value = "false")]
    pub json: bool,
}

pub fn handle(args: NotifyCommands) -> Result<()> {
    match args {
        NotifyCommands::Routes(cmd) => handle_routes(cmd),
        NotifyCommands::Test(cmd) => handle_test(cmd),
        NotifyCommands::Events(cmd) => handle_events(cmd),
        NotifyCommands::Retry(cmd) => handle_retry(cmd),
        NotifyCommands::DeadLetter(cmd) => handle_dead_letter(cmd),
        NotifyCommands::Stats(cmd) => handle_stats(cmd),
    }
}

fn handle_routes(cmd: RoutesCommands) -> Result<()> {
    match cmd {
        RoutesCommands::List { json } => list_routes(json),
        RoutesCommands::Add {
            name,
            description,
            event_type,
            severity,
            source,
            adapter,
            adapter_config,
            max_attempts,
            initial_backoff,
            redact_secrets,
            priority,
            quiet_start,
            quiet_end,
            allow_critical_in_quiet,
            throttle_max,
            throttle_window,
            group_by,
            group_max_batch,
            group_max_wait,
            dedup_window,
            escalate_attempts,
            escalate_adapter,
            json,
        } => add_route(AddRouteParams {
            name,
            description,
            event_type,
            severity,
            source,
            adapter,
            adapter_config,
            max_attempts,
            initial_backoff,
            redact_secrets,
            priority,
            quiet_start,
            quiet_end,
            allow_critical_in_quiet,
            throttle_max,
            throttle_window,
            group_by,
            group_max_batch,
            group_max_wait,
            dedup_window,
            escalate_attempts,
            escalate_adapter,
            json,
        }),
        RoutesCommands::Remove { identifier, json } => remove_route(identifier, json),
        RoutesCommands::Enable { identifier, json } => enable_route(identifier, json),
        RoutesCommands::Disable { identifier, json } => disable_route(identifier, json),
        RoutesCommands::TestRule { identifier, json } => test_route(identifier, json),
    }
}

fn list_routes(json_output: bool) -> Result<()> {
    let config_path = get_config_path()?;
    let config = load_or_init_config(&config_path)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&config.rules)?);
        return Ok(());
    }

    p::header("Notification Routing Rules");
    p::separator();

    if config.rules.is_empty() {
        p::warn("No routing rules configured. Use `starforge notify routes add` to create one.");
        return Ok(());
    }

    for (i, rule) in config.rules.iter().enumerate() {
        let status_str = if rule.enabled {
            "ENABLED".green()
        } else {
            "DISABLED".red()
        };

        println!("\n  {}. {} [{}]", i + 1, rule.name.bold(), status_str);
        println!("     ID:          {}", rule.id);
        if !rule.description.is_empty() {
            println!("     Description: {}", rule.description);
        }
        println!("     Adapter:     {:?}", rule.adapter);
        println!("     Priority:    {}", rule.priority);
        println!("     Retries:     max {}", rule.retry_policy.max_attempts);
        println!("     Redact:      {}", rule.redact_secrets);

        if let Some(ref qh) = rule.quiet_hours {
            println!("     Quiet Hours: {} - {}", qh.start, qh.end);
        }
        if let Some(ref th) = rule.throttling {
            println!(
                "     Throttling:  max {} deliveries per {}s",
                th.max_deliveries, th.window_secs
            );
        }
    }

    p::separator();
    Ok(())
}

struct AddRouteParams {
    name: String,
    description: String,
    event_type: Option<String>,
    severity: Option<String>,
    source: Option<String>,
    adapter: String,
    adapter_config: Vec<(String, String)>,
    max_attempts: u32,
    initial_backoff: u64,
    redact_secrets: bool,
    priority: i32,
    quiet_start: Option<String>,
    quiet_end: Option<String>,
    allow_critical_in_quiet: bool,
    throttle_max: Option<u32>,
    throttle_window: Option<u64>,
    group_by: Option<String>,
    group_max_batch: usize,
    group_max_wait: u64,
    dedup_window: Option<u64>,
    escalate_attempts: Option<u32>,
    escalate_adapter: Option<String>,
    json: bool,
}

fn add_route(params: AddRouteParams) -> Result<()> {
    let config_path = get_config_path()?;
    let mut config = load_or_init_config(&config_path)?;

    // Check if name already exists
    if config.rules.iter().any(|r| r.name == params.name) {
        bail!("A routing rule named '{}' already exists", params.name);
    }

    let adapter_type = parse_adapter_type(&params.adapter)?;

    let mut config_map: HashMap<String, String> = HashMap::new();
    for (k, v) in params.adapter_config {
        config_map.insert(k, v);
    }

    let mut filter = Filter::new();
    if let Some(et) = params.event_type {
        filter.event_type = Some(EventTypeFilter::Equals(et));
    }
    if let Some(sev) = params.severity {
        filter.severity = Some(SeverityFilter::AtLeast(sev.parse::<Severity>()?));
    }
    if let Some(src) = params.source {
        filter.source = Some(StringFilter::Equals(src));
    }

    let quiet_hours = match (params.quiet_start, params.quiet_end) {
        (Some(start), Some(end)) => Some(QuietHoursConfig {
            start,
            end,
            allow_critical: params.allow_critical_in_quiet,
        }),
        _ => None,
    };

    let throttling = match (params.throttle_max, params.throttle_window) {
        (Some(max), Some(win)) => Some(ThrottlingConfig {
            max_deliveries: max,
            window_secs: win,
        }),
        _ => None,
    };

    let grouping = params.group_by.map(|gb| GroupingConfig {
        group_by: gb,
        max_batch_size: params.group_max_batch,
        max_wait_secs: params.group_max_wait,
    });

    let escalation = match (params.escalate_attempts, params.escalate_adapter) {
        (Some(att), Some(adap)) => Some(EscalationConfig {
            escalate_after_attempts: att,
            escalated_severity: None,
            fallback_adapter: Some(parse_adapter_type(&adap)?),
            fallback_adapter_config: None,
        }),
        _ => None,
    };

    let rule = RoutingRule {
        id: Uuid::new_v4(),
        name: params.name,
        description: params.description,
        enabled: true,
        filter,
        adapter: adapter_type,
        adapter_config: config_map,
        retry_policy: RetryPolicy {
            max_attempts: params.max_attempts,
            initial_backoff_secs: params.initial_backoff,
            ..Default::default()
        },
        redact_secrets: params.redact_secrets,
        payload_transform: None,
        grouping,
        throttling,
        dedup_window_seconds: params.dedup_window,
        quiet_hours,
        severity_mapping: None,
        escalation,
        priority: params.priority,
    };

    validate_rule(&rule)?;
    config.rules.push(rule.clone());
    save_config(&config_path, &config)?;

    if params.json {
        println!("{}", serde_json::to_string_pretty(&rule)?);
    } else {
        p::success(&format!(
            "Routing rule '{}' added successfully (ID: {})",
            rule.name, rule.id
        ));
    }

    Ok(())
}

fn remove_route(identifier: String, json_output: bool) -> Result<()> {
    let config_path = get_config_path()?;
    let mut config = load_or_init_config(&config_path)?;

    let original_len = config.rules.len();
    config
        .rules
        .retain(|rule| rule.id.to_string() != identifier && rule.name != identifier);

    if config.rules.len() == original_len {
        bail!("No routing rule found matching '{}'", identifier);
    }

    save_config(&config_path, &config)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "status": "removed", "identifier": identifier })
        );
    } else {
        p::success(&format!("Removed routing rule: {}", identifier));
    }
    Ok(())
}

fn enable_route(identifier: String, json_output: bool) -> Result<()> {
    set_route_enabled(identifier, true, json_output)
}

fn disable_route(identifier: String, json_output: bool) -> Result<()> {
    set_route_enabled(identifier, false, json_output)
}

fn set_route_enabled(identifier: String, enabled: bool, json_output: bool) -> Result<()> {
    let config_path = get_config_path()?;
    let mut config = load_or_init_config(&config_path)?;

    let rule = config
        .rules
        .iter_mut()
        .find(|r| r.id.to_string() == identifier || r.name == identifier)
        .ok_or_else(|| anyhow::anyhow!("Routing rule not found: '{}'", identifier))?;

    rule.enabled = enabled;
    let rule_name = rule.name.clone();
    let rule_id = rule.id;

    save_config(&config_path, &config)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "id": rule_id, "name": rule_name, "enabled": enabled })
        );
    } else {
        let action = if enabled { "Enabled" } else { "Disabled" };
        p::success(&format!("{} routing rule '{}'", action, rule_name));
    }

    Ok(())
}

fn test_route(identifier: String, json_output: bool) -> Result<()> {
    let config_path = get_config_path()?;
    let config = load_or_init_config(&config_path)?;

    let rule = config
        .rules
        .iter()
        .find(|r| r.id.to_string() == identifier || r.name == identifier)
        .ok_or_else(|| anyhow::anyhow!("Routing rule not found: '{}'", identifier))?;

    let test_event = Event::new(EventType::CommandOutcome, "Synthetic Test Event")
        .with_severity(Severity::Info)
        .with_description("Synthetic test event for routing rule verification");

    let matches = rule.filter.matches(&test_event);

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "filter_matched": matches,
                "enabled": rule.enabled,
                "adapter": rule.adapter,
            })
        );
    } else {
        p::header(&format!("Testing Rule: {}", rule.name));
        p::separator();
        println!(
            "  Filter Match: {}",
            if matches { "YES".green() } else { "NO".red() }
        );
        println!(
            "  Enabled:      {}",
            if rule.enabled { "Yes" } else { "No" }
        );
        println!("  Adapter:      {:?}", rule.adapter);
        p::separator();
    }

    Ok(())
}

fn handle_test(args: TestArgs) -> Result<()> {
    let config_path = get_config_path()?;
    let config = load_or_init_config(&config_path)?;

    let event_type: EventType = args.event_type.parse()?;
    let severity: Severity = args.severity.parse()?;

    let mut event = Event::new(event_type, args.title)
        .with_severity(severity)
        .with_source(args.source);

    if let Some(desc) = args.description {
        event = event.with_description(desc);
    }

    if let Some(ref rule_id_str) = args.rule_id {
        let rule = config
            .rules
            .iter()
            .find(|r| r.id.to_string() == *rule_id_str || r.name == *rule_id_str)
            .ok_or_else(|| anyhow::anyhow!("Rule not found: '{}'", rule_id_str))?;

        let matches = rule.filter.matches(&event);

        if args.json {
            println!(
                "{}",
                serde_json::json!({
                    "rule": rule.name,
                    "rule_id": rule.id,
                    "matched": matches,
                    "event": event,
                })
            );
        } else {
            p::header(&format!("Testing Event against Rule '{}'", rule.name));
            println!(
                "  Match: {}",
                if matches {
                    "MATCHED".green()
                } else {
                    "NO MATCH".yellow()
                }
            );
        }
    } else {
        let matched =
            crate::utils::notify_router::rules::find_matching_rules(&event, &config.rules)?;

        if args.json {
            println!(
                "{}",
                serde_json::json!({
                    "matched_count": matched.len(),
                    "matched_rules": matched.iter().map(|r| serde_json::json!({"id": r.id, "name": r.name})).collect::<Vec<_>>(),
                    "event": event,
                })
            );
        } else {
            p::header("Event Routing Test");
            p::separator();
            println!("  Title:        {}", event.title);
            println!("  Type:         {}", event.event_type);
            println!("  Severity:     {}", event.severity);
            println!("  Source:       {}", event.source);
            println!("  Matched:      {} rule(s)", matched.len());
            for r in &matched {
                println!("    • {} ({:?})", r.name.bold(), r.adapter);
            }
            p::separator();
        }
    }

    Ok(())
}

fn handle_events(cmd: EventsCommands) -> Result<()> {
    match cmd {
        EventsCommands::List { limit, json } => list_events(limit, json),
        EventsCommands::Show { event_id, json } => show_event(event_id, json),
        EventsCommands::Emit {
            event_type,
            title,
            severity,
            description,
            source,
            correlation_id,
            idempotency_key,
            data,
            process,
            json,
        } => emit_event(
            event_type,
            title,
            severity,
            description,
            source,
            correlation_id,
            idempotency_key,
            data,
            process,
            json,
        ),
    }
}

fn list_events(limit: usize, json_output: bool) -> Result<()> {
    let events_file = default_data_dir().join("events.jsonl");

    if !events_file.exists() {
        if json_output {
            println!("[]");
        } else {
            p::warn("No events recorded yet.");
        }
        return Ok(());
    }

    let content = fs::read_to_string(&events_file)?;
    let mut events: Vec<Event> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    events.reverse(); // Newest first
    events.truncate(limit);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }

    p::header("Recent Operational Events");
    p::separator();

    for ev in &events {
        let sev_str = match ev.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::Error => "ERROR".red(),
            Severity::Warning => "WARN".yellow(),
            Severity::Info => "INFO".blue(),
        };

        println!(
            "  [{}] [{}] {} - {}",
            ev.timestamp.format("%Y-%m-%d %H:%M:%S"),
            sev_str,
            ev.event_type.to_string().bold(),
            ev.title
        );
        println!("     ID:     {}", ev.id);
        println!("     Source: {}", ev.source);
    }

    p::separator();
    Ok(())
}

fn show_event(event_id: String, json_output: bool) -> Result<()> {
    let events_file = default_data_dir().join("events.jsonl");
    if !events_file.exists() {
        bail!("No events recorded yet.");
    }

    let target_id = Uuid::parse_str(&event_id).context("Invalid event ID format")?;
    let content = fs::read_to_string(&events_file)?;

    for line in content.lines() {
        if let Ok(ev) = serde_json::from_str::<Event>(line) {
            if ev.id == target_id {
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&ev)?);
                } else {
                    p::header(&format!("Event: {}", ev.title));
                    p::separator();
                    println!("  ID:          {}", ev.id);
                    println!("  Version:     {}", ev.version);
                    println!("  Type:        {}", ev.event_type);
                    println!("  Severity:    {}", ev.severity);
                    println!("  Timestamp:   {}", ev.timestamp);
                    println!("  Source:      {}", ev.source);
                    println!("  Description: {}", ev.description);
                    if let Some(ref c) = ev.correlation_id {
                        println!("  Correlation: {}", c);
                    }
                    if let Some(ref idem) = ev.idempotency_key {
                        println!("  Idempotency: {}", idem);
                    }
                    println!("  Data:        {}", serde_json::to_string_pretty(&ev.data)?);
                    p::separator();
                }
                return Ok(());
            }
        }
    }

    bail!("Event not found: {}", event_id)
}

fn emit_event(
    event_type_str: String,
    title: String,
    severity_str: String,
    description: Option<String>,
    source: String,
    correlation_id: Option<String>,
    idempotency_key: Option<String>,
    data_str: Option<String>,
    process: bool,
    json_output: bool,
) -> Result<()> {
    let config_path = get_config_path()?;
    let config = load_or_init_config(&config_path)?;
    let router = NotificationRouter::new(config)?;

    let event_type: EventType = event_type_str.parse()?;
    let severity: Severity = severity_str.parse()?;

    let mut event = Event::new(event_type, title)
        .with_severity(severity)
        .with_source(source);

    if let Some(d) = description {
        event = event.with_description(d);
    }
    if let Some(c) = correlation_id {
        event = event.with_correlation_id(c);
    }
    if let Some(i) = idempotency_key {
        event = event.with_idempotency_key(i);
    }
    if let Some(raw_data) = data_str {
        let val: HashMap<String, serde_json::Value> =
            serde_json::from_str(&raw_data).context("Invalid JSON in --data")?;
        event = event.with_data(EventData::Generic(val));
    }

    let enqueued_tasks = router.route_event(event.clone())?;

    let delivery_results = if process && !enqueued_tasks.is_empty() {
        router.process_deliveries()?
    } else {
        vec![]
    };

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "event_id": event.id,
                "enqueued_tasks": enqueued_tasks,
                "deliveries": delivery_results.iter().map(|d| serde_json::json!({
                    "task_id": d.task_id,
                    "success": d.success,
                    "duration_ms": d.duration_ms,
                    "error": d.error
                })).collect::<Vec<_>>()
            })
        );
    } else {
        p::success(&format!(
            "Event emitted: {} (ID: {})",
            event.title, event.id
        ));
        println!("  Enqueued Tasks: {}", enqueued_tasks.len());
        for res in &delivery_results {
            if res.success {
                println!(
                    "    ✓ Task {} delivered ({}ms)",
                    res.task_id, res.duration_ms
                );
            } else {
                println!(
                    "    ✗ Task {} failed ({}ms): {}",
                    res.task_id,
                    res.duration_ms,
                    res.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
    }

    Ok(())
}

fn handle_retry(cmd: RetryCommands) -> Result<()> {
    let outbox = Outbox::new(default_data_dir())?;

    match cmd {
        RetryCommands::All { process, json } => {
            let count = outbox.retry_all_dead_letter()?;
            let delivery_results = if process && count > 0 {
                let config_path = get_config_path()?;
                let config = load_or_init_config(&config_path)?;
                let router = NotificationRouter::new(config)?;
                router.process_deliveries()?
            } else {
                vec![]
            };

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "retried_count": count,
                        "processed": delivery_results.len()
                    })
                );
            } else {
                p::success(&format!("Retried {} dead-letter task(s)", count));
            }
        }
        RetryCommands::Task {
            task_id,
            process,
            json,
        } => {
            let id = Uuid::parse_str(&task_id).context("Invalid task ID format")?;
            outbox.retry_dead_letter(&id)?;

            if process {
                let config_path = get_config_path()?;
                let config = load_or_init_config(&config_path)?;
                let router = NotificationRouter::new(config)?;
                let _ = router.process_deliveries()?;
            }

            if json {
                println!("{}", serde_json::json!({ "retried_task": task_id }));
            } else {
                p::success(&format!("Retried task: {}", task_id));
            }
        }
    }

    Ok(())
}

fn handle_dead_letter(cmd: DeadLetterCommands) -> Result<()> {
    let outbox = Outbox::new(default_data_dir())?;

    match cmd {
        DeadLetterCommands::List { json } => {
            let tasks = outbox.get_dead_letter_tasks()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tasks)?);
                return Ok(());
            }

            p::header("Dead-Letter Queue");
            p::separator();

            if tasks.is_empty() {
                p::success("No dead-letter tasks. All deliveries successful or pending.");
                return Ok(());
            }

            for t in &tasks {
                println!("  Task ID:   {}", t.id.to_string().bold());
                println!("  Event ID:  {}", t.event_id);
                println!("  Adapter:   {:?}", t.adapter);
                println!("  Attempts:  {}/{}", t.attempts, t.max_attempts);
                println!(
                    "  Error:     {}",
                    t.error_message.as_deref().unwrap_or("Unknown error").red()
                );
                println!("  Created:   {}", t.created_at);
                println!();
            }

            p::separator();
        }
        DeadLetterCommands::Show { task_id, json } => {
            let id = Uuid::parse_str(&task_id).context("Invalid task ID format")?;
            let task = outbox.get_task(&id)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&task)?);
            } else {
                p::header(&format!("Dead-Letter Task: {}", task.id));
                p::separator();
                println!("  Event ID:     {}", task.event_id);
                println!("  Rule ID:      {}", task.rule_id);
                println!("  Adapter:      {:?}", task.adapter);
                println!("  Status:       {:?}", task.status);
                println!("  Attempts:     {}/{}", task.attempts, task.max_attempts);
                println!("  Created At:   {}", task.created_at);
                println!("  Last Attempt: {:?}", task.last_attempt_at);
                println!(
                    "  Error:        {}",
                    task.error_message.as_deref().unwrap_or("None")
                );
                println!(
                    "  Payload:      {}",
                    serde_json::to_string_pretty(&task.payload)?
                );
                p::separator();
            }
        }
        DeadLetterCommands::Retry {
            task_id,
            process,
            json,
        } => {
            let id = Uuid::parse_str(&task_id).context("Invalid task ID format")?;
            outbox.retry_dead_letter(&id)?;

            if process {
                let config_path = get_config_path()?;
                let config = load_or_init_config(&config_path)?;
                let router = NotificationRouter::new(config)?;
                let _ = router.process_deliveries()?;
            }

            if json {
                println!("{}", serde_json::json!({ "retried_task": task_id }));
            } else {
                p::success(&format!("Re-enqueued dead-letter task: {}", task_id));
            }
        }
        DeadLetterCommands::Purge { json } => {
            let count = outbox.purge_dead_letter()?;
            if json {
                println!("{}", serde_json::json!({ "purged_count": count }));
            } else {
                p::success(&format!("Purged {} dead-letter task(s)", count));
            }
        }
        DeadLetterCommands::Prune { days, json } => {
            let pruned = outbox.prune_completed(days)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "pruned_completed": pruned, "older_than_days": days })
                );
            } else {
                p::success(&format!(
                    "Pruned {} completed task(s) older than {} days",
                    pruned, days
                ));
            }
        }
    }

    Ok(())
}

fn handle_stats(args: StatsArgs) -> Result<()> {
    let config_path = get_config_path()?;
    let config = load_or_init_config(&config_path)?;
    let router = NotificationRouter::new(config)?;
    let stats = router.stats()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        p::header("Notification Router Statistics");
        p::separator();
        println!("  Active Rules:      {}", stats.active_rules_count);
        println!("  Pending Tasks:     {}", stats.pending_tasks);
        println!("  Completed Tasks:   {}", stats.completed_tasks);
        println!("  Dead-Letter Tasks: {}", stats.dead_letter_count);
        println!("  Quarantine Tasks:  {}", stats.quarantine_count);
        println!("  Dedup Cache Keys:  {}", stats.dedup_window_size);
        p::separator();
    }

    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    Ok(default_data_dir().join("router_config.json"))
}

fn parse_adapter_type(s: &str) -> Result<AdapterType> {
    match s.to_lowercase().as_str() {
        "stdout" => Ok(AdapterType::Stdout),
        "file" => Ok(AdapterType::File),
        "webhook" => Ok(AdapterType::Webhook),
        "subprocess" => Ok(AdapterType::Subprocess),
        "email" => Ok(AdapterType::Email),
        "chat" => Ok(AdapterType::Chat),
        _ => bail!(
            "Unknown adapter type '{}'. Valid types: stdout, file, webhook, subprocess, email, chat.",
            s
        ),
    }
}

fn parse_key_value(s: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        bail!("Invalid key=value pair '{}'", s);
    }
    Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
}
