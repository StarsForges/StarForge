//! Telemetry for AI feature usage: provider/model calls, token usage, cost
//! estimation, latency, and error rates. Stored locally as JSON lines,
//! independent of (and separately opt-out-able from) general CLI telemetry
//! in [`crate::utils::telemetry`].

use crate::utils::config;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};
use uuid::Uuid;

pub const AI_TELEMETRY_SCHEMA_VERSION: u8 = 1;
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MB

/// One structured AI usage event stored as a JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTelemetryEvent {
    pub schema_version: u8,
    pub timestamp: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub feature: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub duration_ms: u64,
    pub success: bool,
    pub error_type: Option<String>,
    pub estimated_cost_usd: f64,
    pub anonymous_id: String,
}

/// Inputs describing the outcome of a single AI provider call, used to build
/// and record an [`AiTelemetryEvent`].
pub struct AiCallOutcome<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub feature: &'a str,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub duration_ms: u64,
    pub success: bool,
    pub error_type: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Record a single AI call. Silently returns `Ok(())` if AI telemetry is
/// disabled or `STARFORGE_AI_TELEMETRY=0` is set.
pub fn track_ai_event(outcome: AiCallOutcome) -> Result<()> {
    if is_disabled() {
        return Ok(());
    }

    let anonymous_id = get_or_create_anonymous_id()?;
    let estimated_cost_usd =
        estimate_cost(outcome.model, outcome.input_tokens, outcome.output_tokens);

    let event = AiTelemetryEvent {
        schema_version: AI_TELEMETRY_SCHEMA_VERSION,
        timestamp: Utc::now(),
        provider: outcome.provider.to_string(),
        model: outcome.model.to_string(),
        feature: outcome.feature.to_string(),
        input_tokens: outcome.input_tokens,
        output_tokens: outcome.output_tokens,
        duration_ms: outcome.duration_ms,
        success: outcome.success,
        error_type: outcome.error_type,
        estimated_cost_usd,
        anonymous_id,
    };

    append_event(&event)?;
    Ok(())
}

/// Read the last `n` events from the log (most-recent last).
pub fn read_events(n: usize) -> Result<Vec<AiTelemetryEvent>> {
    let path = ai_telemetry_log_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }

    let file = fs::File::open(&path)?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let events: Vec<AiTelemetryEvent> = lines
        .iter()
        .rev()
        .take(n)
        .rev()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    Ok(events)
}

/// Read every stored event (for cost/usage reporting).
pub fn read_all_events() -> Result<Vec<AiTelemetryEvent>> {
    read_events(usize::MAX)
}

/// Wipe the AI telemetry log entirely.
pub fn clear_log() -> Result<()> {
    let path = ai_telemetry_log_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Total number of events currently stored.
pub fn event_count() -> Result<usize> {
    let path = ai_telemetry_log_path()?;
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(&path)?;
    Ok(std::io::BufReader::new(file).lines().count())
}

/// File size of the log in bytes (0 if the file doesn't exist).
pub fn log_size_bytes() -> Result<u64> {
    let path = ai_telemetry_log_path()?;
    if !path.exists() {
        return Ok(0);
    }
    Ok(fs::metadata(&path)?.len())
}

/// Set AI telemetry enabled/disabled in the config file.
pub fn set_ai_telemetry_enabled(enabled: bool) -> Result<()> {
    let mut cfg = config::load()?;
    cfg.ai_telemetry_enabled = Some(enabled);
    config::save(&cfg)?;
    Ok(())
}

/// Whether AI telemetry is currently enabled (config + env override).
pub fn is_enabled() -> bool {
    !is_disabled()
}

// ── Cost estimation ──────────────────────────────────────────────────────────

/// Rough USD cost per 1K input/output tokens for known model families.
/// Unknown models fall back to the gpt-4 rate as a conservative default.
fn pricing_per_1k(model: &str) -> (f64, f64) {
    let m = model.to_lowercase();
    if m.starts_with("gpt-4o-mini") {
        (0.00015, 0.0006)
    } else if m.starts_with("gpt-4o") {
        (0.0025, 0.01)
    } else if m.starts_with("gpt-4-turbo") {
        (0.01, 0.03)
    } else if m.starts_with("gpt-4") {
        (0.03, 0.06)
    } else if m.starts_with("gpt-3.5") {
        (0.0005, 0.0015)
    } else {
        (0.03, 0.06)
    }
}

/// Estimate the USD cost of a call given its token usage.
pub fn estimate_cost(model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
    let (in_rate, out_rate) = pricing_per_1k(model);
    (input_tokens as f64 / 1000.0) * in_rate + (output_tokens as f64 / 1000.0) * out_rate
}

// ── Reporting ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct AiTelemetrySummary {
    pub total_calls: usize,
    pub successful_calls: usize,
    pub failed_calls: usize,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub by_feature: BTreeMap<String, usize>,
    pub by_provider: BTreeMap<String, usize>,
    pub by_model: BTreeMap<String, usize>,
    pub error_types: BTreeMap<String, usize>,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_p99_ms: u64,
}

/// Summarize a set of events: totals, breakdowns, and latency percentiles.
pub fn summarize(events: &[AiTelemetryEvent]) -> AiTelemetrySummary {
    let mut summary = AiTelemetrySummary {
        total_calls: events.len(),
        ..Default::default()
    };

    let mut durations: Vec<u64> = Vec::with_capacity(events.len());

    for ev in events {
        if ev.success {
            summary.successful_calls += 1;
        } else {
            summary.failed_calls += 1;
            if let Some(err) = &ev.error_type {
                *summary.error_types.entry(err.clone()).or_insert(0) += 1;
            }
        }
        summary.total_input_tokens += ev.input_tokens as u64;
        summary.total_output_tokens += ev.output_tokens as u64;
        summary.total_cost_usd += ev.estimated_cost_usd;
        *summary.by_feature.entry(ev.feature.clone()).or_insert(0) += 1;
        *summary.by_provider.entry(ev.provider.clone()).or_insert(0) += 1;
        *summary.by_model.entry(ev.model.clone()).or_insert(0) += 1;
        durations.push(ev.duration_ms);
    }

    durations.sort_unstable();
    summary.latency_p50_ms = percentile(&durations, 0.50);
    summary.latency_p95_ms = percentile(&durations, 0.95);
    summary.latency_p99_ms = percentile(&durations, 0.99);

    summary
}

/// Nearest-rank percentile over an already-sorted slice.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn is_disabled() -> bool {
    if let Ok(val) = std::env::var("STARFORGE_AI_TELEMETRY") {
        if matches!(
            val.to_lowercase().as_str(),
            "0" | "false" | "off" | "disabled" | "no"
        ) {
            return true;
        }
    }
    config::load()
        .map(|c| !c.ai_telemetry_enabled.unwrap_or(true))
        .unwrap_or(false)
}

/// Shares the same anonymous id file as general telemetry so events can be
/// correlated without introducing a second identifier.
fn get_or_create_anonymous_id() -> Result<String> {
    let data_dir = config::get_data_dir()?;
    let id_file = data_dir.join("anonymous_id");
    if id_file.exists() {
        Ok(fs::read_to_string(id_file)?.trim().to_string())
    } else {
        let id = Uuid::new_v4().to_string();
        fs::write(id_file, &id)?;
        Ok(id)
    }
}

fn ai_telemetry_log_path() -> Result<std::path::PathBuf> {
    Ok(config::get_data_dir()?.join("ai_telemetry.log"))
}

/// Append one event and enforce the size/count cap.
fn append_event(event: &AiTelemetryEvent) -> Result<()> {
    let path = ai_telemetry_log_path()?;
    let line = serde_json::to_string(event)?;

    let needs_prune = path.exists()
        && (fs::metadata(&path)?.len() >= MAX_BYTES || line_count(&path)? >= MAX_ENTRIES);

    if needs_prune {
        prune_oldest(&path, MAX_ENTRIES / 2)?;
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

fn line_count(path: &std::path::Path) -> Result<usize> {
    let file = fs::File::open(path)?;
    Ok(std::io::BufReader::new(file).lines().count())
}

fn prune_oldest(path: &std::path::Path, keep: usize) -> Result<()> {
    let file = fs::File::open(path)?;
    let all_lines: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .collect();

    let start = all_lines.len().saturating_sub(keep);
    let retained = &all_lines[start..];

    let mut out = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    for line in retained {
        writeln!(out, "{}", line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(feature: &str, model: &str, duration_ms: u64, success: bool) -> AiTelemetryEvent {
        AiTelemetryEvent {
            schema_version: AI_TELEMETRY_SCHEMA_VERSION,
            timestamp: Utc::now(),
            provider: "openai".to_string(),
            model: model.to_string(),
            feature: feature.to_string(),
            input_tokens: 100,
            output_tokens: 50,
            duration_ms,
            success,
            error_type: if success {
                None
            } else {
                Some("network".to_string())
            },
            estimated_cost_usd: estimate_cost(model, 100, 50),
            anonymous_id: "test-id".to_string(),
        }
    }

    #[test]
    fn event_serialises_to_expected_fields() {
        let ev = make_event("generate", "gpt-4", 10, true);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(json["schema_version"], AI_TELEMETRY_SCHEMA_VERSION);
        assert_eq!(json["provider"], "openai");
        assert_eq!(json["feature"], "generate");
        assert!(json.get("estimated_cost_usd").is_some());
    }

    #[test]
    fn cost_estimation_scales_with_tokens_and_model() {
        let cheap = estimate_cost("gpt-3.5-turbo", 1000, 1000);
        let pricey = estimate_cost("gpt-4", 1000, 1000);
        assert!(cheap < pricey);
        assert!(estimate_cost("gpt-4", 0, 0) == 0.0);
    }

    #[test]
    fn unknown_model_falls_back_to_conservative_default() {
        let known = estimate_cost("gpt-4", 1000, 1000);
        let unknown = estimate_cost("some-future-model", 1000, 1000);
        assert_eq!(known, unknown);
    }

    #[test]
    fn summarize_computes_totals_and_breakdowns() {
        let events = vec![
            make_event("generate", "gpt-4", 100, true),
            make_event("analyze", "gpt-4", 200, true),
            make_event("optimize", "gpt-3.5-turbo", 50, false),
        ];
        let summary = summarize(&events);
        assert_eq!(summary.total_calls, 3);
        assert_eq!(summary.successful_calls, 2);
        assert_eq!(summary.failed_calls, 1);
        assert_eq!(summary.total_input_tokens, 300);
        assert_eq!(*summary.by_feature.get("generate").unwrap(), 1);
        assert_eq!(*summary.error_types.get("network").unwrap(), 1);
    }

    #[test]
    fn percentile_uses_nearest_rank_on_sorted_durations() {
        let mut durations: Vec<u64> = (1..=100).collect();
        durations.sort_unstable();
        assert_eq!(percentile(&durations, 0.50), 50);
        assert_eq!(percentile(&durations, 0.95), 95);
        assert_eq!(percentile(&durations, 0.99), 99);
        assert_eq!(percentile(&[], 0.5), 0);
    }
}
