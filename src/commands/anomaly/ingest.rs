//! Streaming ingestion: turns raw Soroban events, Horizon transaction
//! records, and an RPC health probe into one [`WindowMetrics`] per
//! observation window.
//!
//! The pure aggregation functions here ([`events_to_window`],
//! [`merge_transaction_outcomes`], [`scan_payload`]) take already-fetched
//! data and are exercised by deterministic unit tests. [`collect_live_window`]
//! is the thin network-calling orchestration used by `starforge anomaly
//! monitor` in live mode; per the issue's requirement that CI not depend on
//! external service availability, it is intentionally not unit tested here —
//! `starforge anomaly monitor --events-file`/`--transactions-file` (see
//! `src/commands/anomaly/mod.rs`) exercises the exact same aggregation logic
//! end-to-end against fixtures instead.

use super::model::WindowMetrics;
use crate::utils::horizon::TransactionRecord;
use crate::utils::soroban;
use crate::utils::stream::{EventStreamFilters, SorobanEvent, SorobanEventStream};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::Duration;

/// Aggregates a batch of Soroban events (as returned by
/// [`SorobanEventStream::next_batch`] or replayed from a fixture) into a
/// [`WindowMetrics`]. Every contract-type event is treated as a successful
/// call; system/diagnostic events whose topic or value mentions an error are
/// treated as a failure — Soroban's `getEvents` does not expose transaction
/// status directly, so this is the same heuristic already used by
/// `starforge monitor`'s legacy event filter.
pub fn events_to_window(
    events: &[SorobanEvent],
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> WindowMetrics {
    let mut window = WindowMetrics {
        window_start,
        window_end,
        ..Default::default()
    };

    let mut fee_sum = 0.0;
    let mut cpu_sum = 0.0;
    let mut cpu_samples = 0u64;

    for event in events {
        window.event_count += 1;

        for topic in &event.topic {
            // Topics that look like account/contract IDs (StrKey `G`/`C`
            // prefix, 56 chars) are treated as callers.
            if topic.len() == 56 && (topic.starts_with('G') || topic.starts_with('C')) {
                window.unique_callers.insert(topic.clone());
            }
        }

        let value_text = event.value.to_string();
        let is_error = looks_like_error(event, &value_text);
        if is_error {
            window.error_count += 1;
        } else {
            window.success_count += 1;
        }

        let payload_bytes = value_text.len() as u64;
        window.max_payload_bytes = window.max_payload_bytes.max(payload_bytes);

        let hits = scan_payload(&value_text);
        if !hits.is_empty() {
            window.suspicious_payload_hits += 1;
            window.suspicious_patterns.extend(hits);
        }

        // Best-effort resource hints occasionally embedded in diagnostic
        // event payloads (e.g. `{"cpu_insns": 12345, "fee_stroops": 100}`).
        if let Some(cpu) = event.value.get("cpu_insns").and_then(|v| v.as_u64()) {
            cpu_sum += cpu as f64;
            cpu_samples += 1;
            window.max_cpu_insns = window.max_cpu_insns.max(cpu);
        }
        if let Some(fee) = event.value.get("fee_stroops").and_then(|v| v.as_u64()) {
            fee_sum += fee as f64;
            window.max_fee_stroops = window.max_fee_stroops.max(fee);
        }
    }

    if !events.is_empty() {
        window.avg_fee_stroops = fee_sum / events.len() as f64;
    }
    if cpu_samples > 0 {
        window.avg_cpu_insns = cpu_sum / cpu_samples as f64;
    }

    window
}

fn looks_like_error(event: &SorobanEvent, value_text: &str) -> bool {
    let haystack = value_text.to_lowercase();
    let topic_text = event.topic.join(",").to_lowercase();
    haystack.contains("error")
        || haystack.contains("panic")
        || haystack.contains("fail")
        || topic_text.contains("error")
}

/// Folds Horizon transaction records into an existing window: successful/
/// failed counts and fee statistics. Kept separate from [`events_to_window`]
/// because contract events and account-level transactions come from
/// different endpoints and may not both be available in every ingestion mode.
pub fn merge_transaction_outcomes(window: &mut WindowMetrics, transactions: &[TransactionRecord]) {
    if transactions.is_empty() {
        return;
    }
    let mut fee_sum = 0.0;
    let mut fee_max = window.max_fee_stroops;
    for tx in transactions {
        if tx.successful {
            window.success_count += 1;
        } else {
            window.error_count += 1;
        }
        if let Some(src) = &tx.source_account {
            window.unique_callers.insert(src.clone());
        }
        if let Ok(fee) = tx.fee_charged.parse::<u64>() {
            fee_sum += fee as f64;
            fee_max = fee_max.max(fee);
        }
    }

    // Combine the existing (event-derived) fee average with the
    // transaction-derived fees as a weighted mean, weighting each source by
    // how many samples it contributed.
    let previous_weight = window.event_count as f64;
    let tx_weight = transactions.len() as f64;
    let total_weight = previous_weight + tx_weight;
    if total_weight > 0.0 {
        window.avg_fee_stroops =
            ((window.avg_fee_stroops * previous_weight) + fee_sum) / total_weight;
    }
    window.max_fee_stroops = fee_max;
}

/// Deterministic, dependency-free suspicious-payload pattern scan. Returns
/// the names of every rule matched (deduplicated by [`WindowMetrics`] at the
/// call site), so a single payload can trip more than one rule.
pub fn scan_payload(payload: &str) -> Vec<String> {
    let mut hits = Vec::new();

    const OVERSIZED_PAYLOAD_BYTES: usize = 8192;
    if payload.len() > OVERSIZED_PAYLOAD_BYTES {
        hits.push("oversized_payload".to_string());
    }

    let control_chars = payload
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\t' && *c != '\r')
        .count();
    if !payload.is_empty() && control_chars as f64 / payload.len() as f64 > 0.1 {
        hits.push("high_control_char_ratio".to_string());
    }

    if has_long_repeated_run(payload, 32) {
        hits.push("repeated_byte_run".to_string());
    }

    let lowercase = payload.to_lowercase();
    const SUSPICIOUS_SUBSTRINGS: &[&str] = &[
        "self_destruct",
        "selfdestruct",
        "backdoor",
        "admin_override",
        "bypass_auth",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ];
    for needle in SUSPICIOUS_SUBSTRINGS {
        if lowercase.contains(needle) {
            hits.push(format!("suspicious_substring:{}", needle));
        }
    }

    hits
}

fn has_long_repeated_run(s: &str, min_run: usize) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < min_run {
        return false;
    }
    let mut run_len = 1usize;
    for window in bytes.windows(2) {
        if window[0] == window[1] {
            run_len += 1;
            if run_len >= min_run {
                return true;
            }
        } else {
            run_len = 1;
        }
    }
    false
}

/// Result of an RPC health probe.
pub struct HealthProbe {
    pub reachable: bool,
    pub latency_ms: Option<u64>,
}

/// Probes the Soroban RPC endpoint's `getHealth` method. Never returns an
/// error — an unreachable endpoint is itself the signal callers care about,
/// surfaced as `reachable: false` rather than a propagated network error.
pub fn probe_rpc_health(rpc_url: &str) -> HealthProbe {
    let start = std::time::Instant::now();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getHealth",
        "params": {}
    });
    match ureq::post(rpc_url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(5))
        .send_json(&request)
    {
        Ok(resp) if resp.status() == 200 => HealthProbe {
            reachable: true,
            latency_ms: Some(start.elapsed().as_millis() as u64),
        },
        _ => HealthProbe {
            reachable: false,
            latency_ms: None,
        },
    }
}

/// Live ingestion: fetches one batch of contract events over `poll_interval`
/// and probes RPC health, producing a single [`WindowMetrics`]. This is glue
/// over [`SorobanEventStream`] and [`probe_rpc_health`] — the aggregation
/// logic it delegates to is unit tested via [`events_to_window`] directly.
pub fn collect_live_window(
    rpc_url: &str,
    contract_id: &str,
    filters: EventStreamFilters,
) -> Result<WindowMetrics> {
    let window_start = Utc::now();
    let mut stream =
        SorobanEventStream::new(rpc_url.to_string(), contract_id.to_string()).with_filters(filters);
    let events = stream.next_batch()?;
    let window_end = Utc::now();

    let mut window = events_to_window(&events, window_start, window_end);
    let health = probe_rpc_health(rpc_url);
    window.rpc_reachable = Some(health.reachable);
    window.rpc_latency_ms = health.latency_ms;
    Ok(window)
}

/// Resolves the Soroban RPC URL for `network`, surfacing the same error
/// context `starforge monitor` already uses.
pub fn rpc_url_for(network: &str) -> Result<String> {
    soroban::rpc_url(network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(topic: Vec<&str>, value: serde_json::Value) -> SorobanEvent {
        serde_json::from_value(json!({
            "type": "contract",
            "ledger": 100,
            "id": "evt-1",
            "topic": topic,
            "value": value,
        }))
        .unwrap()
    }

    #[test]
    fn events_to_window_counts_events_and_callers() {
        let caller = "G".to_string() + &"A".repeat(55);
        let events = vec![event(vec![caller.as_str()], json!("ok"))];
        let now = Utc::now();
        let window = events_to_window(&events, now, now);
        assert_eq!(window.event_count, 1);
        assert!(window.unique_callers.contains(&caller));
        assert_eq!(window.success_count, 1);
        assert_eq!(window.error_count, 0);
    }

    #[test]
    fn events_to_window_classifies_error_events() {
        let events = vec![event(vec!["topic"], json!("transfer failed: error"))];
        let now = Utc::now();
        let window = events_to_window(&events, now, now);
        assert_eq!(window.error_count, 1);
        assert_eq!(window.success_count, 0);
    }

    #[test]
    fn events_to_window_extracts_resource_hints() {
        let events = vec![event(
            vec!["topic"],
            json!({"cpu_insns": 5_000_000, "fee_stroops": 100}),
        )];
        let now = Utc::now();
        let window = events_to_window(&events, now, now);
        assert_eq!(window.max_cpu_insns, 5_000_000);
        assert_eq!(window.avg_cpu_insns, 5_000_000.0);
        assert!((window.avg_fee_stroops - 100.0).abs() < 1e-9);
    }

    #[test]
    fn events_to_window_flags_suspicious_payload() {
        let events = vec![event(vec!["topic"], json!("contains a backdoor trigger"))];
        let now = Utc::now();
        let window = events_to_window(&events, now, now);
        assert_eq!(window.suspicious_payload_hits, 1);
        assert!(window
            .suspicious_patterns
            .iter()
            .any(|p| p.contains("backdoor")));
    }

    #[test]
    fn merge_transaction_outcomes_counts_success_and_failure() {
        let mut window = WindowMetrics::default();
        let txs = vec![
            TransactionRecord {
                hash: "a".into(),
                successful: true,
                operation_count: 1,
                fee_charged: "100".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
                memo_type: None,
                memo: None,
                source_account: Some("GABC".into()),
                transaction_type: None,
                paging_token: None,
            },
            TransactionRecord {
                hash: "b".into(),
                successful: false,
                operation_count: 1,
                fee_charged: "200".into(),
                created_at: "2024-01-01T00:00:01Z".into(),
                memo_type: None,
                memo: None,
                source_account: Some("GDEF".into()),
                transaction_type: None,
                paging_token: None,
            },
        ];
        merge_transaction_outcomes(&mut window, &txs);
        assert_eq!(window.success_count, 1);
        assert_eq!(window.error_count, 1);
        assert_eq!(window.max_fee_stroops, 200);
        assert!(window.unique_callers.contains("GABC"));
        assert!(window.unique_callers.contains("GDEF"));
    }

    #[test]
    fn merge_transaction_outcomes_is_a_noop_on_empty_input() {
        let mut window = WindowMetrics {
            event_count: 5,
            ..Default::default()
        };
        merge_transaction_outcomes(&mut window, &[]);
        assert_eq!(window.success_count, 0);
        assert_eq!(window.error_count, 0);
    }

    #[test]
    fn scan_payload_flags_oversized_payload() {
        let payload = "x".repeat(10_000);
        let hits = scan_payload(&payload);
        assert!(hits.contains(&"oversized_payload".to_string()));
    }

    #[test]
    fn scan_payload_flags_repeated_byte_runs() {
        let payload = "a".repeat(64);
        let hits = scan_payload(&payload);
        assert!(hits.contains(&"repeated_byte_run".to_string()));
    }

    #[test]
    fn scan_payload_is_clean_for_ordinary_text() {
        let hits = scan_payload("transfer completed to GABCDEF for 100 units");
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_payload_flags_known_substrings() {
        let hits = scan_payload("attempting bypass_auth on the vault");
        assert!(hits.iter().any(|h| h.contains("bypass_auth")));
    }
}
