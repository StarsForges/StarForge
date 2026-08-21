//! Simulation adapters: normalize Soroban RPC `simulateTransaction` responses
//! (and already-parsed [`crate::utils::soroban::SimulationResult`] values)
//! into the stable [`ResourceUsage`] structure the cost model consumes.
//!
//! Consuming raw RPC JSON directly (rather than only the fields
//! `crate::utils::soroban` already surfaces) lets the estimator use signals —
//! `cost.cpuInsns`, `cost.memBytes`, per-key size hints — that the existing
//! invoke/deploy flows don't need but cost estimation does.

use crate::commands::cost::model::ResourceUsage;
use crate::utils::soroban::SimulationResult;
use anyhow::{Context, Result};
use serde_json::Value;

/// Parses a full Soroban RPC JSON-RPC envelope (`{"jsonrpc", "id", "result"|"error"}`)
/// — the same shape used by `tests/fixtures/soroban_rpc/*.json` — and normalizes
/// its `result` payload into [`ResourceUsage`].
pub fn normalize_from_rpc_envelope(envelope: &Value) -> Result<ResourceUsage> {
    if let Some(error) = envelope.get("error") {
        anyhow::bail!("Soroban RPC response contains an error: {}", error);
    }
    let result = envelope
        .get("result")
        .context("Soroban RPC envelope has neither a 'result' nor an 'error' field")?;
    Ok(normalize_from_result_value(result))
}

/// Normalizes an already-unwrapped `result` value (i.e. the object a real RPC
/// client would receive after stripping the `jsonrpc`/`id`/`error` envelope).
pub fn normalize_from_result_value(result: &Value) -> ResourceUsage {
    let cpu_insns = result
        .pointer("/cost/cpuInsns")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mem_bytes = result
        .pointer("/cost/memBytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let footprint = result
        .pointer("/transactionData/resources/footprint")
        .or_else(|| result.pointer("/transactionData/footprint"))
        .or_else(|| result.pointer("/footprint"));

    let (read_entries, read_bytes) = footprint
        .and_then(|f| f.get("readOnly").or_else(|| f.get("readOnlyKeys")))
        .map(count_and_size)
        .unwrap_or((0, 0));

    let (write_entries, write_bytes) = footprint
        .and_then(|f| f.get("readWrite").or_else(|| f.get("readWriteKeys")))
        .map(count_and_size)
        .unwrap_or((0, 0));

    let events = result.get("events").and_then(Value::as_array);
    let event_count = events.map(|e| e.len() as u32).unwrap_or(0);
    let event_bytes = events
        .map(|e| {
            e.iter()
                .map(|ev| ev.as_str().map(str::len).unwrap_or(0) as u64)
                .sum()
        })
        .unwrap_or(0);

    ResourceUsage {
        cpu_insns,
        mem_bytes,
        read_entries,
        write_entries,
        read_bytes,
        write_bytes,
        event_count,
        event_bytes,
    }
}

fn count_and_size(keys: &Value) -> (u32, u64) {
    let arr = match keys.as_array() {
        Some(a) => a,
        None => return (0, 0),
    };
    let count = arr.len() as u32;
    let bytes = arr
        .iter()
        .map(|k| {
            k.get("sizeHintBytes")
                .or_else(|| k.get("size_hint_bytes"))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    (count, bytes)
}

/// Normalizes an already-constructed [`SimulationResult`] (as produced by
/// `crate::utils::soroban::simulate_transaction`/`simulate_deploy_transaction`)
/// into [`ResourceUsage`]. CPU/memory counters are not preserved on
/// `SimulationResult` itself, so this reads storage footprint and event
/// counts only; callers with access to the raw RPC JSON should prefer
/// [`normalize_from_rpc_envelope`] for the fuller picture.
pub fn normalize_from_simulation(sim: &SimulationResult) -> ResourceUsage {
    let (read_entries, read_bytes, write_entries, write_bytes) = match &sim.footprint {
        Some(fp) => {
            let read_bytes: u64 = fp.read_only.iter().map(|k| k.size_hint_bytes as u64).sum();
            let write_bytes: u64 = fp.read_write.iter().map(|k| k.size_hint_bytes as u64).sum();
            (
                fp.read_only.len() as u32,
                read_bytes,
                fp.read_write.len() as u32,
                write_bytes,
            )
        }
        None => (0, 0, 0, 0),
    };

    let event_count = sim.events.len() as u32;
    let event_bytes: u64 = sim.events.iter().map(|e| e.len() as u64).sum();

    ResourceUsage {
        cpu_insns: 0,
        mem_bytes: 0,
        read_entries,
        write_entries,
        read_bytes,
        write_bytes,
        event_count,
        event_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_full_envelope_with_cost_and_footprint() {
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "cost": { "cpuInsns": 150000, "memBytes": 2048 },
                "transactionData": {
                    "resources": {
                        "footprint": {
                            "readOnly": [{ "sizeHintBytes": 64 }],
                            "readWrite": [{ "sizeHintBytes": 128 }, { "sizeHintBytes": 32 }],
                        }
                    }
                },
                "events": ["AAAA", "BBBBBB"],
            }
        });

        let usage = normalize_from_rpc_envelope(&envelope).unwrap();
        assert_eq!(usage.cpu_insns, 150_000);
        assert_eq!(usage.mem_bytes, 2048);
        assert_eq!(usage.read_entries, 1);
        assert_eq!(usage.read_bytes, 64);
        assert_eq!(usage.write_entries, 2);
        assert_eq!(usage.write_bytes, 160);
        assert_eq!(usage.event_count, 2);
        assert_eq!(usage.event_bytes, 4 + 6);
    }

    #[test]
    fn error_envelope_is_rejected() {
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32600, "message": "boom" }
        });
        let err = normalize_from_rpc_envelope(&envelope).unwrap_err();
        assert!(err.to_string().contains("error"));
    }

    #[test]
    fn missing_result_and_error_is_rejected() {
        let envelope = json!({ "jsonrpc": "2.0", "id": 1 });
        assert!(normalize_from_rpc_envelope(&envelope).is_err());
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let envelope = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        let usage = normalize_from_rpc_envelope(&envelope).unwrap();
        assert_eq!(usage, ResourceUsage::default());
    }

    #[test]
    fn normalize_from_simulation_sums_footprint_and_events() {
        use crate::utils::soroban::{
            FootprintAccess, StorageFootprintKey, StorageFootprintSummary,
        };

        let sim = SimulationResult {
            return_value: "ok".to_string(),
            fee: 12345,
            events: vec!["abcd".to_string(), "ef".to_string()],
            errors: vec![],
            footprint: Some(StorageFootprintSummary {
                read_only: vec![StorageFootprintKey {
                    access: FootprintAccess::ReadOnly,
                    key: "k1".to_string(),
                    size_hint_bytes: 40,
                }],
                read_write: vec![StorageFootprintKey {
                    access: FootprintAccess::ReadWrite,
                    key: "k2".to_string(),
                    size_hint_bytes: 80,
                }],
            }),
        };

        let usage = normalize_from_simulation(&sim);
        assert_eq!(usage.read_entries, 1);
        assert_eq!(usage.read_bytes, 40);
        assert_eq!(usage.write_entries, 1);
        assert_eq!(usage.write_bytes, 80);
        assert_eq!(usage.event_count, 2);
        assert_eq!(usage.event_bytes, 6);
        assert_eq!(usage.cpu_insns, 0);
    }

    #[test]
    fn normalize_from_simulation_handles_missing_footprint() {
        let sim = SimulationResult {
            return_value: "ok".to_string(),
            fee: 100,
            events: vec![],
            errors: vec![],
            footprint: None,
        };
        let usage = normalize_from_simulation(&sim);
        assert_eq!(usage, ResourceUsage::default());
    }
}
