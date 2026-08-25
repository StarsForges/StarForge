//! Versioned migrations for on-disk anomaly baselines.
//!
//! Mirrors the schema-agnostic `serde_json::Value` migration pattern used by
//! `src/utils/config/migrations.rs`: a baseline file is first parsed as a
//! generic JSON value, its `schema_version` is inspected, and a sequence of
//! pure migration functions reshape it before final deserialization into
//! [`super::model::Baseline`]. This guarantees a baseline written by an older
//! StarForge release loads cleanly rather than silently losing fields, and a
//! baseline written by a *newer* release fails loudly instead of being
//! misread.
//!
//! ## Adding a new schema version
//!
//! 1. Bump [`CURRENT_BASELINE_VERSION`].
//! 2. Write a `migrate_vN_to_vN1(&mut serde_json::Value)` pure function.
//! 3. Register it in [`MIGRATIONS`].
//! 4. Add a fixture + test exercising the migration (see the tests below).

use anyhow::{anyhow, Result};
use serde_json::Value;

/// The current on-disk baseline schema version. Bump this whenever
/// [`super::model::Baseline`]'s shape changes in a way `#[serde(default)]`
/// alone cannot safely absorb.
pub const CURRENT_BASELINE_VERSION: u8 = 1;

pub struct Migration {
    pub from: u8,
    pub to: u8,
    pub apply: fn(&mut Value),
}

/// Ordered registry of every baseline migration StarForge knows about.
/// Empty today because schema version 1 is the first released shape; future
/// migrations are appended here as the schema evolves.
pub const MIGRATIONS: &[Migration] = &[];

/// Reads `schema_version` from a raw baseline JSON value. Missing or
/// unparseable versions are treated as version `1`, matching the config
/// migrator's "assume the oldest known shape" policy for legacy files.
pub fn read_version(value: &Value) -> u8 {
    value
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .filter(|v| *v >= 1)
        .unwrap_or(1)
}

fn set_version(value: &mut Value, version: u8) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("schema_version".to_string(), Value::from(version));
    }
}

/// Applies every migration required to bring `value` up to `target`,
/// returning the `(from, to)` steps actually applied. Errors when `value`'s
/// version is newer than any migration path StarForge knows about (i.e. the
/// baseline was written by a newer release than the one running).
pub fn migrate_value(value: &mut Value, target: u8) -> Result<Vec<(u8, u8)>> {
    let mut applied = Vec::new();
    loop {
        let current = read_version(value);
        if current >= target {
            if current > target {
                anyhow::bail!(
                    "Anomaly baseline schema version {} is newer than the {} this StarForge \
                     build supports. Upgrade StarForge or delete the baseline with \
                     `starforge anomaly baseline reset` to start fresh.",
                    current,
                    target
                );
            }
            break;
        }

        let migration = MIGRATIONS
            .iter()
            .find(|m| m.from == current)
            .ok_or_else(|| {
                anyhow!(
                    "No migration path from anomaly baseline schema version {} (target {}).",
                    current,
                    target
                )
            })?;

        (migration.apply)(value);
        set_version(value, migration.to);
        applied.push((migration.from, migration.to));
    }
    Ok(applied)
}

/// Parses raw JSON bytes into a [`super::model::Baseline`], migrating
/// forward first if the on-disk schema version is older than current.
pub fn load_baseline_json(raw: &str) -> Result<super::model::Baseline> {
    let mut value: Value = serde_json::from_str(raw)
        .map_err(|e| anyhow!("Failed to parse anomaly baseline as JSON: {}", e))?;
    migrate_value(&mut value, CURRENT_BASELINE_VERSION)?;
    serde_json::from_value(value)
        .map_err(|e| anyhow!("Anomaly baseline did not match the expected schema: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_version_defaults_to_one() {
        let value = serde_json::json!({"contract_id": "C..."});
        assert_eq!(read_version(&value), 1);
    }

    #[test]
    fn current_version_requires_no_migration() {
        let mut value = serde_json::json!({"schema_version": 1});
        let applied = migrate_value(&mut value, CURRENT_BASELINE_VERSION).unwrap();
        assert!(applied.is_empty());
    }

    #[test]
    fn newer_than_supported_version_errors_clearly() {
        let mut value = serde_json::json!({"schema_version": 99});
        let err = migrate_value(&mut value, CURRENT_BASELINE_VERSION).unwrap_err();
        assert!(err.to_string().contains("newer than"));
    }

    #[test]
    fn load_baseline_json_round_trips_a_full_baseline() {
        let baseline = super::super::model::Baseline::new("CCONTRACT", "testnet");
        let raw = serde_json::to_string(&baseline).unwrap();
        let loaded = load_baseline_json(&raw).unwrap();
        assert_eq!(loaded.contract_id, "CCONTRACT");
        assert_eq!(loaded.schema_version, CURRENT_BASELINE_VERSION);
    }

    #[test]
    fn load_baseline_json_rejects_malformed_json() {
        assert!(load_baseline_json("not json").is_err());
    }
}
