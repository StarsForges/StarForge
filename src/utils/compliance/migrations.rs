//! Versioned migrations for the compliance profile file
//! (`~/.starforge/compliance/profile.toml`).
//!
//! Mirrors [`crate::utils::config::migrations`]: the on-disk file is parsed
//! as a schema-agnostic [`serde_json::Value`] first, its `version` field is
//! read, and a sequence of pure `migrate_vN_to_vN1` functions reshapes the
//! value before final deserialization into [`super::ComplianceProfile`].
//!
//! ## Adding a new schema version
//!
//! 1. Bump [`super::CURRENT_PROFILE_VERSION`] and
//!    [`super::CURRENT_PROFILE_VERSION_NUM`].
//! 2. Write a `migrate_vN_to_vN1(&mut serde_json::Value)` pure function here.
//! 3. Register it in [`MIGRATIONS`].
//! 4. Add a test fixture and an integration test exercising the migration,
//!    following the pattern in `tests/config_migration_integration.rs`.

use anyhow::{anyhow, Result};
use serde_json::Value;

/// A single forward migration step from schema `from` to schema `to`.
pub struct Migration {
    pub from: u32,
    pub to: u32,
    pub apply: fn(&mut Value),
}

/// No migrations are registered yet — schema version 1 is the first shipped
/// version of the compliance profile. The engine is wired up from day one so
/// the first real rename/reshape doesn't require retrofitting a migration
/// path onto profiles teams have already saved.
pub const MIGRATIONS: &[Migration] = &[];

/// Reads the schema version from a profile value. Missing, empty, `"0"`, or
/// unparseable versions are treated as version `1`, so a hand-edited or
/// pre-versioning file still loads instead of erroring.
pub fn read_version(value: &Value) -> u32 {
    let raw = match value.get("version") {
        Some(Value::String(s)) => s.trim().parse::<u32>().ok(),
        Some(Value::Number(n)) => n.as_u64().map(|n| n as u32),
        _ => None,
    };
    raw.filter(|v| *v >= 1).unwrap_or(1)
}

fn set_version(value: &mut Value, version: u32) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("version".to_string(), Value::String(version.to_string()));
    }
}

/// Applies every migration required to bring `value` up to `target`.
/// Returns the ordered list of `(from, to)` steps actually applied.
///
/// Errors if there is no registered migration path from the current
/// version — for example, a profile written by a newer StarForge release
/// than the one running.
pub fn migrate_value(value: &mut Value, target: u32) -> Result<Vec<(u32, u32)>> {
    let mut applied = Vec::new();

    loop {
        let current = read_version(value);
        if current >= target {
            break;
        }

        let migration = MIGRATIONS
            .iter()
            .find(|m| m.from == current)
            .ok_or_else(|| {
                anyhow!(
                    "No migration path from compliance profile version {} (target version {}). \
                 This profile may have been written by a newer StarForge release.",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_version_defaults_missing_to_one() {
        assert_eq!(read_version(&json!({})), 1);
        assert_eq!(read_version(&json!({"version": ""})), 1);
        assert_eq!(read_version(&json!({"version": "0"})), 1);
    }

    #[test]
    fn read_version_reads_numeric_and_string_forms() {
        assert_eq!(read_version(&json!({"version": "1"})), 1);
        assert_eq!(read_version(&json!({"version": 3})), 3);
        assert_eq!(read_version(&json!({"version": "3"})), 3);
    }

    #[test]
    fn migrate_value_is_noop_at_current_version() {
        let mut value = json!({"version": "1"});
        let applied = migrate_value(&mut value, 1).unwrap();
        assert!(applied.is_empty());
        assert_eq!(read_version(&value), 1);
    }

    #[test]
    fn migrate_value_does_not_downgrade_newer_versions() {
        let mut value = json!({"version": "99"});
        assert!(migrate_value(&mut value, 1).unwrap().is_empty());
        assert_eq!(read_version(&value), 99);
    }

    #[test]
    fn migrate_value_errors_when_no_path_exists_to_reach_target() {
        // The registry is intentionally empty right now, so asking to reach
        // a version above the current one must fail clearly rather than
        // silently returning an unmigrated value.
        let mut value = json!({"version": "1"});
        let err = migrate_value(&mut value, 2).unwrap_err();
        assert!(err.to_string().contains("No migration path"));
    }
}
