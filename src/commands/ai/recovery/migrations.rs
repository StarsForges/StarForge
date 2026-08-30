//! Versioned schema migrations for on-disk recovery data.
//!
//! Mirrors the migration pattern used by the `anomaly` subsystem: each
//! persisted document ([`BackupPolicy`], [`RecoveryPlan`], [`RecoveryReport`])
//! is first parsed as a generic `serde_json::Value`, its `schema_version`
//! field is inspected, and a sequence of pure migration functions reshape it
//! before final deserialization into the typed struct.
//!
//! ## Adding a new schema version
//!
//! 1. Bump the relevant `CURRENT_*_VERSION` constant.
//! 2. Write a `migrate_vN_to_vN1(value: &mut serde_json::Value)` function.
//! 3. Register it in the appropriate migration table inside `migrate_policy`,
//!    `migrate_plan`, or `migrate_report`.
//! 4. Add a fixture and unit test exercising the new migration.

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::model::{BackupPolicy, RecoveryPlan, RecoveryReport};

// ── Current schema version constants ─────────────────────────────────────────

/// Current on-disk schema version for [`BackupPolicy`] documents.
pub const CURRENT_POLICY_VERSION: u8 = 1;

/// Current on-disk schema version for [`RecoveryPlan`] documents.
pub const CURRENT_PLAN_VERSION: u8 = 1;

/// Current on-disk schema version for [`RecoveryReport`] documents.
pub const CURRENT_REPORT_VERSION: u8 = 1;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Reads `schema_version` from a JSON value.
///
/// Returns `0` when the field is absent or unparseable, which triggers the
/// v0→v1 migration path and lets legacy files (written before versioning was
/// introduced) load cleanly.
fn read_version(value: &Value) -> u8 {
    value
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0)
}

/// Overwrites the `schema_version` field in `value`.
fn set_version(value: &mut Value, version: u8) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("schema_version".to_string(), Value::from(version));
    }
}

// ── v0 → v1 migration functions ───────────────────────────────────────────────

/// Migrate a `BackupPolicy` document from schema version 0 to version 1.
///
/// Version 1 is the first released schema, so this is an identity migration:
/// all v1 fields are either already present in the v0 document (because v0
/// was an informal pre-release format with the same shape) or can be filled
/// with `serde` defaults during final deserialization.
fn migrate_policy_v0_to_v1(_value: &mut Value) {
    // Identity migration: v1 shape matches the original unversioned layout.
}

/// Migrate a `RecoveryPlan` document from schema version 0 to version 1.
fn migrate_plan_v0_to_v1(_value: &mut Value) {
    // Identity migration: v1 shape matches the original unversioned layout.
}

/// Migrate a `RecoveryReport` document from schema version 0 to version 1.
fn migrate_report_v0_to_v1(_value: &mut Value) {
    // Identity migration: v1 shape matches the original unversioned layout.
}

// ── Public migration entry points ─────────────────────────────────────────────

/// Parse a raw JSON value into a [`BackupPolicy`], migrating forward if the
/// on-disk schema version is older than [`CURRENT_POLICY_VERSION`].
///
/// Returns an error when the document's `schema_version` is *newer* than the
/// version this build knows about (i.e. the file was written by a newer
/// StarForge release).
pub fn migrate_policy(mut raw: Value) -> Result<BackupPolicy> {
    let version = read_version(&raw);
    if version > CURRENT_POLICY_VERSION {
        return Err(anyhow!(
            "BackupPolicy schema version {} is newer than the version {} this StarForge \
             build supports. Upgrade StarForge to read this file.",
            version,
            CURRENT_POLICY_VERSION
        ));
    }

    // Apply forward migrations in sequence.
    let mut current = version;
    while current < CURRENT_POLICY_VERSION {
        match current {
            0 => {
                migrate_policy_v0_to_v1(&mut raw);
                current = 1;
            }
            _ => {
                return Err(anyhow!(
                    "No migration path for BackupPolicy from schema version {} to {}.",
                    current,
                    CURRENT_POLICY_VERSION
                ));
            }
        }
        set_version(&mut raw, current);
    }

    serde_json::from_value(raw)
        .map_err(|e| anyhow!("BackupPolicy did not match the expected schema: {}", e))
}

/// Parse a raw JSON value into a [`RecoveryPlan`], migrating forward if the
/// on-disk schema version is older than [`CURRENT_PLAN_VERSION`].
///
/// Returns an error when the document's `schema_version` is *newer* than the
/// version this build knows about.
pub fn migrate_plan(mut raw: Value) -> Result<RecoveryPlan> {
    let version = read_version(&raw);
    if version > CURRENT_PLAN_VERSION {
        return Err(anyhow!(
            "RecoveryPlan schema version {} is newer than the version {} this StarForge \
             build supports. Upgrade StarForge to read this file.",
            version,
            CURRENT_PLAN_VERSION
        ));
    }

    let mut current = version;
    while current < CURRENT_PLAN_VERSION {
        match current {
            0 => {
                migrate_plan_v0_to_v1(&mut raw);
                current = 1;
            }
            _ => {
                return Err(anyhow!(
                    "No migration path for RecoveryPlan from schema version {} to {}.",
                    current,
                    CURRENT_PLAN_VERSION
                ));
            }
        }
        set_version(&mut raw, current);
    }

    serde_json::from_value(raw)
        .map_err(|e| anyhow!("RecoveryPlan did not match the expected schema: {}", e))
}

/// Parse a raw JSON value into a [`RecoveryReport`], migrating forward if the
/// on-disk schema version is older than [`CURRENT_REPORT_VERSION`].
///
/// Returns an error when the document's `schema_version` is *newer* than the
/// version this build knows about.
pub fn migrate_report(mut raw: Value) -> Result<RecoveryReport> {
    let version = read_version(&raw);
    if version > CURRENT_REPORT_VERSION {
        return Err(anyhow!(
            "RecoveryReport schema version {} is newer than the version {} this StarForge \
             build supports. Upgrade StarForge to read this file.",
            version,
            CURRENT_REPORT_VERSION
        ));
    }

    let mut current = version;
    while current < CURRENT_REPORT_VERSION {
        match current {
            0 => {
                migrate_report_v0_to_v1(&mut raw);
                current = 1;
            }
            _ => {
                return Err(anyhow!(
                    "No migration path for RecoveryReport from schema version {} to {}.",
                    current,
                    CURRENT_REPORT_VERSION
                ));
            }
        }
        set_version(&mut raw, current);
    }

    serde_json::from_value(raw)
        .map_err(|e| anyhow!("RecoveryReport did not match the expected schema: {}", e))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ai::recovery::model::{
        EncryptionMode, IntegrityAlgorithm, RiskLevel,
    };
    use chrono::Utc;

    // ── Helper: build minimal v1 BackupPolicy JSON ────────────────────────────

    fn valid_policy_json_v1() -> Value {
        serde_json::json!({
            "schema_version": 1,
            "cadence_hours": 24,
            "retention_count": 7,
            "encryption": "aes256-gcm",
            "integrity": "sha256"
        })
    }

    // ── Helper: build a minimal v1 RecoveryPlan JSON ──────────────────────────

    fn valid_plan_json_v1() -> Value {
        serde_json::json!({
            "schema_version": 1,
            "generated_at": Utc::now().to_rfc3339(),
            "network": "testnet",
            "artifacts": [],
            "risk_score": 10,
            "risk_level": "low",
            "risk_factors": [],
            "ai_narrative": null
        })
    }

    // ── Helper: build a minimal v1 RecoveryReport JSON ───────────────────────

    fn valid_report_json_v1() -> Value {
        serde_json::json!({
            "schema_version": 1,
            "generated_at": Utc::now().to_rfc3339(),
            "plan": valid_plan_json_v1(),
            "verify_summary": null,
            "recommendations": [],
            "ai_narrative": null
        })
    }

    // ── Helper: build a v0 BackupPolicy JSON (no schema_version field) ────────

    fn valid_policy_json_v0() -> Value {
        serde_json::json!({
            // deliberately absent: "schema_version"
            "cadence_hours": 48,
            "retention_count": 14,
            "encryption": "aes256-gcm",
            "integrity": "sha256"
        })
    }

    fn valid_plan_json_v0() -> Value {
        serde_json::json!({
            // deliberately absent: "schema_version"
            "generated_at": Utc::now().to_rfc3339(),
            "network": "mainnet",
            "artifacts": [],
            "risk_score": 5,
            "risk_level": "low",
            "risk_factors": [],
            "ai_narrative": null
        })
    }

    fn valid_report_json_v0() -> Value {
        serde_json::json!({
            // deliberately absent: "schema_version"
            "generated_at": Utc::now().to_rfc3339(),
            "plan": valid_plan_json_v1(),   // plan itself must be v1 to embed
            "verify_summary": null,
            "recommendations": [],
            "ai_narrative": null
        })
    }

    // ── migrate_policy ────────────────────────────────────────────────────────

    #[test]
    fn policy_future_version_returns_error_naming_version() {
        let raw = serde_json::json!({
            "schema_version": 99,
            "cadence_hours": 24,
            "retention_count": 7,
            "encryption": "aes-256-gcm",
            "integrity": "sha256"
        });
        let err = migrate_policy(raw).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("99"),
            "Error message should name the unsupported version 99, got: {msg}"
        );
        assert!(
            msg.contains("BackupPolicy"),
            "Error message should name the document type, got: {msg}"
        );
    }

    #[test]
    fn policy_current_version_deserializes_cleanly() {
        let raw = valid_policy_json_v1();
        let policy = migrate_policy(raw).expect("should deserialize cleanly");
        assert_eq!(policy.schema_version, CURRENT_POLICY_VERSION);
        assert_eq!(policy.cadence_hours, 24);
        assert_eq!(policy.retention_count, 7);
        assert_eq!(policy.encryption, EncryptionMode::Aes256Gcm);
        assert_eq!(policy.integrity, IntegrityAlgorithm::Sha256);
    }

    #[test]
    fn policy_v0_migrates_without_field_loss() {
        let raw = valid_policy_json_v0();
        let policy = migrate_policy(raw).expect("v0 policy should migrate cleanly");
        // After migration the schema_version field must equal the current version.
        assert_eq!(
            policy.schema_version, CURRENT_POLICY_VERSION,
            "schema_version should be bumped to current after migration"
        );
        // All original v0 fields must survive the migration without loss.
        assert_eq!(policy.cadence_hours, 48, "cadence_hours field must not be lost");
        assert_eq!(policy.retention_count, 14, "retention_count field must not be lost");
        assert_eq!(
            policy.encryption,
            EncryptionMode::Aes256Gcm,
            "encryption field must not be lost"
        );
        assert_eq!(
            policy.integrity,
            IntegrityAlgorithm::Sha256,
            "integrity field must not be lost"
        );
    }

    // ── migrate_plan ──────────────────────────────────────────────────────────

    #[test]
    fn plan_future_version_returns_error_naming_version() {
        let raw = serde_json::json!({
            "schema_version": 42,
            "generated_at": Utc::now().to_rfc3339(),
            "network": "testnet",
            "artifacts": [],
            "risk_score": 0,
            "risk_level": "low",
            "risk_factors": [],
            "ai_narrative": null
        });
        let err = migrate_plan(raw).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("42"),
            "Error should name the unsupported version 42, got: {msg}"
        );
        assert!(
            msg.contains("RecoveryPlan"),
            "Error should name the document type, got: {msg}"
        );
    }

    #[test]
    fn plan_current_version_deserializes_cleanly() {
        let raw = valid_plan_json_v1();
        let plan = migrate_plan(raw).expect("should deserialize cleanly");
        assert_eq!(plan.schema_version, CURRENT_PLAN_VERSION);
        assert_eq!(plan.network, "testnet");
        assert_eq!(plan.risk_score, 10);
        assert_eq!(plan.risk_level, RiskLevel::Low);
    }

    #[test]
    fn plan_v0_migrates_without_field_loss() {
        let raw = valid_plan_json_v0();
        let plan = migrate_plan(raw).expect("v0 plan should migrate cleanly");
        assert_eq!(
            plan.schema_version, CURRENT_PLAN_VERSION,
            "schema_version should be bumped to current after migration"
        );
        assert_eq!(plan.network, "mainnet", "network field must not be lost");
        assert_eq!(plan.risk_score, 5, "risk_score field must not be lost");
        assert_eq!(
            plan.risk_level,
            RiskLevel::Low,
            "risk_level field must not be lost"
        );
        assert!(plan.artifacts.is_empty(), "artifacts field must not be lost");
    }

    // ── migrate_report ────────────────────────────────────────────────────────

    #[test]
    fn report_future_version_returns_error_naming_version() {
        let raw = serde_json::json!({
            "schema_version": 255,
            "generated_at": Utc::now().to_rfc3339(),
            "plan": valid_plan_json_v1(),
            "verify_summary": null,
            "recommendations": [],
            "ai_narrative": null
        });
        let err = migrate_report(raw).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("255"),
            "Error should name the unsupported version 255, got: {msg}"
        );
        assert!(
            msg.contains("RecoveryReport"),
            "Error should name the document type, got: {msg}"
        );
    }

    #[test]
    fn report_current_version_deserializes_cleanly() {
        let raw = valid_report_json_v1();
        let report = migrate_report(raw).expect("should deserialize cleanly");
        assert_eq!(report.schema_version, CURRENT_REPORT_VERSION);
        assert_eq!(report.plan.network, "testnet");
    }

    #[test]
    fn report_v0_migrates_without_field_loss() {
        let raw = valid_report_json_v0();
        let report = migrate_report(raw).expect("v0 report should migrate cleanly");
        assert_eq!(
            report.schema_version, CURRENT_REPORT_VERSION,
            "schema_version should be bumped to current after migration"
        );
        assert!(
            report.recommendations.is_empty(),
            "recommendations field must not be lost"
        );
        assert!(
            report.ai_narrative.is_none(),
            "ai_narrative field must not be lost"
        );
    }
}
