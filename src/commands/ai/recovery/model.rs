//! Core data model for the AI disaster-recovery subsystem.
//!
//! All persisted types carry a `schema_version` field so
//! [`super::migrations`] can reshape on-disk data forward without silently
//! dropping fields (mirrors the pattern used by the `anomaly` subsystem).

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The kind of item that was found during artifact inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    WasmBinary,
    DeployManifest,
    ContractId,
    KeyReference,
}

/// Whether the artifact was found, found but hash-mismatched, or absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactStatus {
    Present,
    Stale,
    Missing,
}

/// One recoverable item discovered during inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// UUID v4 identifier.
    pub id: String,
    pub kind: ArtifactKind,
    /// Filesystem path, redacted via the secret redactor.
    pub path: String,
    pub status: ArtifactStatus,
    /// Hex SHA-256 digest of the current bytes on disk, if the file exists.
    pub sha256: Option<String>,
    /// Hex SHA-256 digest stored in the manifest, if a manifest exists.
    pub expected_sha256: Option<String>,
    pub size_bytes: u64,
    pub last_modified: DateTime<Utc>,
}

/// The encryption mode for backup archives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode {
    Aes256Gcm,
    None,
}

/// The integrity hash algorithm used for the `.sha256` sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntegrityAlgorithm {
    Sha256,
    Blake3,
}

/// User-editable backup configuration persisted to `policy.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// Must equal [`crate::commands::ai::recovery::migrations::CURRENT_POLICY_VERSION`].
    pub schema_version: u8,
    /// How often a backup should be taken, in hours. Valid range: 1–8760.
    pub cadence_hours: u32,
    /// How many backup archives to keep. Valid range: 1–365.
    pub retention_count: u32,
    pub encryption: EncryptionMode,
    pub integrity: IntegrityAlgorithm,
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            cadence_hours: 24,
            retention_count: 7,
            encryption: EncryptionMode::Aes256Gcm,
            integrity: IntegrityAlgorithm::Sha256,
        }
    }
}

/// Validate a [`BackupPolicy`], returning an error if any field is outside its
/// allowed range and emitting a warning when encryption is disabled.
///
/// # Errors
/// - `retention_count` must be in `[1, 365]`
/// - `cadence_hours` must be in `[1, 8760]`
pub fn validate_policy(policy: &BackupPolicy) -> Result<()> {
    if !(1..=365).contains(&policy.retention_count) {
        bail!(
            "retention_count must be between 1 and 365, got {}",
            policy.retention_count
        );
    }
    if !(1..=8760).contains(&policy.cadence_hours) {
        bail!(
            "cadence_hours must be between 1 and 8760, got {}",
            policy.cadence_hours
        );
    }
    if policy.encryption == EncryptionMode::None {
        eprintln!(
            "warning: backup encryption is disabled (encryption = none); \
             the backup archive will contain sensitive deployment metadata in plain text"
        );
    }
    Ok(())
}

/// One contributing factor to the overall risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub description: String,
    pub points: u8,
}

/// Risk band derived from the numeric score.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Map a numeric score (0–100) to its risk band.
    ///
    /// | Range   | Band     |
    /// |---------|----------|
    /// | 0–29    | Low      |
    /// | 30–59   | Medium   |
    /// | 60–84   | High     |
    /// | 85–100  | Critical |
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=29 => RiskLevel::Low,
            30..=59 => RiskLevel::Medium,
            60..=84 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// The machine-readable output of `starforge ai recovery plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub network: String,
    pub artifacts: Vec<Artifact>,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub ai_narrative: Option<String>,
}

/// Per-archive result from `starforge ai recovery verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub archive_path: String,
    pub status: VerifyStatus,
    pub expected_digest: Option<String>,
    pub actual_digest: Option<String>,
}

/// Status of a single archive verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyStatus {
    Ok,
    Corrupted,
    Unverifiable,
}

impl VerifyResult {
    /// Return a static string representation of the verify status suitable for
    /// display in human-readable CLI output.
    pub fn status_str(&self) -> &'static str {
        match self.status {
            VerifyStatus::Ok => "OK",
            VerifyStatus::Corrupted => "CORRUPTED",
            VerifyStatus::Unverifiable => "UNVERIFIABLE",
        }
    }
}

/// Per-artifact validation result from `restore-dry-run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactValidation {
    pub artifact_id: String,
    pub passed: bool,
    pub issues: Vec<String>,
}

/// Output of `starforge ai recovery restore-dry-run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub archive_path: String,
    pub artifact_count: usize,
    pub validation_results: Vec<ArtifactValidation>,
    pub simulation_passed: bool,
    pub simulated_restore_duration_ms: u64,
}

/// Result of `starforge ai recovery backup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupResult {
    pub archive_path: String,
    pub artifact_count: usize,
    pub size_bytes: u64,
    pub integrity_digest: String,
    pub timestamp: DateTime<Utc>,
}

/// Output of `starforge ai recovery report`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub plan: RecoveryPlan,
    pub verify_summary: Option<Vec<VerifyResult>>,
    pub recommendations: Vec<Recommendation>,
    pub ai_narrative: Option<String>,
}

/// A single recommended remediation step, sortable by risk contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Risk points this recommendation addresses — used for priority sort.
    pub priority: u8,
    pub description: String,
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RiskLevel::from_score ────────────────────────────────────────────────

    #[test]
    fn risk_level_from_score_low_boundary_zero() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
    }

    #[test]
    fn risk_level_from_score_low_boundary_29() {
        assert_eq!(RiskLevel::from_score(29), RiskLevel::Low);
    }

    #[test]
    fn risk_level_from_score_medium_boundary_30() {
        assert_eq!(RiskLevel::from_score(30), RiskLevel::Medium);
    }

    #[test]
    fn risk_level_from_score_medium_boundary_59() {
        assert_eq!(RiskLevel::from_score(59), RiskLevel::Medium);
    }

    #[test]
    fn risk_level_from_score_high_boundary_60() {
        assert_eq!(RiskLevel::from_score(60), RiskLevel::High);
    }

    #[test]
    fn risk_level_from_score_high_boundary_84() {
        assert_eq!(RiskLevel::from_score(84), RiskLevel::High);
    }

    #[test]
    fn risk_level_from_score_critical_boundary_85() {
        assert_eq!(RiskLevel::from_score(85), RiskLevel::Critical);
    }

    #[test]
    fn risk_level_from_score_critical_boundary_100() {
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
    }

    // ── BackupPolicy::default ────────────────────────────────────────────────

    #[test]
    fn backup_policy_default_schema_version_is_1() {
        assert_eq!(BackupPolicy::default().schema_version, 1);
    }

    #[test]
    fn backup_policy_default_cadence_hours_is_24() {
        assert_eq!(BackupPolicy::default().cadence_hours, 24);
    }

    #[test]
    fn backup_policy_default_retention_count_is_7() {
        assert_eq!(BackupPolicy::default().retention_count, 7);
    }

    #[test]
    fn backup_policy_default_encryption_is_aes256gcm() {
        assert_eq!(
            BackupPolicy::default().encryption,
            EncryptionMode::Aes256Gcm
        );
    }

    #[test]
    fn backup_policy_default_integrity_is_sha256() {
        assert_eq!(
            BackupPolicy::default().integrity,
            IntegrityAlgorithm::Sha256
        );
    }

    // ── JSON round-trip serialization ────────────────────────────────────────

    #[test]
    fn backup_policy_serialization_round_trip() {
        let policy = BackupPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: BackupPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.schema_version, policy.schema_version);
        assert_eq!(restored.cadence_hours, policy.cadence_hours);
        assert_eq!(restored.retention_count, policy.retention_count);
        assert_eq!(restored.encryption, policy.encryption);
        assert_eq!(restored.integrity, policy.integrity);
    }

    #[test]
    fn verify_result_serialization_round_trip() {
        let result = VerifyResult {
            archive_path: "/tmp/test.tar.gz".to_string(),
            status: VerifyStatus::Ok,
            expected_digest: Some("abc123".to_string()),
            actual_digest: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: VerifyResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.archive_path, result.archive_path);
        assert_eq!(restored.status, VerifyStatus::Ok);
        assert_eq!(restored.expected_digest, result.expected_digest);
        assert_eq!(restored.actual_digest, result.actual_digest);
    }

    #[test]
    fn recovery_plan_serialization_round_trip() {
        let plan = RecoveryPlan {
            schema_version: 1,
            generated_at: Utc::now(),
            network: "testnet".to_string(),
            artifacts: vec![],
            risk_score: 42,
            risk_level: RiskLevel::Medium,
            risk_factors: vec![],
            ai_narrative: None,
        };
        let json = serde_json::to_string(&plan).expect("serialize");
        let restored: RecoveryPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.schema_version, 1);
        assert_eq!(restored.network, "testnet");
        assert_eq!(restored.risk_score, 42);
        assert_eq!(restored.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn recovery_report_serialization_round_trip() {
        let plan = RecoveryPlan {
            schema_version: 1,
            generated_at: Utc::now(),
            network: "mainnet".to_string(),
            artifacts: vec![],
            risk_score: 10,
            risk_level: RiskLevel::Low,
            risk_factors: vec![],
            ai_narrative: None,
        };
        let report = RecoveryReport {
            schema_version: 1,
            generated_at: Utc::now(),
            plan,
            verify_summary: None,
            recommendations: vec![],
            ai_narrative: None,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let restored: RecoveryReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.schema_version, 1);
        assert_eq!(restored.plan.network, "mainnet");
    }

    // ── as_str ───────────────────────────────────────────────────────────────

    #[test]
    fn risk_level_as_str_values() {
        assert_eq!(RiskLevel::Low.as_str(), "low");
        assert_eq!(RiskLevel::Medium.as_str(), "medium");
        assert_eq!(RiskLevel::High.as_str(), "high");
        assert_eq!(RiskLevel::Critical.as_str(), "critical");
    }

    // ── validate_policy ──────────────────────────────────────────────────────

    #[test]
    fn validate_policy_default_is_ok() {
        assert!(validate_policy(&BackupPolicy::default()).is_ok());
    }

    #[test]
    fn validate_policy_retention_count_zero_is_err() {
        let policy = BackupPolicy {
            retention_count: 0,
            ..BackupPolicy::default()
        };
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("retention_count"));
        assert!(err.to_string().contains('0'.to_string().as_str()));
    }

    #[test]
    fn validate_policy_retention_count_366_is_err() {
        let policy = BackupPolicy {
            retention_count: 366,
            ..BackupPolicy::default()
        };
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("retention_count"));
        assert!(err.to_string().contains("366"));
    }

    #[test]
    fn validate_policy_cadence_hours_zero_is_err() {
        let policy = BackupPolicy {
            cadence_hours: 0,
            ..BackupPolicy::default()
        };
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("cadence_hours"));
    }

    #[test]
    fn validate_policy_cadence_hours_8761_is_err() {
        let policy = BackupPolicy {
            cadence_hours: 8761,
            ..BackupPolicy::default()
        };
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("cadence_hours"));
        assert!(err.to_string().contains("8761"));
    }

    #[test]
    fn validate_policy_boundary_values_are_ok() {
        let policy1 = BackupPolicy {
            retention_count: 1,
            cadence_hours: 1,
            ..BackupPolicy::default()
        };
        assert!(validate_policy(&policy1).is_ok());

        let policy2 = BackupPolicy {
            retention_count: 365,
            cadence_hours: 8760,
            ..BackupPolicy::default()
        };
        assert!(validate_policy(&policy2).is_ok());
    }

    // ── Property 6: Policy field range validation ────────────────────────────
    // Feature: ai-disaster-recovery, Property 6: Policy field range validation
    // Validates: Requirements 2.6, 2.7

    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// For any i64 value for retention_count: if it fits in u32 and is
            /// outside [1, 365], validate_policy must return Err; if it is within
            /// [1, 365], validate_policy must return Ok (holding cadence_hours fixed
            /// at a valid value).
            #[test]
            fn prop_retention_count_range_validation(raw_retention in i64::MIN..=i64::MAX) {
                // Use a valid cadence_hours so only retention_count is under test.
                let cadence_hours: u32 = 24;

                if let Ok(retention_count) = u32::try_from(raw_retention) {
                    let policy = BackupPolicy {
                        schema_version: 1,
                        cadence_hours,
                        retention_count,
                        encryption: EncryptionMode::Aes256Gcm,
                        integrity: IntegrityAlgorithm::Sha256,
                    };
                    if !(1..=365).contains(&retention_count) {
                        prop_assert!(
                            validate_policy(&policy).is_err(),
                            "expected Err for retention_count = {}",
                            retention_count
                        );
                        let msg = validate_policy(&policy).unwrap_err().to_string();
                        prop_assert!(
                            msg.contains("retention_count"),
                            "error message should mention 'retention_count', got: {}",
                            msg
                        );
                    } else {
                        prop_assert!(
                            validate_policy(&policy).is_ok(),
                            "expected Ok for retention_count = {}",
                            retention_count
                        );
                    }
                }
                // Values that don't fit in u32 are negative; u32 conversion fails and
                // we simply skip — they can never be stored in a BackupPolicy.
            }

            /// For any i64 value for cadence_hours: if it fits in u32 and is
            /// outside [1, 8760], validate_policy must return Err; if it is within
            /// [1, 8760], validate_policy must return Ok (holding retention_count
            /// fixed at a valid value).
            #[test]
            fn prop_cadence_hours_range_validation(raw_cadence in i64::MIN..=i64::MAX) {
                // Use a valid retention_count so only cadence_hours is under test.
                let retention_count: u32 = 7;

                if let Ok(cadence_hours) = u32::try_from(raw_cadence) {
                    let policy = BackupPolicy {
                        schema_version: 1,
                        cadence_hours,
                        retention_count,
                        encryption: EncryptionMode::Aes256Gcm,
                        integrity: IntegrityAlgorithm::Sha256,
                    };
                    if !(1..=8760).contains(&cadence_hours) {
                        prop_assert!(
                            validate_policy(&policy).is_err(),
                            "expected Err for cadence_hours = {}",
                            cadence_hours
                        );
                        let msg = validate_policy(&policy).unwrap_err().to_string();
                        prop_assert!(
                            msg.contains("cadence_hours"),
                            "error message should mention 'cadence_hours', got: {}",
                            msg
                        );
                    } else {
                        prop_assert!(
                            validate_policy(&policy).is_ok(),
                            "expected Ok for cadence_hours = {}",
                            cadence_hours
                        );
                    }
                }
            }
        }
    }
}
