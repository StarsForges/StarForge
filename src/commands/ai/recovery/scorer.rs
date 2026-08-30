// Offline risk scorer — implemented in task 6.

use chrono::{DateTime, Utc};

use super::model::{
    Artifact, ArtifactKind, ArtifactStatus, BackupPolicy, RiskFactor, RiskLevel,
};

/// Compute the offline risk score for the current recovery state.
///
/// Accumulates point contributions from five distinct conditions. Each
/// condition contributes at most once regardless of how many artifacts trigger
/// it (deduplicated per condition, not per artifact):
///
/// | Condition                                       | Points |
/// |-------------------------------------------------|--------|
/// | Missing WASM binary (`kind=WasmBinary, status=Missing`) | +30 |
/// | Missing Manifest (`kind=DeployManifest, status=Missing`) | +25 |
/// | Stale digest mismatch (any artifact `status=Stale`)      | +20 |
/// | Unencrypted key reference (`kind=KeyReference`)          | +15 |
/// | No backup within `cadence_hours`                         | +10 |
///
/// The total is clamped to `[0, 100]` and a [`RiskLevel`] is derived via
/// [`RiskLevel::from_score`].
///
/// Returns `(score, level, risk_factors)`.
pub fn score_offline(
    artifacts: &[Artifact],
    policy: &BackupPolicy,
    last_backup_ts: Option<DateTime<Utc>>,
) -> (u8, RiskLevel, Vec<RiskFactor>) {
    let mut factors: Vec<RiskFactor> = Vec::new();

    // Condition 1: missing WASM binary (+30)
    let has_missing_wasm = artifacts
        .iter()
        .any(|a| a.kind == ArtifactKind::WasmBinary && a.status == ArtifactStatus::Missing);
    if has_missing_wasm {
        factors.push(RiskFactor {
            description: "Missing WASM binary: at least one WasmBinary artifact is absent"
                .to_string(),
            points: 30,
        });
    }

    // Condition 2: missing deploy manifest (+25)
    let has_missing_manifest = artifacts
        .iter()
        .any(|a| a.kind == ArtifactKind::DeployManifest && a.status == ArtifactStatus::Missing);
    if has_missing_manifest {
        factors.push(RiskFactor {
            description: "Missing deploy manifest: at least one DeployManifest artifact is absent"
                .to_string(),
            points: 25,
        });
    }

    // Condition 3: stale digest mismatch (+20)
    let has_stale = artifacts.iter().any(|a| a.status == ArtifactStatus::Stale);
    if has_stale {
        factors.push(RiskFactor {
            description: "Stale digest mismatch: at least one artifact has a digest that does not match the stored manifest"
                .to_string(),
            points: 20,
        });
    }

    // Condition 4: unencrypted key reference (+15)
    // Any artifact with kind=KeyReference signals that a key is referenced in
    // an artifact path, which may expose sensitive material.
    let has_key_reference = artifacts
        .iter()
        .any(|a| a.kind == ArtifactKind::KeyReference);
    if has_key_reference {
        factors.push(RiskFactor {
            description: "Unencrypted key reference: at least one artifact path contains a key reference"
                .to_string(),
            points: 15,
        });
    }

    // Condition 5: no backup within cadence_hours (+10)
    let backup_overdue = match last_backup_ts {
        None => true,
        Some(ts) => {
            let elapsed = Utc::now().signed_duration_since(ts);
            elapsed.num_hours() >= policy.cadence_hours as i64
        }
    };
    if backup_overdue {
        factors.push(RiskFactor {
            description: format!(
                "No backup in the last {} hour(s): backup cadence has been exceeded",
                policy.cadence_hours
            ),
            points: 10,
        });
    }

    // Sum all factor points, clamp to [0, 100]
    let raw_total: u32 = factors.iter().map(|f| f.points as u32).sum();
    let score = raw_total.min(100) as u8;
    let level = RiskLevel::from_score(score);

    (score, level, factors)
}

// ── Unit tests (task 6.1) ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_artifact(kind: ArtifactKind, status: ArtifactStatus) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            path: "/tmp/artifact".to_string(),
            status,
            sha256: None,
            expected_sha256: None,
            size_bytes: 0,
            last_modified: Utc::now(),
        }
    }

    fn default_policy() -> BackupPolicy {
        BackupPolicy::default() // cadence_hours = 24
    }

    // ── Individual condition tests ────────────────────────────────────────────

    #[test]
    fn condition_missing_wasm_adds_30() {
        let artifacts = vec![make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing)];
        let (score, _level, factors) =
            score_offline(&artifacts, &default_policy(), Some(Utc::now()));
        assert_eq!(score, 30);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].points, 30);
    }

    #[test]
    fn condition_missing_manifest_adds_25() {
        let artifacts =
            vec![make_artifact(ArtifactKind::DeployManifest, ArtifactStatus::Missing)];
        let (score, _level, factors) =
            score_offline(&artifacts, &default_policy(), Some(Utc::now()));
        assert_eq!(score, 25);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].points, 25);
    }

    #[test]
    fn condition_stale_artifact_adds_20() {
        let artifacts = vec![make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Stale)];
        let (score, _level, factors) =
            score_offline(&artifacts, &default_policy(), Some(Utc::now()));
        assert_eq!(score, 20);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].points, 20);
    }

    #[test]
    fn condition_key_reference_adds_15() {
        let artifacts = vec![make_artifact(ArtifactKind::KeyReference, ArtifactStatus::Present)];
        let (score, _level, factors) =
            score_offline(&artifacts, &default_policy(), Some(Utc::now()));
        assert_eq!(score, 15);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].points, 15);
    }

    #[test]
    fn condition_no_backup_none_ts_adds_10() {
        let artifacts: Vec<Artifact> = vec![];
        let (score, _level, factors) = score_offline(&artifacts, &default_policy(), None);
        assert_eq!(score, 10);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].points, 10);
    }

    #[test]
    fn condition_no_backup_stale_ts_adds_10() {
        // Backup was 48 hours ago, cadence is 24 hours → overdue
        let old_ts = Utc::now() - Duration::hours(48);
        let artifacts: Vec<Artifact> = vec![];
        let (score, _level, factors) = score_offline(&artifacts, &default_policy(), Some(old_ts));
        assert_eq!(score, 10);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].points, 10);
    }

    #[test]
    fn condition_no_backup_recent_ts_no_penalty() {
        // Backup was 1 hour ago, cadence is 24 hours → not overdue
        let recent_ts = Utc::now() - Duration::hours(1);
        let artifacts: Vec<Artifact> = vec![];
        let (score, _level, factors) =
            score_offline(&artifacts, &default_policy(), Some(recent_ts));
        assert_eq!(score, 0);
        assert!(factors.is_empty());
    }

    // ── Deduplication: multiple artifacts triggering same condition ───────────

    #[test]
    fn two_missing_wasms_still_add_30_once() {
        let artifacts = vec![
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing),
        ];
        let (score, _level, factors) =
            score_offline(&artifacts, &default_policy(), Some(Utc::now()));
        // Only one RiskFactor for missing WASM
        let wasm_factors: Vec<_> = factors.iter().filter(|f| f.points == 30).collect();
        assert_eq!(wasm_factors.len(), 1);
        assert_eq!(score, 30);
    }

    // ── Score clamp ───────────────────────────────────────────────────────────

    #[test]
    fn score_clamp_all_conditions_clamped_to_100() {
        // All five conditions: 30+25+20+15+10 = 100; already exactly 100, not
        // exceeding — add an extra stale manifest to confirm we never exceed 100.
        let artifacts = vec![
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::DeployManifest, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Stale),
            make_artifact(ArtifactKind::KeyReference, ArtifactStatus::Present),
        ];
        // No recent backup
        let (score, _level, _factors) = score_offline(&artifacts, &default_policy(), None);
        // 30+25+20+15+10 = 100; clamped to 100
        assert_eq!(score, 100);
    }

    #[test]
    fn score_exceeding_100_clamped() {
        // Manually construct a policy where cadence check triggers, and all
        // artifact conditions trigger — total would be 100, which already
        // tests the exact boundary. To test *above* 100 we'd need more than 5
        // distinct conditions, which doesn't exist; so we verify the sum is
        // exactly capped at 100.
        let artifacts = vec![
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::DeployManifest, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Stale),
            make_artifact(ArtifactKind::KeyReference, ArtifactStatus::Present),
        ];
        let (score, _level, factors) = score_offline(&artifacts, &default_policy(), None);
        let sum: u32 = factors.iter().map(|f| f.points as u32).sum();
        assert!(score <= 100);
        assert_eq!(score, sum.min(100) as u8);
    }

    // ── RiskLevel boundary values ─────────────────────────────────────────────

    #[test]
    fn score_0_is_low() {
        let recent_ts = Utc::now() - Duration::hours(1);
        let (score, level, _) = score_offline(&[], &default_policy(), Some(recent_ts));
        assert_eq!(score, 0);
        assert_eq!(level, RiskLevel::Low);
    }

    #[test]
    fn score_29_is_low() {
        // Only stale (20) + no backup? Let's get a 29 by using stale+key_ref (20+15=35, too high)
        // Use stale only = 20, plus a policy where backup is not overdue = 20. Still not 29.
        // The score is derived from discrete conditions so exact "29" can only come from
        // RiskLevel::from_score directly. Let's verify RiskLevel::from_score(29) == Low.
        assert_eq!(RiskLevel::from_score(29), RiskLevel::Low);
    }

    #[test]
    fn score_30_is_medium() {
        let artifacts = vec![make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing)];
        let recent_ts = Utc::now() - Duration::hours(1);
        let (score, level, _) = score_offline(&artifacts, &default_policy(), Some(recent_ts));
        assert_eq!(score, 30);
        assert_eq!(level, RiskLevel::Medium);
    }

    #[test]
    fn score_60_is_high() {
        // missing wasm (30) + missing manifest (25) = 55, not 60
        // missing wasm (30) + stale (20) + key_ref (15) = 65 — let's use stale+key+backup = 20+15+10=45
        // Actually: missing manifest (25) + stale (20) + key (15) = 60
        let artifacts = vec![
            make_artifact(ArtifactKind::DeployManifest, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Stale),
            make_artifact(ArtifactKind::KeyReference, ArtifactStatus::Present),
        ];
        let recent_ts = Utc::now() - Duration::hours(1);
        let (score, level, _) = score_offline(&artifacts, &default_policy(), Some(recent_ts));
        assert_eq!(score, 60);
        assert_eq!(level, RiskLevel::High);
    }

    #[test]
    fn score_85_is_critical() {
        // missing wasm (30) + missing manifest (25) + stale (20) + key_ref (15) = 90
        // Use: missing wasm (30) + stale (20) + key (15) + no backup (10) = 75 — not 85
        // Use: missing wasm (30) + missing manifest (25) + stale (20) + key (15) = 90 — closest to 85 above
        // The exact score 85 maps to Critical via RiskLevel::from_score
        assert_eq!(RiskLevel::from_score(85), RiskLevel::Critical);
        // Also test an actual artifact combo that yields >=85
        let artifacts = vec![
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::DeployManifest, ArtifactStatus::Missing),
            make_artifact(ArtifactKind::WasmBinary, ArtifactStatus::Stale),
            make_artifact(ArtifactKind::KeyReference, ArtifactStatus::Present),
        ];
        let recent_ts = Utc::now() - Duration::hours(1);
        let (score, level, _) = score_offline(&artifacts, &default_policy(), Some(recent_ts));
        assert_eq!(score, 90);
        assert_eq!(level, RiskLevel::Critical);
    }

    // ── Zero score → Low ──────────────────────────────────────────────────────

    #[test]
    fn empty_artifacts_recent_backup_score_zero() {
        let recent_ts = Utc::now() - Duration::minutes(30);
        let (score, level, factors) = score_offline(&[], &default_policy(), Some(recent_ts));
        assert_eq!(score, 0);
        assert_eq!(level, RiskLevel::Low);
        assert!(factors.is_empty());
    }
}

// ── Property-based tests (task 6.2) ──────────────────────────────────────────

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    // Generators for arbitrary Artifact values

    fn arb_artifact_kind() -> impl Strategy<Value = ArtifactKind> {
        prop_oneof![
            Just(ArtifactKind::WasmBinary),
            Just(ArtifactKind::DeployManifest),
            Just(ArtifactKind::ContractId),
            Just(ArtifactKind::KeyReference),
        ]
    }

    fn arb_artifact_status() -> impl Strategy<Value = ArtifactStatus> {
        prop_oneof![
            Just(ArtifactStatus::Present),
            Just(ArtifactStatus::Stale),
            Just(ArtifactStatus::Missing),
        ]
    }

    fn arb_artifact() -> impl Strategy<Value = Artifact> {
        (arb_artifact_kind(), arb_artifact_status()).prop_map(|(kind, status)| Artifact {
            id: "test-id".to_string(),
            kind,
            path: "/tmp/test".to_string(),
            status,
            sha256: None,
            expected_sha256: None,
            size_bytes: 0,
            last_modified: Utc::now(),
        })
    }

    fn arb_artifacts() -> impl Strategy<Value = Vec<Artifact>> {
        prop::collection::vec(arb_artifact(), 0..=20)
    }

    fn arb_backup_policy() -> impl Strategy<Value = BackupPolicy> {
        // cadence_hours in valid range [1, 8760]
        (1u32..=8760u32).prop_map(|cadence_hours| BackupPolicy {
            schema_version: 1,
            cadence_hours,
            retention_count: 7,
            encryption: super::super::model::EncryptionMode::Aes256Gcm,
            integrity: super::super::model::IntegrityAlgorithm::Sha256,
        })
    }

    fn arb_last_backup_ts() -> impl Strategy<Value = Option<DateTime<Utc>>> {
        prop_oneof![
            Just(None),
            // Recent backup (0–200 hours ago)
            (0i64..=200i64).prop_map(|hours_ago| Some(Utc::now() - chrono::Duration::hours(hours_ago))),
        ]
    }

    // Feature: ai-disaster-recovery, Property 8: Risk score bounded invariant
    // Validates: Requirements 5.1, 5.4, 5.5
    proptest! {
        #[test]
        fn prop_score_bounded_and_level_consistent(
            artifacts in arb_artifacts(),
            policy in arb_backup_policy(),
            last_backup_ts in arb_last_backup_ts(),
        ) {
            let (score, level, _factors) = score_offline(&artifacts, &policy, last_backup_ts);

            // Score must be in [0, 100]
            prop_assert!(score <= 100, "score {} exceeds 100", score);

            // RiskLevel must be consistent with the score
            prop_assert_eq!(
                level,
                RiskLevel::from_score(score),
                "risk_level inconsistent with score {}",
                score
            );
        }
    }

    // Feature: ai-disaster-recovery, Property 9: Risk score additivity
    // Validates: Requirements 5.4, 5.5
    proptest! {
        #[test]
        fn prop_score_equals_clamped_sum_of_factors(
            artifacts in arb_artifacts(),
            policy in arb_backup_policy(),
            last_backup_ts in arb_last_backup_ts(),
        ) {
            let (score, _level, factors) = score_offline(&artifacts, &policy, last_backup_ts);

            // risk_score == min(sum of risk_factors[i].points, 100)
            let sum: u32 = factors.iter().map(|f| f.points as u32).sum();
            let expected_score = sum.min(100) as u8;

            prop_assert_eq!(
                score,
                expected_score,
                "score {} != min(sum={}, 100)",
                score,
                sum
            );
        }
    }
}
