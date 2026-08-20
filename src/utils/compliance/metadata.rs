//! User-supplied deployment metadata: the operational-policy answers that
//! can't be derived from static contract inspection alone (signer setup,
//! upgrade governance, KYC/AML posture, incident response, disclosures).
//!
//! This is loaded from a TOML file passed to `starforge compliance check
//! --metadata <path>`, so teams can keep their compliance answers under
//! version control alongside the contract itself.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DeploymentMetadata {
    /// Public keys authorized to sign administrative operations.
    #[serde(default)]
    pub signer_public_keys: Vec<String>,
    /// Minimum number of signers required for administrative operations.
    #[serde(default)]
    pub signer_threshold: Option<u8>,
    /// Whether contract upgrades require multisig approval.
    #[serde(default)]
    pub upgrade_authority_multisig: bool,
    /// Delay (in seconds) between an upgrade proposal and its execution.
    #[serde(default)]
    pub upgrade_timelock_seconds: Option<u64>,
    /// Whether the contract is known to store personal data on-chain.
    #[serde(default)]
    pub stores_personal_data: bool,
    /// Whether a data-minimization review has been completed.
    #[serde(default)]
    pub data_minimization_reviewed: bool,
    /// Whether a KYC/identity-verification provider is integrated.
    #[serde(default)]
    pub kyc_provider_integrated: bool,
    /// Whether sanctions screening is applied before fund transfers.
    #[serde(default)]
    pub sanctions_screening: bool,
    /// Whether transfer restrictions are documented.
    #[serde(default)]
    pub transfer_restrictions_documented: bool,
    /// Whether the contract exposes an emergency pause mechanism.
    #[serde(default)]
    pub has_pause_mechanism: bool,
    /// Named contact or channel for reporting incidents.
    #[serde(default)]
    pub incident_response_contact: Option<String>,
    /// Publicly reachable terms-of-service URL.
    #[serde(default)]
    pub terms_of_service_url: Option<String>,
    /// Publicly reachable privacy-policy URL.
    #[serde(default)]
    pub privacy_policy_url: Option<String>,
}

impl DeploymentMetadata {
    /// True when at least `threshold` distinct signers are configured and a
    /// threshold of 2 or more was requested (a single-signer "threshold" of 1
    /// is not multi-party authorization).
    pub fn has_multi_party_signers(&self) -> bool {
        match self.signer_threshold {
            Some(threshold) if threshold >= 2 => self.signer_public_keys.len() as u8 >= threshold,
            _ => false,
        }
    }
}

/// Loads deployment metadata from a TOML file.
pub fn load_metadata(path: &Path) -> Result<DeploymentMetadata> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read deployment metadata at {}", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("Failed to parse deployment metadata at {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_metadata_has_no_multi_party_signers() {
        assert!(!DeploymentMetadata::default().has_multi_party_signers());
    }

    #[test]
    fn threshold_of_one_is_not_multi_party() {
        let meta = DeploymentMetadata {
            signer_public_keys: vec!["G1".into(), "G2".into()],
            signer_threshold: Some(1),
            ..Default::default()
        };
        assert!(!meta.has_multi_party_signers());
    }

    #[test]
    fn enough_signers_at_threshold_is_multi_party() {
        let meta = DeploymentMetadata {
            signer_public_keys: vec!["G1".into(), "G2".into(), "G3".into()],
            signer_threshold: Some(2),
            ..Default::default()
        };
        assert!(meta.has_multi_party_signers());
    }

    #[test]
    fn too_few_signers_for_threshold_is_not_multi_party() {
        let meta = DeploymentMetadata {
            signer_public_keys: vec!["G1".into()],
            signer_threshold: Some(2),
            ..Default::default()
        };
        assert!(!meta.has_multi_party_signers());
    }

    #[test]
    fn load_metadata_parses_a_minimal_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.toml");
        std::fs::write(
            &path,
            r#"
            signer_public_keys = ["G1", "G2"]
            signer_threshold = 2
            has_pause_mechanism = true
            "#,
        )
        .unwrap();

        let meta = load_metadata(&path).unwrap();
        assert_eq!(meta.signer_public_keys, vec!["G1", "G2"]);
        assert_eq!(meta.signer_threshold, Some(2));
        assert!(meta.has_pause_mechanism);
        assert!(!meta.kyc_provider_integrated);
    }

    #[test]
    fn load_metadata_errors_on_missing_file() {
        let result = load_metadata(Path::new("/nonexistent/metadata.toml"));
        assert!(result.is_err());
    }
}
