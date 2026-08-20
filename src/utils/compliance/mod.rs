//! Configurable regulatory-compliance checking for Soroban contracts
//! (issue #49 / AI-016).
//!
//! This module provides: a versioned compliance-profile format
//! ([`ComplianceProfile`]) with jurisdiction/control-family selection and
//! waiver handling; a deterministic scanner ([`scanner`]) that maps contract
//! wasm facts and deployment metadata to control findings; an append-only
//! evidence log ([`evidence`]); redaction of secret-shaped values in report
//! output ([`redact`]); an additive, opt-in AI-assisted explanation layer
//! ([`ai_assist`]); and audit-ready report assembly ([`report`]).
//!
//! The built-in control catalog ([`framework`]) is an illustrative baseline
//! — a configurable starting point, not legal advice.

pub mod ai_assist;
pub mod evidence;
pub mod framework;
pub mod metadata;
pub mod migrations;
pub mod redact;
pub mod report;
pub mod scanner;
pub mod waiver;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub use waiver::Waiver;

pub const CURRENT_PROFILE_VERSION: &str = "1";
pub const CURRENT_PROFILE_VERSION_NUM: u32 = 1;

fn default_version() -> String {
    CURRENT_PROFILE_VERSION.to_string()
}

fn default_jurisdictions() -> Vec<String> {
    vec!["global-baseline".to_string()]
}

/// A team's configured compliance posture: which jurisdictions/baselines are
/// enabled, and the waivers currently on file. Persisted as versioned TOML
/// at `~/.starforge/compliance/profile.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceProfile {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_jurisdictions")]
    pub enabled_jurisdictions: Vec<String>,
    #[serde(default)]
    pub waivers: Vec<Waiver>,
}

impl Default for ComplianceProfile {
    fn default() -> Self {
        Self {
            version: default_version(),
            enabled_jurisdictions: default_jurisdictions(),
            waivers: Vec::new(),
        }
    }
}

pub fn compliance_dir() -> PathBuf {
    let home = dirs::home_dir().expect("Could not find home directory");
    home.join(".starforge").join("compliance")
}

pub fn profile_path() -> PathBuf {
    compliance_dir().join("profile.toml")
}

pub fn profile_exists() -> bool {
    profile_path().exists()
}

/// Loads the profile, applying any pending schema migrations in memory.
/// Never writes to disk on read (mirrors [`crate::utils::config::load`]) so
/// reads stay side-effect free. Returns the default profile if none exists
/// yet.
pub fn load_profile() -> Result<ComplianceProfile> {
    let path = profile_path();
    if !path.exists() {
        return Ok(ComplianceProfile::default());
    }

    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read compliance profile at {}", path.display()))?;
    let mut value: serde_json::Value = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse compliance profile at {}", path.display()))?;
    migrations::migrate_value(&mut value, CURRENT_PROFILE_VERSION_NUM)?;

    let profile: ComplianceProfile = serde_json::from_value(value)
        .context("Failed to deserialize compliance profile after migration")?;
    Ok(profile)
}

/// Saves the profile, backing up the previous file to `profile.toml.bak`
/// first if its schema version differs from what's about to be written
/// (mirrors [`crate::utils::config::save`]).
pub fn save_profile(profile: &ComplianceProfile) -> Result<()> {
    let dir = compliance_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    }

    let path = profile_path();
    if let Ok(existing) = fs::read_to_string(&path) {
        if let Ok(existing_value) = toml::from_str::<serde_json::Value>(&existing) {
            let existing_version = migrations::read_version(&existing_value).to_string();
            if existing_version != profile.version {
                let backup_path = dir.join("profile.toml.bak");
                fs::write(&backup_path, &existing).with_context(|| {
                    format!("Failed to write backup at {}", backup_path.display())
                })?;
            }
        }
    }

    let contents =
        toml::to_string_pretty(profile).context("Failed to serialize compliance profile")?;
    fs::write(&path, contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Isolates `HOME` for the lifetime of the guard, mirroring the
    /// `TestConfigGuard` pattern in `src/utils/horizon.rs`.
    struct TestHomeGuard {
        _env_lock: MutexGuard<'static, ()>,
        _temp_dir: TempDir,
        original_home: Option<String>,
    }

    impl TestHomeGuard {
        fn new() -> Self {
            let env_lock = TEST_ENV_LOCK.lock().expect("test env lock");
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let original_home = std::env::var("HOME").ok();
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
            }
            Self {
                _env_lock: env_lock,
                _temp_dir: temp_dir,
                original_home,
            }
        }
    }

    impl Drop for TestHomeGuard {
        fn drop(&mut self) {
            match &self.original_home {
                Some(home) => unsafe { std::env::set_var("HOME", home) },
                None => unsafe { std::env::remove_var("HOME") },
            }
        }
    }

    #[test]
    fn default_profile_enables_global_baseline() {
        let profile = ComplianceProfile::default();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(
            profile.enabled_jurisdictions,
            vec!["global-baseline".to_string()]
        );
        assert!(profile.waivers.is_empty());
    }

    #[test]
    fn load_profile_returns_default_when_missing() {
        let _guard = TestHomeGuard::new();
        let profile = load_profile().unwrap();
        assert_eq!(profile, ComplianceProfile::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let _guard = TestHomeGuard::new();
        let mut profile = ComplianceProfile::default();
        profile
            .enabled_jurisdictions
            .push("aml-kyc-baseline".to_string());
        profile
            .waivers
            .push(Waiver::new("AC-1", "accepted for pilot", None));

        save_profile(&profile).unwrap();
        let loaded = load_profile().unwrap();
        assert_eq!(loaded, profile);
    }

    #[test]
    fn profile_exists_reflects_disk_state() {
        let _guard = TestHomeGuard::new();
        assert!(!profile_exists());
        save_profile(&ComplianceProfile::default()).unwrap();
        assert!(profile_exists());
    }

    #[test]
    fn save_backs_up_previous_file_on_version_change() {
        let _guard = TestHomeGuard::new();
        // Write a raw file at a different version by hand.
        let dir = compliance_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            profile_path(),
            "version = \"2\"\nenabled_jurisdictions = []\n",
        )
        .unwrap();

        save_profile(&ComplianceProfile::default()).unwrap();

        let backup_path = dir.join("profile.toml.bak");
        assert!(
            backup_path.exists(),
            "expected a backup to be written on version change"
        );
    }
}
