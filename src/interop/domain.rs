//! Versioned contracts for Stellar CLI ↔ StarForge configuration interoperability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

pub const INTEROP_SCHEMA_VERSION: u32 = 1;
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;
pub const STELLAR_NETWORK_FORMAT_V1: u32 = 1;
pub const STELLAR_IDENTITY_FORMAT_V1: u32 = 1;
pub const STELLAR_IDENTITY_FORMAT_V2: u32 = 2;
pub const STELLAR_CONTRACT_ALIAS_FORMAT_V1: u32 = 1;
pub const STELLAR_CONTRACT_ALIAS_FORMAT_V2: u32 = 2;

/// Which configuration store a record originated from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    StarForge,
    StellarCli,
    LegacySorobanCli,
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StarForge => write!(f, "starforge"),
            Self::StellarCli => write!(f, "stellar_cli"),
            Self::LegacySorobanCli => write!(f, "legacy_soroban_cli"),
        }
    }
}

/// Direction of a synchronization operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDirection {
    ImportToStarforge,
    ExportToStellarCli,
    Bidirectional,
}

/// How conflicts between StarForge and Stellar CLI records should be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecedencePolicy {
    /// StarForge values win on conflict.
    StarforgeWins,
    /// Stellar CLI values win on conflict.
    StellarCliWins,
    /// Newer fingerprint wins; ties require explicit resolution.
    NewestFingerprint,
    /// Never overwrite existing records; only add missing entries.
    AdditiveOnly,
    /// Fail the operation when any conflict is detected.
    FailOnConflict,
}

impl Default for PrecedencePolicy {
    fn default() -> Self {
        Self::FailOnConflict
    }
}

/// Classification of a diff item between two configuration stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Record exists only in the source store.
    MissingInTarget,
    /// Record exists only in the target store.
    MissingInSource,
    /// Both stores have the record but field values differ.
    ValueMismatch,
    /// Network name matches but underlying endpoints/passphrases differ.
    NetworkMismatch,
    /// Identity name matches but public keys differ.
    IdentityMismatch,
    /// Contract alias matches but contract IDs differ.
    ContractAliasMismatch,
    /// Duplicate names within a single store.
    DuplicateName,
    /// Format version is unsupported or requires migration.
    UnsupportedFormat,
    /// Symlink or non-regular file encountered.
    IrregularFile,
    /// File permissions are too permissive for secrets.
    InsecurePermissions,
    /// Encrypted secret present and migration requires explicit opt-in.
    EncryptedSecret,
    /// No conflict; records are equivalent.
    Equivalent,
}

impl ConflictKind {
    pub fn is_blocking(self) -> bool {
        !matches!(
            self,
            Self::Equivalent | Self::MissingInTarget | Self::MissingInSource
        )
    }

    pub fn requires_confirmation(self) -> bool {
        matches!(
            self,
            Self::ValueMismatch
                | Self::NetworkMismatch
                | Self::IdentityMismatch
                | Self::ContractAliasMismatch
                | Self::EncryptedSecret
                | Self::InsecurePermissions
        )
    }
}

/// A normalized network definition shared across both configuration stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedNetwork {
    pub name: String,
    pub horizon_url: String,
    pub rpc_url: Option<String>,
    pub friendbot_url: Option<String>,
    pub passphrase: Option<String>,
    pub format_version: u32,
    pub source: ConfigSource,
    pub source_path: Option<PathBuf>,
    pub fingerprint: String,
}

impl NormalizedNetwork {
    pub fn canonical_key(&self) -> String {
        self.name.to_ascii_lowercase()
    }

    pub fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update(self.horizon_url.as_bytes());
        if let Some(rpc) = &self.rpc_url {
            hasher.update(rpc.as_bytes());
        }
        if let Some(fb) = &self.friendbot_url {
            hasher.update(fb.as_bytes());
        }
        if let Some(pp) = &self.passphrase {
            hasher.update(pp.as_bytes());
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

/// Whether an identity carries secret material and how it is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretMaterialKind {
    None,
    PlaintextSecret,
    EncryptedSecret,
    SeedPhrase,
}

/// A normalized identity/wallet record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedIdentity {
    pub name: String,
    pub public_key: String,
    pub secret_material: SecretMaterialKind,
    /// Redacted representation for display; never contains raw secrets.
    pub secret_hint: Option<String>,
    pub network: Option<String>,
    pub format_version: u32,
    pub source: ConfigSource,
    pub source_path: Option<PathBuf>,
    pub fingerprint: String,
    pub created_at: Option<String>,
}

impl NormalizedIdentity {
    pub fn canonical_key(&self) -> String {
        self.name.to_ascii_lowercase()
    }

    pub fn has_secret(&self) -> bool {
        !matches!(self.secret_material, SecretMaterialKind::None)
    }

    pub fn compute_fingerprint(public_key: &str, network: &Option<String>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        if let Some(net) = network {
            hasher.update(net.as_bytes());
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

/// A normalized contract alias record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedContractAlias {
    pub alias: String,
    pub contract_id: String,
    pub network: String,
    pub wasm_hash: Option<String>,
    pub format_version: u32,
    pub source: ConfigSource,
    pub source_path: Option<PathBuf>,
    pub fingerprint: String,
}

impl NormalizedContractAlias {
    pub fn canonical_key(&self) -> String {
        format!(
            "{}:{}",
            self.network.to_ascii_lowercase(),
            self.alias.to_ascii_lowercase()
        )
    }

    pub fn compute_fingerprint(contract_id: &str, network: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(contract_id.as_bytes());
        hasher.update(network.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

/// Complete snapshot of a configuration store at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub schema_version: u32,
    pub source: ConfigSource,
    pub root_path: PathBuf,
    pub discovered_at: DateTime<Utc>,
    pub networks: BTreeMap<String, NormalizedNetwork>,
    pub identities: BTreeMap<String, NormalizedIdentity>,
    pub contract_aliases: BTreeMap<String, NormalizedContractAlias>,
    pub warnings: Vec<DiscoveryWarning>,
    pub aggregate_fingerprint: String,
}

impl ConfigSnapshot {
    pub fn empty(source: ConfigSource, root_path: PathBuf) -> Self {
        Self {
            schema_version: INTEROP_SCHEMA_VERSION,
            source,
            root_path,
            discovered_at: Utc::now(),
            networks: BTreeMap::new(),
            identities: BTreeMap::new(),
            contract_aliases: BTreeMap::new(),
            warnings: Vec::new(),
            aggregate_fingerprint: String::new(),
        }
    }

    pub fn finalize_fingerprint(&mut self) {
        let mut hasher = Sha256::new();
        for key in self.networks.keys() {
            hasher.update(key.as_bytes());
            hasher.update(self.networks[key].fingerprint.as_bytes());
        }
        for key in self.identities.keys() {
            hasher.update(key.as_bytes());
            hasher.update(self.identities[key].fingerprint.as_bytes());
        }
        for key in self.contract_aliases.keys() {
            hasher.update(key.as_bytes());
            hasher.update(self.contract_aliases[key].fingerprint.as_bytes());
        }
        self.aggregate_fingerprint = format!("sha256:{}", hex::encode(hasher.finalize()));
    }

    pub fn network_count(&self) -> usize {
        self.networks.len()
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    pub fn contract_alias_count(&self) -> usize {
        self.contract_aliases.len()
    }
}

/// Non-fatal issue discovered during read-only scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryWarning {
    pub code: String,
    pub message: String,
    pub path: Option<PathBuf>,
    pub severity: WarningSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    Info,
    Warning,
    Error,
}

/// A single diff entry comparing source and target snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEntry {
    pub kind: ConflictKind,
    pub category: DiffCategory,
    pub name: String,
    pub source_fingerprint: Option<String>,
    pub target_fingerprint: Option<String>,
    pub message: String,
    pub blocking: bool,
    pub requires_confirmation: bool,
    pub field_diffs: Vec<FieldDiff>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffCategory {
    Network,
    Identity,
    ContractAlias,
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    pub source_value: Option<String>,
    pub target_value: Option<String>,
}

/// Complete diff report between two configuration snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub source: ConfigSource,
    pub target: ConfigSource,
    pub direction: SyncDirection,
    pub precedence: PrecedencePolicy,
    pub dry_run: bool,
    pub entries: Vec<DiffEntry>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total: usize,
    pub equivalent: usize,
    pub missing_in_target: usize,
    pub missing_in_source: usize,
    pub mismatches: usize,
    pub blocking: usize,
    pub requires_confirmation: usize,
}

impl DiffReport {
    pub fn from_entries(
        source: ConfigSource,
        target: ConfigSource,
        direction: SyncDirection,
        precedence: PrecedencePolicy,
        dry_run: bool,
        entries: Vec<DiffEntry>,
    ) -> Self {
        let mut summary = DiffSummary {
            total: entries.len(),
            equivalent: 0,
            missing_in_target: 0,
            missing_in_source: 0,
            mismatches: 0,
            blocking: 0,
            requires_confirmation: 0,
        };
        for entry in &entries {
            match entry.kind {
                ConflictKind::Equivalent => summary.equivalent += 1,
                ConflictKind::MissingInTarget => summary.missing_in_target += 1,
                ConflictKind::MissingInSource => summary.missing_in_source += 1,
                ConflictKind::ValueMismatch
                | ConflictKind::NetworkMismatch
                | ConflictKind::IdentityMismatch
                | ConflictKind::ContractAliasMismatch
                | ConflictKind::DuplicateName
                | ConflictKind::UnsupportedFormat
                | ConflictKind::IrregularFile => summary.mismatches += 1,
                ConflictKind::InsecurePermissions | ConflictKind::EncryptedSecret => {
                    summary.mismatches += 1
                }
            }
            if entry.blocking {
                summary.blocking += 1;
            }
            if entry.requires_confirmation {
                summary.requires_confirmation += 1;
            }
        }
        Self {
            schema_version: INTEROP_SCHEMA_VERSION,
            generated_at: Utc::now(),
            source,
            target,
            direction,
            precedence,
            dry_run,
            entries,
            summary,
        }
    }

    pub fn has_blocking_conflicts(&self) -> bool {
        self.summary.blocking > 0
    }
}

/// Outcome of a single applied sync action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncActionResult {
    pub category: DiffCategory,
    pub name: String,
    pub action: SyncAction,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncAction {
    Created,
    Updated,
    Skipped,
    Rejected,
    NoOp,
}

/// Complete sync operation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub direction: SyncDirection,
    pub precedence: PrecedencePolicy,
    pub include_secrets: bool,
    pub dry_run: bool,
    pub actions: Vec<SyncActionResult>,
    pub diff: DiffReport,
    pub provenance: ProvenanceRecord,
}

/// Tracks last-synchronized fingerprints without modifying external files during reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub schema_version: u32,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub starforge_fingerprint: Option<String>,
    pub stellar_cli_fingerprint: Option<String>,
    pub last_direction: Option<SyncDirection>,
    pub sync_count: u64,
    pub history: Vec<ProvenanceEvent>,
}

impl Default for ProvenanceRecord {
    fn default() -> Self {
        Self {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            last_sync_at: None,
            starforge_fingerprint: None,
            stellar_cli_fingerprint: None,
            last_direction: None,
            sync_count: 0,
            history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEvent {
    pub at: DateTime<Utc>,
    pub direction: SyncDirection,
    pub starforge_fingerprint: String,
    pub stellar_cli_fingerprint: String,
    pub actions_applied: usize,
    pub dry_run: bool,
}

/// Options controlling discovery behavior.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub stellar_config_dir: Option<PathBuf>,
    pub include_legacy_soroban: bool,
    pub follow_symlinks: bool,
    pub max_file_bytes: u64,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            stellar_config_dir: None,
            include_legacy_soroban: true,
            follow_symlinks: false,
            max_file_bytes: 1024 * 1024,
        }
    }
}

/// Options controlling diff and sync behavior.
#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub direction: SyncDirection,
    pub precedence: PrecedencePolicy,
    pub dry_run: bool,
    pub include_secrets: bool,
    pub categories: BTreeSet<DiffCategory>,
    pub names: BTreeSet<String>,
    pub require_secure_permissions: bool,
    pub confirm_overwrites: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        let mut categories = BTreeSet::new();
        categories.insert(DiffCategory::Network);
        categories.insert(DiffCategory::Identity);
        categories.insert(DiffCategory::ContractAlias);
        Self {
            direction: SyncDirection::ImportToStarforge,
            precedence: PrecedencePolicy::default(),
            dry_run: true,
            include_secrets: false,
            categories,
            names: BTreeSet::new(),
            require_secure_permissions: true,
            confirm_overwrites: false,
        }
    }
}

/// Health check finding for `interop stellar doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorFinding {
    pub code: String,
    pub severity: DoctorSeverity,
    pub message: String,
    pub remediation: String,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSeverity {
    Ok,
    Info,
    Warning,
    Error,
}

/// Complete doctor report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub starforge_root: PathBuf,
    pub stellar_cli_root: PathBuf,
    pub findings: Vec<DoctorFinding>,
    pub overall: DoctorSeverity,
    pub starforge_snapshot: ConfigSnapshot,
    pub stellar_cli_snapshot: ConfigSnapshot,
    pub provenance: ProvenanceRecord,
}

impl DoctorReport {
    pub fn compute_overall(findings: &[DoctorFinding]) -> DoctorSeverity {
        findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(DoctorSeverity::Ok)
    }
}

/// Export bundle for automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropExportBundle {
    pub schema_version: u32,
    pub exported_at: DateTime<Utc>,
    pub source: ConfigSource,
    pub snapshot: ConfigSnapshot,
    pub provenance: ProvenanceRecord,
    pub redacted: bool,
}

/// Filter which records participate in an operation.
pub fn matches_name_filter(name: &str, filter: &BTreeSet<String>) -> bool {
    filter.is_empty() || filter.contains(&name.to_ascii_lowercase())
}

/// Filter which categories participate in an operation.
pub fn category_enabled(category: DiffCategory, enabled: &BTreeSet<DiffCategory>) -> bool {
    enabled.contains(&category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_fingerprint_is_deterministic() {
        let network = NormalizedNetwork {
            name: "testnet".into(),
            horizon_url: "https://horizon-testnet.stellar.org".into(),
            rpc_url: Some("https://soroban-testnet.stellar.org".into()),
            friendbot_url: Some("https://friendbot.stellar.org".into()),
            passphrase: Some("Test SDF Network ; September 2015".into()),
            format_version: STELLAR_NETWORK_FORMAT_V1,
            source: ConfigSource::StellarCli,
            source_path: None,
            fingerprint: String::new(),
        };
        let fp1 = network.compute_fingerprint();
        let fp2 = network.compute_fingerprint();
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
    }

    #[test]
    fn snapshot_aggregate_fingerprint_changes_with_content() {
        let mut snap = ConfigSnapshot::empty(ConfigSource::StarForge, PathBuf::from("/tmp/sf"));
        snap.finalize_fingerprint();
        let empty_fp = snap.aggregate_fingerprint.clone();

        snap.networks.insert(
            "testnet".into(),
            NormalizedNetwork {
                name: "testnet".into(),
                horizon_url: "https://horizon-testnet.stellar.org".into(),
                rpc_url: None,
                friendbot_url: None,
                passphrase: None,
                format_version: 1,
                source: ConfigSource::StarForge,
                source_path: None,
                fingerprint: "sha256:abc".into(),
            },
        );
        snap.finalize_fingerprint();
        assert_ne!(empty_fp, snap.aggregate_fingerprint);
    }

    #[test]
    fn diff_summary_counts_blocking_entries() {
        let entries = vec![
            DiffEntry {
                kind: ConflictKind::Equivalent,
                category: DiffCategory::Network,
                name: "testnet".into(),
                source_fingerprint: None,
                target_fingerprint: None,
                message: "ok".into(),
                blocking: false,
                requires_confirmation: false,
                field_diffs: vec![],
            },
            DiffEntry {
                kind: ConflictKind::IdentityMismatch,
                category: DiffCategory::Identity,
                name: "alice".into(),
                source_fingerprint: None,
                target_fingerprint: None,
                message: "mismatch".into(),
                blocking: true,
                requires_confirmation: true,
                field_diffs: vec![],
            },
        ];
        let report = DiffReport::from_entries(
            ConfigSource::StellarCli,
            ConfigSource::StarForge,
            SyncDirection::ImportToStarforge,
            PrecedencePolicy::FailOnConflict,
            true,
            entries,
        );
        assert_eq!(report.summary.total, 2);
        assert_eq!(report.summary.blocking, 1);
        assert!(report.has_blocking_conflicts());
    }

    #[test]
    fn conflict_kind_blocking_semantics() {
        assert!(!ConflictKind::Equivalent.is_blocking());
        assert!(ConflictKind::NetworkMismatch.is_blocking());
        assert!(ConflictKind::EncryptedSecret.requires_confirmation());
    }

    #[test]
    fn name_filter_empty_means_all() {
        let filter = BTreeSet::new();
        assert!(matches_name_filter("alice", &filter));
        assert!(matches_name_filter("bob", &filter));
    }

    #[test]
    fn name_filter_restricts() {
        let mut filter = BTreeSet::new();
        filter.insert("alice".into());
        assert!(matches_name_filter("alice", &filter));
        assert!(!matches_name_filter("bob", &filter));
    }
}
