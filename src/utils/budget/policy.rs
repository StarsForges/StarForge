//! Versioned budget policy documents: global/network/command/contract/function
//! limit overrides, resolved by [`BudgetPolicy::resolve`] into a single
//! effective [`LimitSet`] for a given invocation scope.
//!
//! Overrides are layered narrowest-wins: `global` is the base, then
//! `networks[<network>]`, then `commands[<command>]`, then
//! `contracts[<contract>]`, then `functions[<key>]` — each layer only
//! replaces the specific fields it sets (`Some(_)`), so a network override
//! that only tightens the classic fee limit doesn't erase a global memory
//! limit. `functions` keys are `"<contract>::<function>"` when a contract is
//! known, or bare `"<function>"` otherwise, so the same function name on two
//! different contracts can carry independent limits.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const BUDGET_POLICY_SCHEMA_VERSION: u8 = 1;

/// Default warning threshold: a metric at or above this percentage of its
/// limit — but not yet over it — is reported as a warning rather than a
/// silent pass.
pub const DEFAULT_WARNING_THRESHOLD_PERCENT: f64 = 80.0;

/// A set of optional per-metric ceilings. `None` means "no limit configured
/// at this layer" (not "limit is zero") so layering can distinguish "not
/// set" from "explicitly unlimited" is out of scope here — omission is the
/// only way to leave a metric unconstrained, matching how the rest of
/// StarForge's config layers behave (see `utils::config`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LimitSet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_classic_fee_stroops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_resource_fee_stroops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_insns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mem_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_read_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_write_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_read_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_write_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_event_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tx_size_bytes: Option<u64>,
    /// Overrides [`DEFAULT_WARNING_THRESHOLD_PERCENT`] for checks resolved
    /// through this layer, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning_threshold_percent: Option<f64>,
}

impl LimitSet {
    /// Returns the configured limit for `kind`, in the same widened `u64`
    /// representation [`super::metrics::BudgetMetrics::value_of`] uses.
    pub fn limit_of(&self, kind: super::metrics::MetricKind) -> Option<u64> {
        use super::metrics::MetricKind;
        match kind {
            MetricKind::ClassicFeeStroops => self.max_classic_fee_stroops,
            MetricKind::ResourceFeeStroops => self.max_resource_fee_stroops,
            MetricKind::CpuInsns => self.max_cpu_insns,
            MetricKind::MemBytes => self.max_mem_bytes,
            MetricKind::ReadEntries => self.max_read_entries.map(u64::from),
            MetricKind::WriteEntries => self.max_write_entries.map(u64::from),
            MetricKind::ReadBytes => self.max_read_bytes,
            MetricKind::WriteBytes => self.max_write_bytes,
            MetricKind::EventBytes => self.max_event_bytes,
            MetricKind::TxSizeBytes => self.max_tx_size_bytes,
        }
    }

    /// Overlays `other` on top of `self`: any field `other` sets replaces the
    /// corresponding field in the result; unset fields fall through.
    fn overlay(&self, other: &LimitSet) -> LimitSet {
        LimitSet {
            max_classic_fee_stroops: other
                .max_classic_fee_stroops
                .or(self.max_classic_fee_stroops),
            max_resource_fee_stroops: other
                .max_resource_fee_stroops
                .or(self.max_resource_fee_stroops),
            max_cpu_insns: other.max_cpu_insns.or(self.max_cpu_insns),
            max_mem_bytes: other.max_mem_bytes.or(self.max_mem_bytes),
            max_read_entries: other.max_read_entries.or(self.max_read_entries),
            max_write_entries: other.max_write_entries.or(self.max_write_entries),
            max_read_bytes: other.max_read_bytes.or(self.max_read_bytes),
            max_write_bytes: other.max_write_bytes.or(self.max_write_bytes),
            max_event_bytes: other.max_event_bytes.or(self.max_event_bytes),
            max_tx_size_bytes: other.max_tx_size_bytes.or(self.max_tx_size_bytes),
            warning_threshold_percent: other
                .warning_threshold_percent
                .or(self.warning_threshold_percent),
        }
    }

    fn is_empty(&self) -> bool {
        *self == LimitSet::default()
    }
}

/// A versioned, on-disk budget policy: a global baseline plus scoped
/// overrides. See the module docs for the resolution order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicyDocument {
    pub schema_version: u8,
    /// Free-text identifier for audit trails/CI logs (e.g. repo or team name).
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub global: LimitSet,
    #[serde(default)]
    pub networks: BTreeMap<String, LimitSet>,
    #[serde(default)]
    pub commands: BTreeMap<String, LimitSet>,
    #[serde(default)]
    pub contracts: BTreeMap<String, LimitSet>,
    #[serde(default)]
    pub functions: BTreeMap<String, LimitSet>,
}

/// The scope an enforcement check is resolved for. `contract`/`function` are
/// optional because classic (non-Soroban) payment paths have neither.
#[derive(Debug, Clone, Default)]
pub struct Scope<'a> {
    pub command: &'a str,
    pub network: &'a str,
    pub contract: Option<&'a str>,
    pub function: Option<&'a str>,
}

impl<'a> Scope<'a> {
    pub fn new(command: &'a str, network: &'a str) -> Self {
        Self {
            command,
            network,
            contract: None,
            function: None,
        }
    }

    pub fn with_contract(mut self, contract: Option<&'a str>) -> Self {
        self.contract = contract;
        self
    }

    pub fn with_function(mut self, function: Option<&'a str>) -> Self {
        self.function = function;
        self
    }

    fn function_key(&self) -> Option<String> {
        self.function.map(|f| match self.contract {
            Some(c) => format!("{}::{}", c, f),
            None => f.to_string(),
        })
    }
}

/// A fully resolved limit set for one [`Scope`], along with which layers
/// actually contributed a value — used by `starforge budget explain` to show
/// *why* an effective limit is what it is.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub limits: LimitSet,
    pub warning_threshold_percent: f64,
    /// Layer names (in application order) that had at least one field set,
    /// e.g. `["global", "network:mainnet", "command:invoke"]`.
    pub contributing_layers: Vec<String>,
}

impl BudgetPolicyDocument {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema_version: BUDGET_POLICY_SCHEMA_VERSION,
            name: name.into(),
            global: LimitSet::default(),
            networks: BTreeMap::new(),
            commands: BTreeMap::new(),
            contracts: BTreeMap::new(),
            functions: BTreeMap::new(),
        }
    }

    /// A conservative starting policy for `starforge budget init`: generous
    /// enough not to block routine testnet development, but present on every
    /// metric so regressions are visible from the first run.
    pub fn default_policy() -> Self {
        let mut doc = Self::new("default");
        doc.global = LimitSet {
            max_classic_fee_stroops: Some(1_000_000),
            max_resource_fee_stroops: Some(5_000_000),
            max_cpu_insns: Some(100_000_000),
            max_mem_bytes: Some(41_943_040), // 40 MiB
            max_read_entries: Some(200),
            max_write_entries: Some(100),
            max_read_bytes: Some(2_097_152),  // 2 MiB
            max_write_bytes: Some(1_048_576), // 1 MiB
            max_event_bytes: Some(262_144),   // 256 KiB
            max_tx_size_bytes: Some(102_400), // 100 KiB, Stellar's tx envelope ceiling
            warning_threshold_percent: Some(DEFAULT_WARNING_THRESHOLD_PERCENT),
        };
        doc.networks.insert(
            "mainnet".to_string(),
            LimitSet {
                max_classic_fee_stroops: Some(300_000),
                max_resource_fee_stroops: Some(2_000_000),
                ..LimitSet::default()
            },
        );
        doc
    }

    pub fn resolve(&self, scope: &Scope) -> ResolvedPolicy {
        let mut limits = self.global.clone();
        let mut layers = Vec::new();
        if !self.global.is_empty() {
            layers.push("global".to_string());
        }

        if let Some(network_limits) = self.networks.get(scope.network) {
            if !network_limits.is_empty() {
                limits = limits.overlay(network_limits);
                layers.push(format!("network:{}", scope.network));
            }
        }
        if let Some(command_limits) = self.commands.get(scope.command) {
            if !command_limits.is_empty() {
                limits = limits.overlay(command_limits);
                layers.push(format!("command:{}", scope.command));
            }
        }
        if let Some(contract) = scope.contract {
            if let Some(contract_limits) = self.contracts.get(contract) {
                if !contract_limits.is_empty() {
                    limits = limits.overlay(contract_limits);
                    layers.push(format!("contract:{}", contract));
                }
            }
        }
        if let Some(function_key) = scope.function_key() {
            if let Some(function_limits) = self.functions.get(&function_key) {
                if !function_limits.is_empty() {
                    limits = limits.overlay(function_limits);
                    layers.push(format!("function:{}", function_key));
                }
            }
        }

        let warning_threshold_percent = limits
            .warning_threshold_percent
            .unwrap_or(DEFAULT_WARNING_THRESHOLD_PERCENT);

        ResolvedPolicy {
            limits,
            warning_threshold_percent,
            contributing_layers: layers,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version == 0 {
            anyhow::bail!("Budget policy schema_version must be >= 1");
        }
        if self.schema_version > BUDGET_POLICY_SCHEMA_VERSION {
            anyhow::bail!(
                "Budget policy schema_version {} is newer than this build supports (max {}). \
                 Upgrade starforge or downgrade the policy file.",
                self.schema_version,
                BUDGET_POLICY_SCHEMA_VERSION
            );
        }
        let all_sets = std::iter::once(&self.global)
            .chain(self.networks.values())
            .chain(self.commands.values())
            .chain(self.contracts.values())
            .chain(self.functions.values());
        for set in all_sets {
            if let Some(pct) = set.warning_threshold_percent {
                if !(0.0..=100.0).contains(&pct) {
                    anyhow::bail!(
                        "warning_threshold_percent must be between 0 and 100, got {}",
                        pct
                    );
                }
            }
        }
        Ok(())
    }
}

/// Reads a policy document from `path`, migrating forward if an older
/// (but still supported) `schema_version` is found on disk. Currently there
/// is only one schema version, so this is a straight parse + validate, but
/// the shape mirrors `utils::config::migrations` so a v2 can be introduced
/// the same way: bump [`BUDGET_POLICY_SCHEMA_VERSION`], add a migration
/// function operating on the raw `serde_json::Value`, and re-run this loader.
pub fn load_policy(path: &Path) -> Result<BudgetPolicyDocument> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read budget policy at {}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse budget policy {} as JSON", path.display()))?;

    let on_disk_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1) as u8;
    if on_disk_version < BUDGET_POLICY_SCHEMA_VERSION {
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "schema_version".to_string(),
                serde_json::json!(BUDGET_POLICY_SCHEMA_VERSION),
            );
        }
    }

    let doc: BudgetPolicyDocument = serde_json::from_value(value)
        .with_context(|| format!("Failed to deserialize budget policy {}", path.display()))?;
    doc.validate()?;
    Ok(doc)
}

/// Loads the policy at `path` if it exists, or `None` if no policy has been
/// initialized yet (the common case for a fresh checkout — budgets are
/// opt-in via `starforge budget init`, not an implicit default limit).
pub fn load_policy_if_present(path: &Path) -> Result<Option<BudgetPolicyDocument>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(load_policy(path)?))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn save_policy(path: &Path, doc: &BudgetPolicyDocument) -> Result<()> {
    doc.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(doc).context("Failed to serialize budget policy")?;
    fs::write(path, json)
        .with_context(|| format!("Failed to write budget policy to {}", path.display()))?;
    restrict_permissions(path)?;
    Ok(())
}

/// Default on-disk location for the budget policy: `<data_dir>/budget/policy.json`.
pub fn default_policy_path() -> Result<PathBuf> {
    Ok(crate::utils::config::get_data_dir()?
        .join("budget")
        .join("policy.json"))
}

/// Resolves the effective policy path: `STARFORGE_BUDGET_POLICY` env var when
/// set (used by CI to point at a repo-checked-in policy file without relying
/// on `$HOME`), otherwise [`default_policy_path`].
pub fn resolve_policy_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Ok(env_path) = std::env::var("STARFORGE_BUDGET_POLICY") {
        if !env_path.trim().is_empty() {
            return Ok(PathBuf::from(env_path));
        }
    }
    default_policy_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::budget::metrics::MetricKind;
    use tempfile::tempdir;

    #[test]
    fn resolve_falls_back_through_layers() {
        let mut doc = BudgetPolicyDocument::new("test");
        doc.global.max_cpu_insns = Some(1_000);
        doc.global.max_mem_bytes = Some(500);
        doc.networks.insert(
            "mainnet".to_string(),
            LimitSet {
                max_cpu_insns: Some(200),
                ..Default::default()
            },
        );

        let scope = Scope::new("invoke", "mainnet");
        let resolved = doc.resolve(&scope);
        assert_eq!(resolved.limits.limit_of(MetricKind::CpuInsns), Some(200));
        assert_eq!(resolved.limits.limit_of(MetricKind::MemBytes), Some(500));
        assert!(resolved
            .contributing_layers
            .contains(&"network:mainnet".to_string()));
    }

    #[test]
    fn narrower_layers_win_over_broader_ones() {
        let mut doc = BudgetPolicyDocument::new("test");
        doc.global.max_cpu_insns = Some(1_000);
        doc.commands.insert(
            "invoke".to_string(),
            LimitSet {
                max_cpu_insns: Some(500),
                ..Default::default()
            },
        );
        doc.contracts.insert(
            "CABC".to_string(),
            LimitSet {
                max_cpu_insns: Some(250),
                ..Default::default()
            },
        );
        doc.functions.insert(
            "CABC::transfer".to_string(),
            LimitSet {
                max_cpu_insns: Some(100),
                ..Default::default()
            },
        );

        let scope = Scope::new("invoke", "testnet")
            .with_contract(Some("CABC"))
            .with_function(Some("transfer"));
        let resolved = doc.resolve(&scope);
        assert_eq!(resolved.limits.limit_of(MetricKind::CpuInsns), Some(100));
    }

    #[test]
    fn function_key_is_namespaced_by_contract() {
        let mut doc = BudgetPolicyDocument::new("test");
        doc.functions.insert(
            "transfer".to_string(),
            LimitSet {
                max_cpu_insns: Some(999),
                ..Default::default()
            },
        );
        doc.functions.insert(
            "CABC::transfer".to_string(),
            LimitSet {
                max_cpu_insns: Some(111),
                ..Default::default()
            },
        );

        let scoped = Scope::new("invoke", "testnet")
            .with_contract(Some("CABC"))
            .with_function(Some("transfer"));
        assert_eq!(
            doc.resolve(&scoped).limits.limit_of(MetricKind::CpuInsns),
            Some(111)
        );

        let unscoped = Scope::new("invoke", "testnet").with_function(Some("transfer"));
        assert_eq!(
            doc.resolve(&unscoped).limits.limit_of(MetricKind::CpuInsns),
            Some(999)
        );
    }

    #[test]
    fn empty_layers_do_not_appear_in_contributing_layers() {
        let doc = BudgetPolicyDocument::new("test");
        let scope = Scope::new("deploy", "testnet");
        let resolved = doc.resolve(&scope);
        assert!(resolved.contributing_layers.is_empty());
        assert_eq!(resolved.limits.limit_of(MetricKind::CpuInsns), None);
    }

    #[test]
    fn warning_threshold_falls_back_to_default() {
        let doc = BudgetPolicyDocument::new("test");
        let resolved = doc.resolve(&Scope::new("deploy", "testnet"));
        assert_eq!(
            resolved.warning_threshold_percent,
            DEFAULT_WARNING_THRESHOLD_PERCENT
        );
    }

    #[test]
    fn validate_rejects_out_of_range_warning_threshold() {
        let mut doc = BudgetPolicyDocument::new("test");
        doc.global.warning_threshold_percent = Some(150.0);
        assert!(doc.validate().is_err());
    }

    #[test]
    fn validate_rejects_future_schema_version() {
        let mut doc = BudgetPolicyDocument::new("test");
        doc.schema_version = BUDGET_POLICY_SCHEMA_VERSION + 1;
        assert!(doc.validate().is_err());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let doc = BudgetPolicyDocument::default_policy();
        save_policy(&path, &doc).unwrap();
        let loaded = load_policy(&path).unwrap();
        assert_eq!(loaded.schema_version, doc.schema_version);
        assert_eq!(loaded.global.max_cpu_insns, Some(100_000_000));
    }

    #[cfg(unix)]
    #[test]
    fn saved_policy_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.json");
        save_policy(&path, &BudgetPolicyDocument::default_policy()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_policy_if_present_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        assert!(load_policy_if_present(&path).unwrap().is_none());
    }

    #[test]
    fn resolve_policy_path_prefers_explicit_over_env() {
        let explicit = PathBuf::from("/tmp/explicit-policy.json");
        let resolved = resolve_policy_path(Some(&explicit)).unwrap();
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn older_on_disk_schema_version_is_upgraded_in_memory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.json");
        fs::write(
            &path,
            serde_json::json!({
                "schema_version": 1,
                "name": "legacy",
                "global": {},
                "networks": {},
                "commands": {},
                "contracts": {},
                "functions": {}
            })
            .to_string(),
        )
        .unwrap();
        let doc = load_policy(&path).unwrap();
        assert_eq!(doc.schema_version, BUDGET_POLICY_SCHEMA_VERSION);
    }
}
