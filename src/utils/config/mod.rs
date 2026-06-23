pub mod migrations;

use crate::utils::crypto;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Validates that a string is a well-formed Stellar Ed25519 public key.
///
/// A valid Stellar public key:
/// - Starts with 'G'
/// - Is exactly 56 characters long
/// - Contains only valid base32 characters (A-Z, 2-7)
///
/// Returns `Ok(())` if the key is valid, or an error with a descriptive message.
pub fn validate_public_key(key: &str) -> Result<()> {
    if !key.starts_with('G') {
        anyhow::bail!(
            "Invalid public key: must start with 'G'.\n  \
             A valid Stellar public key looks like: GABC...XYZ (56 characters, starting with G)."
        );
    }

    if key.len() != 56 {
        anyhow::bail!(
            "Invalid public key: expected 56 characters, got {}.\n  \
             A valid Stellar public key is exactly 56 characters long.",
            key.len()
        );
    }

    // Validate base32 character set (A-Z, 2-7)
    if let Some(bad_char) = key.chars().find(|c| !matches!(c, 'A'..='Z' | '2'..='7')) {
        anyhow::bail!(
            "Invalid public key: contains invalid character '{}'.\n  \
             A valid Stellar public key uses only uppercase letters A-Z and digits 2-7.",
            bad_char
        );
    }
    Ok(())
}

/// Validates a Soroban contract ID.
/// Must start with 'C', be exactly 56 chars long, and use valid base32 chars.
pub fn validate_contract_id(id: &str) -> Result<()> {
    if !id.starts_with('C') {
        anyhow::bail!("Invalid contract ID: must start with 'C'.");
    }
    if id.len() != 56 {
        anyhow::bail!(
            "Invalid contract ID: expected 56 characters, got {}.",
            id.len()
        );
    }
    if let Some(bad_char) = id.chars().find(|c| !matches!(c, 'A'..='Z' | '2'..='7')) {
        anyhow::bail!(
            "Invalid contract ID: contains invalid character '{}'.",
            bad_char
        );
    }
    Ok(())
}

/// Validates a file path exists and optionally matches an extension.
pub fn validate_file_path(path: &std::path::Path, expected_ext: Option<&str>) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }
    if !path.is_file() {
        anyhow::bail!("Path is not a file: {}", path.display());
    }
    if let Some(ext) = expected_ext {
        if path.extension().and_then(|e| e.to_str()) != Some(ext) {
            anyhow::bail!("Invalid file type: expected '{}' extension.", ext);
        }
    }
    Ok(())
}

/// Validates network setting.
pub fn validate_network(network: &str) -> Result<()> {
    match network {
        "testnet" | "mainnet" | "docker-testnet" => Ok(()),
        _ => {
            let cfg = load()?;
            if cfg.networks.contains_key(network) {
                Ok(())
            } else {
                anyhow::bail!(
                    "Unsupported network '{}'. Use 'testnet', 'mainnet', 'docker-testnet', or a configured custom network.",
                    network
                )
            }
        }
    }
}

/// Validates a Stellar secret key or encrypted bundle.
pub fn validate_secret_key(secret: &str) -> Result<()> {
    if secret.contains(':') {
        let parts: Vec<&str> = secret.split(':').collect();
        // Accept:
        // - 3-part (legacy: salt:nonce:ciphertext)
        // - 5-part (KDF without p_cost: salt:nonce:ciphertext:mem:iterations)
        // - 6-part (KDF with p_cost: salt:nonce:ciphertext:mem:iterations:parallelism)
        if parts.len() != 3 && parts.len() != 5 && parts.len() != 6 {
            anyhow::bail!(
                "Invalid encrypted secret bundle format: expected 3, 5, or 6 parts, got {}",
                parts.len()
            );
        }

        // Validate base64 parts (first 3 parts are always base64)
        for (i, part) in parts.iter().enumerate().take(3) {
            BASE64.decode(part).map_err(|_| {
                anyhow::anyhow!("Invalid base64 in encrypted secret bundle at part {}", i)
            })?;
        }

        // If 5 or 6-part bundle, validate KDF parameters are valid u32
        if parts.len() >= 5 {
            parts[3]
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("Invalid KDF memory cost: must be a valid u32"))?;
            parts[4]
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("Invalid KDF iteration count: must be a valid u32"))?;
        }
        if parts.len() == 6 {
            parts[5].parse::<u32>().map_err(|_| {
                anyhow::anyhow!("Invalid KDF parallelism factor: must be a valid u32")
            })?;
        }

        return Ok(());
    }

    if !secret.starts_with('S') {
        anyhow::bail!("Invalid secret key: must start with 'S'.");
    }
    if secret.len() != 56 {
        anyhow::bail!(
            "Invalid secret key: expected 56 characters, got {}.",
            secret.len()
        );
    }
    if let Some(bad_char) = secret.chars().find(|c| !matches!(c, 'A'..='Z' | '2'..='7')) {
        anyhow::bail!(
            "Invalid secret key: contains invalid character '{}'.",
            bad_char
        );
    }
    Ok(())
}

/// Validates that a network exists in the current configuration.
pub fn validate_network_exists(cfg: &Config, network: &str) -> Result<()> {
    if cfg.networks.contains_key(network) {
        return Ok(());
    }
    validate_network(network)
}

/// Validates an amount string parses to a positive f64.
pub fn validate_amount(amount: &str) -> Result<f64> {
    let amt: f64 = amount
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid amount format: '{}'", amount))?;
    if amt <= 0.0 {
        anyhow::bail!("Amount must be strictly positive, got {}", amt);
    }
    Ok(amt)
}

/// Validates a wallet name.
/// Must not be empty and must contain only alphanumeric chars, dashes, or underscores.
pub fn validate_wallet_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Wallet name cannot be empty.");
    }
    if let Some(bad_char) = name
        .chars()
        .find(|c| !c.is_alphanumeric() && *c != '-' && *c != '_')
    {
        anyhow::bail!("Invalid wallet name '{}': contains invalid character '{}'. Use alphanumeric, dash, or underscore.", name, bad_char);
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: String,
    pub network: String,
    pub wallets: Vec<WalletEntry>,
    #[serde(default)]
    pub networks: std::collections::HashMap<String, NetworkConfig>,
    #[serde(default)]
    pub plugin_trust: PluginTrustConfig,
    pub telemetry_enabled: Option<bool>,
    pub wallet_encryption: Option<crypto::KdfOptions>,
}

/// The current on-disk config schema version, as a string.
///
/// Bump this (and add a migration in [`migrations`]) whenever the [`Config`]
/// shape changes in a way that would otherwise silently drop or mis-read data.
pub fn default_version() -> String {
    CURRENT_CONFIG_VERSION.to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub horizon_url: String,
    pub soroban_rpc_url: Option<String>,
    pub friendbot_url: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PluginTrustConfig {
    /// Trusted plugin source allowlist entries. Entries may be domains
    /// (`plugins.example.com`) or URL prefixes (`https://plugins.example.com/releases/`).
    #[serde(default = "default_trusted_plugin_sources")]
    pub trusted_sources: Vec<String>,
}

impl Default for PluginTrustConfig {
    fn default() -> Self {
        Self {
            trusted_sources: default_trusted_plugin_sources(),
        }
    }
}

pub fn default_trusted_plugin_sources() -> Vec<String> {
    vec![
        "https://github.com/Nanle-code/starforge-*".to_string(),
        "https://github.com/StarForge-Labs/*".to_string(),
        "https://crates.io/crates/starforge-plugin-*".to_string(),
    ]
}

pub fn validate_plugin_trust_source(source: &str) -> Result<()> {
    let source = source.trim();
    if source.is_empty() {
        anyhow::bail!("Trusted plugin source cannot be empty");
    }
    if source.chars().any(char::is_whitespace) {
        anyhow::bail!("Trusted plugin source cannot contain whitespace");
    }

    let wildcard_count = source.matches('*').count();
    if wildcard_count > 1 || (wildcard_count == 1 && !source.ends_with('*')) {
        anyhow::bail!("Trusted plugin source may only use '*' as a trailing wildcard");
    }

    let without_wildcard = source.strip_suffix('*').unwrap_or(source);
    if without_wildcard.contains("://") {
        let scheme = without_wildcard
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(scheme.as_str(), "http" | "https" | "git+https") {
            anyhow::bail!("Trusted plugin source URL must use http, https, or git+https scheme");
        }
        let after_scheme = without_wildcard
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or("");
        let host = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit('@')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
            anyhow::bail!("Trusted plugin source URL must include a valid host");
        }
        return Ok(());
    }

    let domain = without_wildcard.trim_start_matches("*.");
    if domain.contains('/')
        || domain.contains(':')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        anyhow::bail!("Trusted plugin domain must be a domain name, not a path or URL fragment");
    }
    if domain.is_empty() || !domain.contains('.') {
        anyhow::bail!("Trusted plugin domain must include a dot, such as plugins.example.com");
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        anyhow::bail!("Trusted plugin domain contains invalid characters");
    }

    Ok(())
}

pub fn add_trusted_plugin_source(config: &mut Config, source: String) -> Result<bool> {
    validate_plugin_trust_source(&source)?;
    let source = source.trim().to_string();
    if config
        .plugin_trust
        .trusted_sources
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&source))
    {
        return Ok(false);
    }
    config.plugin_trust.trusted_sources.push(source);
    config
        .plugin_trust
        .trusted_sources
        .sort_by_key(|entry| entry.to_ascii_lowercase());
    Ok(true)
}

pub fn remove_trusted_plugin_source(config: &mut Config, source: &str) -> bool {
    let before = config.plugin_trust.trusted_sources.len();
    config
        .plugin_trust
        .trusted_sources
        .retain(|existing| !existing.eq_ignore_ascii_case(source.trim()));
    before != config.plugin_trust.trusted_sources.len()
}

pub fn reset_trusted_plugin_sources(config: &mut Config) {
    config.plugin_trust.trusted_sources = default_trusted_plugin_sources();
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletEntry {
    pub name: String,
    pub public_key: String,
    pub secret_key: Option<String>,
    pub network: String,
    pub created_at: String,
    pub funded: bool,
    #[serde(default)]
    pub rotation_history: Vec<WalletRotationRecord>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletRotationRecord {
    pub rotated_at: String,
    pub previous_public_key: String,
    pub previous_network: String,
    pub previous_funded: bool,
    /// The previous secret key (plaintext or encrypted bundle), preserved when
    /// `--backup` is passed to `wallet rotate`.  `None` when not requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_secret_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut networks = HashMap::new();
        networks.insert(
            "testnet".to_string(),
            NetworkConfig {
                horizon_url: "https://horizon-testnet.stellar.org".to_string(),
                soroban_rpc_url: Some("https://soroban-testnet.stellar.org".to_string()),
                friendbot_url: Some("https://friendbot.stellar.org".to_string()),
                passphrase: Some("Test SDF Network ; September 2015".to_string()),
            },
        );
        networks.insert(
            "mainnet".to_string(),
            NetworkConfig {
                horizon_url: "https://horizon.stellar.org".to_string(),
                soroban_rpc_url: Some("https://mainnet.sorobanrpc.com".to_string()),
                friendbot_url: None,
                passphrase: Some("Public Global Stellar Network ; September 2015".to_string()),
            },
        );
        networks.insert(
            "docker-testnet".to_string(),
            NetworkConfig {
                horizon_url: "http://localhost:8000".to_string(),
                soroban_rpc_url: Some("http://localhost:8000/rpc".to_string()),
                friendbot_url: None,
                passphrase: Some("Test SDF Network ; September 2015".to_string()),
            },
        );

        Self {
            version: CURRENT_CONFIG_VERSION.to_string(),
            network: "testnet".to_string(),
            wallets: vec![],
            networks,
            plugin_trust: PluginTrustConfig::default(),
            telemetry_enabled: Some(true),
            wallet_encryption: None,
        }
    }
}

/// Current config schema version, as a string (matches the serialized form).
pub const CURRENT_CONFIG_VERSION: &str = "2";

/// Numeric form of [`CURRENT_CONFIG_VERSION`], used by the migration engine.
pub const CURRENT_CONFIG_VERSION_NUM: u32 = 2;

/// Outcome of running migrations against a raw config value.
#[derive(Debug, Clone)]
pub struct MigrationOutcome {
    /// The config value after all migrations were applied.
    pub value: serde_json::Value,
    /// Ordered `(from, to)` version steps that were applied.
    pub steps: Vec<(u32, u32)>,
    /// Human-readable diff between the original and migrated values.
    pub changes: Vec<migrations::Change>,
}

impl MigrationOutcome {
    /// True when at least one migration step was applied.
    pub fn migrated(&self) -> bool {
        !self.steps.is_empty()
    }
}

/// Runs the migration pipeline on a raw [`serde_json::Value`] without touching
/// the file system. This is the pure core shared by `load()` and the
/// `config migrate --dry-run` command.
pub fn migrate_json_value(original: &serde_json::Value) -> Result<MigrationOutcome> {
    let mut value = original.clone();
    let steps = migrations::migrate_value(&mut value, CURRENT_CONFIG_VERSION_NUM)?;
    let changes = migrations::diff(original, &value);
    Ok(MigrationOutcome {
        value,
        steps,
        changes,
    })
}

/// Parses raw config file contents (TOML) into a [`serde_json::Value`].
fn parse_config_value(contents: &str) -> Result<serde_json::Value> {
    toml::from_str::<serde_json::Value>(contents)
        .with_context(|| "Failed to parse config file as structured data")
}

/// Legacy entry point retained for compatibility: migrates an already-parsed
/// [`Config`] by round-tripping it through the JSON migration pipeline.
///
/// Prefer [`load`], which performs version-aware migration directly from the raw
/// file before deserializing into [`Config`].
pub fn migrate_config(config: Config) -> Result<Config> {
    let value =
        serde_json::to_value(&config).with_context(|| "Failed to convert config for migration")?;
    let outcome = migrate_json_value(&value)?;
    serde_json::from_value(outcome.value).with_context(|| "Failed to deserialize migrated config")
}

/// Writes a `config.toml.bak` backup of the current on-disk config before a
/// migration overwrites it. A timestamped copy is also retained so multiple
/// migrations never clobber a single backup.
fn backup_config_file(contents: &str) -> Result<PathBuf> {
    let dir = config_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create config dir {:?}", dir))?;
    }

    let backup_path = dir.join("config.toml.bak");
    fs::write(&backup_path, contents)
        .with_context(|| format!("Failed to write backup to {:?}", backup_path))?;

    // Also keep a timestamped copy so successive migrations are recoverable.
    let timestamped = dir.join(format!(
        "config.toml.{}.bak",
        chrono::Utc::now().timestamp()
    ));
    let _ = fs::write(&timestamped, contents);

    Ok(backup_path)
}

/// Restores the most recent pre-migration backup over the live config file.
///
/// Prefers the canonical `config.toml.bak`; otherwise falls back to the newest
/// timestamped `config.toml.<ts>.bak` copy written by [`backup_config_file`].
#[allow(dead_code)]
pub fn rollback_config() -> Result<PathBuf> {
    let dir = config_dir();

    let canonical = dir.join("config.toml.bak");
    let backup_path = if canonical.exists() {
        canonical
    } else {
        let mut backups: Vec<_> = fs::read_dir(&dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("config.toml.") && name.ends_with(".bak")
            })
            .collect();

        if backups.is_empty() {
            anyhow::bail!("No config backup found to roll back to");
        }

        // Sort by file name (timestamped) — newest first.
        backups.sort_by_key(|b| std::cmp::Reverse(b.file_name()));
        backups[0].path()
    };

    fs::copy(&backup_path, config_path())
        .with_context(|| format!("Failed to restore backup from {:?}", backup_path))?;

    Ok(backup_path)
}

pub fn config_dir() -> PathBuf {
    let home = dirs::home_dir().expect("Could not find home directory");
    home.join(".starforge")
}

pub fn get_data_dir() -> Result<PathBuf> {
    let dir = config_dir().join("data");
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

pub fn get_config_path() -> Result<PathBuf> {
    Ok(config_path())
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {:?}", path))?;

    // Deserialize as a schema-agnostic value first, then migrate by version
    // *before* attempting to deserialize into the current `Config`. This is the
    // crux of the fix: a renamed/restructured field is reshaped here instead of
    // being silently dropped by `#[serde(default)]`.
    let raw = parse_config_value(&contents)?;
    let outcome = migrate_json_value(&raw)?;

    let mut config: Config = serde_json::from_value(outcome.value)
        .with_context(|| "Failed to deserialize config after migration")?;

    // Guarantee built-in networks are always present.
    ensure_default_networks(&mut config);

    // NOTE: `load()` migrates in memory only and never writes to disk. This keeps
    // reads side-effect free (so e.g. `config migrate --dry-run` and telemetry
    // hooks don't silently rewrite the file). Persisting a migration is explicit:
    // it happens on the next `save()` (which backs up the old file) or via
    // `starforge config migrate`.
    Ok(config)
}

/// Loads the raw config value and computes the migration plan without writing
/// anything to disk. Backs the `config migrate --dry-run` command.
///
/// Returns `Ok(None)` when no config file exists yet.
pub fn plan_migration() -> Result<Option<MigrationOutcome>> {
    let path = config_path();
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {:?}", path))?;
    let raw = parse_config_value(&contents)?;
    Ok(Some(migrate_json_value(&raw)?))
}

/// Applies pending migrations to the on-disk config, writing a
/// `config.toml.bak` backup beforehand. Returns the migration outcome.
///
/// This is the non-dry-run counterpart used by `config migrate`.
pub fn apply_migration() -> Result<Option<MigrationOutcome>> {
    let path = config_path();
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {:?}", path))?;
    let raw = parse_config_value(&contents)?;
    let outcome = migrate_json_value(&raw)?;

    if outcome.migrated() {
        let mut config: Config = serde_json::from_value(outcome.value.clone())
            .with_context(|| "Failed to deserialize config after migration")?;
        ensure_default_networks(&mut config);
        // `save()` writes `config.toml.bak` before overwriting the old version.
        save(&config)?;
    }

    Ok(Some(outcome))
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_public_key() {
        // Well-formed Stellar public key (56 chars, starts with G, valid base32)
        let key = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        assert!(validate_public_key(key).is_ok());
    }

    #[test]
    fn test_rejects_key_not_starting_with_g() {
        let key = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
        let err = validate_public_key(key).unwrap_err();
        assert!(err.to_string().contains("must start with 'G'"));
    }

    #[test]
    fn test_rejects_key_wrong_length() {
        let key = "GAAZI4TCR3TY5";
        let err = validate_public_key(key).unwrap_err();
        assert!(err.to_string().contains("expected 56 characters"));
    }

    #[test]
    fn test_rejects_key_invalid_characters() {
        // Lowercase letters are not valid base32
        let key = "Gaazi4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        let err = validate_public_key(key).unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_rejects_empty_key() {
        let err = validate_public_key("").unwrap_err();
        assert!(err.to_string().contains("must start with 'G'"));
    }

    #[test]
    fn test_valid_contract_id() {
        let id = "CAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNW";
        assert!(validate_contract_id(id).is_ok());
    }

    #[test]
    fn test_rejects_contract_id_not_starting_with_c() {
        // Starts with 'G'
        let id = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNW";
        let err = validate_contract_id(id).unwrap_err();
        assert!(err.to_string().contains("must start with 'C'"));
    }

    #[test]
    fn test_valid_amount() {
        assert_eq!(validate_amount("10.5").unwrap(), 10.5);
        assert_eq!(validate_amount("1").unwrap(), 1.0);
    }

    #[test]
    fn test_invalid_amount() {
        assert!(validate_amount("-5").is_err());
        assert!(validate_amount("0").is_err());
        assert!(validate_amount("abc").is_err());
    }

    #[test]
    fn test_valid_wallet_name() {
        assert!(validate_wallet_name("alice-123_DEPLOY").is_ok());
    }

    #[test]
    fn test_invalid_wallet_name() {
        assert!(validate_wallet_name("").is_err());
        assert!(validate_wallet_name("alice!").is_err());
        assert!(validate_wallet_name("my wallet").is_err());
    }

    #[test]
    fn test_valid_plain_secret_key() {
        let Ok(secret) = std::env::var("STARFORGE_TEST_SECRET_KEY") else {
            eprintln!("skipping test_valid_plain_secret_key: STARFORGE_TEST_SECRET_KEY is not set");
            return;
        };
        assert!(validate_secret_key(&secret).is_ok());
    }

    #[test]
    fn test_valid_encrypted_secret_bundle() {
        let salt = BASE64.encode([0u8; 16]);
        let nonce = BASE64.encode([1u8; 12]);
        let cipher = BASE64.encode([2u8; 32]);
        let bundle = format!("{}:{}:{}", salt, nonce, cipher);
        assert!(validate_secret_key(&bundle).is_ok());

        // 5-part
        let bundle_5 = format!("{}:{}:{}:32768:4", salt, nonce, cipher);
        assert!(validate_secret_key(&bundle_5).is_ok());

        // 6-part
        let bundle_6 = format!("{}:{}:{}:32768:4:2", salt, nonce, cipher);
        assert!(validate_secret_key(&bundle_6).is_ok());
    }

    #[test]
    fn test_invalid_secret_key() {
        assert!(validate_secret_key("not-a-key").is_err());
        assert!(validate_secret_key("S123").is_err());
        assert!(validate_secret_key("bad:bundle").is_err());
    }

    #[test]
    fn default_config_includes_plugin_trust_sources() {
        let cfg = Config::default();
        assert_eq!(
            cfg.plugin_trust.trusted_sources,
            default_trusted_plugin_sources()
        );
    }

    #[test]
    fn config_without_plugin_trust_deserializes_with_defaults() {
        let toml = r#"
version = "1"
network = "testnet"
wallets = []
telemetry_enabled = true
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.plugin_trust.trusted_sources,
            default_trusted_plugin_sources()
        );
    }

    #[test]
    fn trusted_plugin_source_management_deduplicates_and_resets() {
        let mut cfg = Config::default();
        assert!(add_trusted_plugin_source(&mut cfg, "plugins.example.com".to_string()).unwrap());
        assert!(!add_trusted_plugin_source(&mut cfg, "PLUGINS.EXAMPLE.COM".to_string()).unwrap());
        assert!(cfg
            .plugin_trust
            .trusted_sources
            .contains(&"plugins.example.com".to_string()));

        assert!(remove_trusted_plugin_source(
            &mut cfg,
            "plugins.example.com"
        ));
        assert!(!remove_trusted_plugin_source(
            &mut cfg,
            "plugins.example.com"
        ));

        cfg.plugin_trust.trusted_sources.clear();
        reset_trusted_plugin_sources(&mut cfg);
        assert_eq!(
            cfg.plugin_trust.trusted_sources,
            default_trusted_plugin_sources()
        );
    }

    #[test]
    fn invalid_trusted_plugin_sources_are_rejected() {
        for source in [
            "",
            "plugins example.com",
            "https://",
            "ftp://example.com",
            "example",
            "example.com/path",
            "https://example.com/*/bad",
        ] {
            assert!(
                validate_plugin_trust_source(source).is_err(),
                "{source} should be invalid"
            );
        }
    }
}

/// Returns the network passphrase for transaction signing.
/// Checks the config for a custom passphrase; falls back to well-known defaults.
pub fn get_network_passphrase(network: &str) -> String {
    if let Ok(cfg) = load() {
        if let Some(net_cfg) = cfg.networks.get(network) {
            if let Some(passphrase) = &net_cfg.passphrase {
                return passphrase.clone();
            }
        }
    }
    match network {
        "mainnet" => "Public Global Stellar Network ; September 2015".to_string(),
        _ => "Test SDF Network ; September 2015".to_string(),
    }
}

/// Ensures the three built-in networks are present in the config's network map.
/// Safe to call on any Config — existing entries are never overwritten.
pub fn ensure_default_networks(cfg: &mut Config) {
    cfg.networks
        .entry("testnet".to_string())
        .or_insert_with(|| NetworkConfig {
            horizon_url: "https://horizon-testnet.stellar.org".to_string(),
            soroban_rpc_url: Some("https://soroban-testnet.stellar.org".to_string()),
            friendbot_url: Some("https://friendbot.stellar.org".to_string()),
            passphrase: Some("Test SDF Network ; September 2015".to_string()),
        });
    cfg.networks
        .entry("mainnet".to_string())
        .or_insert_with(|| NetworkConfig {
            horizon_url: "https://horizon.stellar.org".to_string(),
            soroban_rpc_url: Some("https://mainnet.sorobanrpc.com".to_string()),
            friendbot_url: None,
            passphrase: Some("Public Global Stellar Network ; September 2015".to_string()),
        });
    cfg.networks
        .entry("docker-testnet".to_string())
        .or_insert_with(|| NetworkConfig {
            horizon_url: "http://localhost:8000".to_string(),
            soroban_rpc_url: Some("http://localhost:8000/rpc".to_string()),
            friendbot_url: None,
            passphrase: Some("Test SDF Network ; September 2015".to_string()),
        });
}

pub fn save(config: &Config) -> Result<()> {
    let dir = config_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create config dir {:?}", dir))?;
    }

    // If an on-disk config exists with a *different* schema version than the one
    // we're about to write, back it up first. This is the "backup before every
    // migration" guarantee: the original file is preserved as `config.toml.bak`
    // the moment a version bump is persisted over it.
    let path = config_path();
    if let Ok(existing) = fs::read_to_string(&path) {
        let existing_version = parse_config_value(&existing)
            .map(|v| migrations::read_version(&v).to_string())
            .unwrap_or_default();
        if existing_version != config.version {
            backup_config_file(&existing)?;
        }
    }

    let contents = toml::to_string_pretty(config).with_context(|| "Failed to serialize config")?;
    fs::write(&path, contents).with_context(|| "Failed to write config file")?;
    Ok(())
}

pub fn get_network_config(cfg: &Config, network: &str) -> Result<NetworkConfig> {
    cfg.networks
        .get(network)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Network '{}' not found in configuration", network))
}

pub const RESERVED_NETWORKS: &[&str] = &["testnet", "mainnet", "docker-testnet"];

/// Returns true for built-in networks that cannot be removed or renamed.
pub fn is_reserved_network(name: &str) -> bool {
    RESERVED_NETWORKS.contains(&name)
}

pub fn add_custom_network(
    config: &mut Config,
    name: String,
    horizon_url: String,
    soroban_rpc_url: Option<String>,
    friendbot_url: Option<String>,
    passphrase: Option<String>,
) -> Result<()> {
    if is_reserved_network(&name) {
        anyhow::bail!(
            "'{}' is a reserved network name ('testnet', 'mainnet', 'docker-testnet'). Choose a different name.",
            name
        );
    }
    if config.networks.contains_key(&name) {
        anyhow::bail!("Network '{}' already exists", name);
    }
    config.networks.insert(
        name,
        NetworkConfig {
            horizon_url,
            soroban_rpc_url,
            friendbot_url,
            passphrase,
        },
    );
    Ok(())
}

/// Remove a custom network from config. Built-in networks are protected.
pub fn remove_custom_network(config: &mut Config, name: &str) -> Result<()> {
    if is_reserved_network(name) {
        anyhow::bail!(
            "'{}' is a built-in network and cannot be removed. Only custom networks can be removed.",
            name
        );
    }
    if !config.networks.contains_key(name) {
        anyhow::bail!("Network '{}' not found", name);
    }
    // Only remove if it is not a built-in re-injected entry (custom keys are user-added).
    config.networks.remove(name);

    if config.network == name {
        config.network = "testnet".to_string();
    }

    for wallet in &mut config.wallets {
        if wallet.network == name {
            wallet.network = config.network.clone();
        }
    }

    Ok(())
}

/// Rename a custom network. Built-in networks cannot be renamed.
pub fn rename_custom_network(config: &mut Config, old_name: &str, new_name: &str) -> Result<()> {
    if is_reserved_network(old_name) {
        anyhow::bail!(
            "'{}' is a built-in network and cannot be renamed.",
            old_name
        );
    }
    if is_reserved_network(new_name) {
        anyhow::bail!(
            "'{}' is a reserved network name. Choose a different name.",
            new_name
        );
    }
    if !config.networks.contains_key(old_name) {
        anyhow::bail!("Network '{}' not found", old_name);
    }
    if config.networks.contains_key(new_name) {
        anyhow::bail!("Network '{}' already exists", new_name);
    }
    if old_name == new_name {
        anyhow::bail!("Old and new network names are the same");
    }

    let net_cfg = config.networks.remove(old_name).expect("network exists");
    config.networks.insert(new_name.to_string(), net_cfg);

    if config.network == old_name {
        config.network = new_name.to_string();
    }

    for wallet in &mut config.wallets {
        if wallet.network == old_name {
            wallet.network = new_name.to_string();
        }
    }

    Ok(())
}
