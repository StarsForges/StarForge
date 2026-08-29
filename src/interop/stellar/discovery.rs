//! Discover StarForge and Stellar CLI configuration stores (read-only).

use crate::interop::domain::*;
use crate::interop::stellar::parser::StellarConfigParser;
use crate::interop::stellar::permissions::PermissionValidator;
use crate::utils::config;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn starforge_root() -> PathBuf {
    config::config_dir()
}

pub fn resolve_stellar_config_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir.to_path_buf());
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg).join("stellar");
        if path.exists() {
            return Ok(path);
        }
    }
    let home = dirs::home_dir().context("could not resolve home directory")?;
    Ok(home.join(".config").join("stellar"))
}

pub fn legacy_soroban_config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/"))
        .join(".config")
        .join("soroban")
}

pub fn discover_starforge() -> Result<ConfigSnapshot> {
    let root = starforge_root();
    let mut snapshot = ConfigSnapshot::empty(ConfigSource::StarForge, root.clone());

    let cfg = config::load().unwrap_or_default();

    for (name, net) in &cfg.networks {
        let normalized = NormalizedNetwork {
            name: name.clone(),
            horizon_url: net.horizon_url.clone(),
            rpc_url: net.soroban_rpc_url.clone(),
            friendbot_url: net.friendbot_url.clone(),
            passphrase: net.passphrase.clone(),
            format_version: STELLAR_NETWORK_FORMAT_V1,
            source: ConfigSource::StarForge,
            source_path: Some(config::config_path()),
            fingerprint: String::new(),
        };
        let mut n = normalized;
        n.fingerprint = n.compute_fingerprint();
        snapshot.networks.insert(n.canonical_key(), n);
    }

    for wallet in &cfg.wallets {
        let secret_material = if wallet.secret_key.is_some() {
            if wallet
                .secret_key
                .as_ref()
                .map(|s| s.contains(':'))
                .unwrap_or(false)
            {
                SecretMaterialKind::EncryptedSecret
            } else {
                SecretMaterialKind::PlaintextSecret
            }
        } else {
            SecretMaterialKind::None
        };
        let secret_hint = wallet
            .secret_key
            .as_ref()
            .map(|s| crate::interop::stellar::redact::redact_secret_hint(s));
        let fingerprint = NormalizedIdentity::compute_fingerprint(
            &wallet.public_key,
            &Some(wallet.network.clone()),
        );
        let identity = NormalizedIdentity {
            name: wallet.name.clone(),
            public_key: wallet.public_key.clone(),
            secret_material,
            secret_hint,
            network: Some(wallet.network.clone()),
            format_version: STELLAR_IDENTITY_FORMAT_V1,
            source: ConfigSource::StarForge,
            source_path: Some(config::config_path()),
            fingerprint,
            created_at: Some(wallet.created_at.clone()),
        };
        insert_identity(&mut snapshot, identity)?;
    }

    scan_starforge_contract_aliases(&root, &mut snapshot)?;
    snapshot.finalize_fingerprint();
    Ok(snapshot)
}

fn scan_starforge_contract_aliases(root: &Path, snapshot: &mut ConfigSnapshot) -> Result<()> {
    let aliases_dir = root.join("contract-aliases");
    if !aliases_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&aliases_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let alias = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let contents = fs::read_to_string(&path)?;
        let network = snapshot
            .networks
            .values()
            .next()
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "testnet".into());
        match StellarConfigParser::parse_contract_alias_file(
            &alias,
            &network,
            &path,
            &contents,
            ConfigSource::StarForge,
        ) {
            Ok(record) => {
                snapshot
                    .contract_aliases
                    .insert(record.canonical_key(), record);
            }
            Err(e) => snapshot.warnings.push(DiscoveryWarning {
                code: "contract_alias.parse_failed".into(),
                message: e.to_string(),
                path: Some(path),
                severity: WarningSeverity::Warning,
            }),
        }
    }
    Ok(())
}

fn insert_identity(snapshot: &mut ConfigSnapshot, identity: NormalizedIdentity) -> Result<()> {
    let key = identity.canonical_key();
    if snapshot.identities.contains_key(&key) {
        snapshot.warnings.push(DiscoveryWarning {
            code: "identity.duplicate".into(),
            message: format!("duplicate identity name '{}'", identity.name),
            path: identity.source_path.clone(),
            severity: WarningSeverity::Error,
        });
    }
    snapshot.identities.insert(key, identity);
    Ok(())
}

pub fn discover_stellar_cli(options: &DiscoveryOptions) -> Result<ConfigSnapshot> {
    let root = resolve_stellar_config_dir(options.stellar_config_dir.as_deref())?;
    let mut snapshot = ConfigSnapshot::empty(ConfigSource::StellarCli, root.clone());

    if root.exists() {
        scan_stellar_root(&root, ConfigSource::StellarCli, options, &mut snapshot)?;
    } else {
        snapshot.warnings.push(DiscoveryWarning {
            code: "stellar_cli.not_found".into(),
            message: format!(
                "Stellar CLI config directory not found at {}; run `stellar keys generate` or set --stellar-config-dir",
                root.display()
            ),
            path: Some(root.clone()),
            severity: WarningSeverity::Info,
        });
    }

    if options.include_legacy_soroban {
        let legacy = legacy_soroban_config_dir();
        if legacy.exists() && legacy != root {
            scan_stellar_root(
                &legacy,
                ConfigSource::LegacySorobanCli,
                options,
                &mut snapshot,
            )?;
        }
    }

    snapshot.finalize_fingerprint();
    Ok(snapshot)
}

fn scan_stellar_root(
    root: &Path,
    source: ConfigSource,
    options: &DiscoveryOptions,
    snapshot: &mut ConfigSnapshot,
) -> Result<()> {
    if let Err(e) = PermissionValidator::check_directory(root) {
        snapshot.warnings.push(DiscoveryWarning {
            code: "directory.insecure_permissions".into(),
            message: e.to_string(),
            path: Some(root.to_path_buf()),
            severity: WarningSeverity::Warning,
        });
    }

    scan_networks_dir(&root.join("network"), root, source, options, snapshot)?;
    scan_identities_dir(&root.join("identities"), root, source, options, snapshot)?;
    scan_legacy_identity_dir(&root.join("identity"), root, source, options, snapshot)?;
    scan_contract_aliases(&root.join("contract-ids"), source, options, snapshot)?;
    Ok(())
}

fn scan_networks_dir(
    dir: &Path,
    _root: &Path,
    source: ConfigSource,
    options: &DiscoveryOptions,
    snapshot: &mut ConfigSnapshot,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() && !options.follow_symlinks {
            snapshot.warnings.push(DiscoveryWarning {
                code: "network.symlink_skipped".into(),
                message: format!("skipping symlink {}", path.display()),
                path: Some(path),
                severity: WarningSeverity::Info,
            });
            continue;
        }
        if !path.is_file() {
            if path.is_symlink() {
                snapshot.warnings.push(DiscoveryWarning {
                    code: "network.irregular_file".into(),
                    message: format!("irregular network entry {}", path.display()),
                    path: Some(path),
                    severity: WarningSeverity::Warning,
                });
            }
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        if file_too_large(&path, options.max_file_bytes) {
            snapshot.warnings.push(DiscoveryWarning {
                code: "network.file_too_large".into(),
                message: format!("network file exceeds {} bytes", options.max_file_bytes),
                path: Some(path),
                severity: WarningSeverity::Error,
            });
            continue;
        }
        let contents = fs::read_to_string(&path)?;
        match StellarConfigParser::parse_network_file(&name, &path, &contents, source) {
            Ok(network) => {
                let key = network.canonical_key();
                if snapshot.networks.contains_key(&key) {
                    snapshot.warnings.push(DiscoveryWarning {
                        code: "network.duplicate".into(),
                        message: format!("duplicate network name '{}'", name),
                        path: Some(path),
                        severity: WarningSeverity::Error,
                    });
                }
                snapshot.networks.insert(key, network);
            }
            Err(e) => snapshot.warnings.push(DiscoveryWarning {
                code: "network.parse_failed".into(),
                message: e.to_string(),
                path: Some(path),
                severity: WarningSeverity::Warning,
            }),
        }
    }
    Ok(())
}

fn scan_identities_dir(
    dir: &Path,
    _root: &Path,
    source: ConfigSource,
    options: &DiscoveryOptions,
    snapshot: &mut ConfigSnapshot,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() && !options.follow_symlinks {
            snapshot.warnings.push(DiscoveryWarning {
                code: "identity.symlink_skipped".into(),
                message: format!("skipping symlink {}", path.display()),
                path: Some(path),
                severity: WarningSeverity::Info,
            });
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        if PermissionValidator::is_insecure_file(&path) {
            snapshot.warnings.push(DiscoveryWarning {
                code: "identity.insecure_permissions".into(),
                message: format!("identity file {} has permissive mode", path.display()),
                path: Some(path.clone()),
                severity: WarningSeverity::Warning,
            });
        }
        if file_too_large(&path, options.max_file_bytes) {
            continue;
        }
        let contents = fs::read_to_string(&path)?;
        match StellarConfigParser::parse_identity_file(&name, &path, &contents, source) {
            Ok(identity) => insert_identity(snapshot, identity)?,
            Err(e) => snapshot.warnings.push(DiscoveryWarning {
                code: "identity.parse_failed".into(),
                message: e.to_string(),
                path: Some(path),
                severity: WarningSeverity::Warning,
            }),
        }
    }
    Ok(())
}

fn scan_legacy_identity_dir(
    dir: &Path,
    root: &Path,
    source: ConfigSource,
    options: &DiscoveryOptions,
    snapshot: &mut ConfigSnapshot,
) -> Result<()> {
    if dir.exists() {
        scan_identities_dir(dir, root, source, options, snapshot)?;
    }
    Ok(())
}

fn scan_contract_aliases(
    dir: &Path,
    source: ConfigSource,
    options: &DiscoveryOptions,
    snapshot: &mut ConfigSnapshot,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();

    fn walk(
        dir: &Path,
        network_hint: Option<String>,
        source: ConfigSource,
        options: &DiscoveryOptions,
        snapshot: &mut ConfigSnapshot,
        seen: &mut BTreeSet<String>,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let network = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string());
                walk(
                    &path,
                    network.or(network_hint.clone()),
                    source,
                    options,
                    snapshot,
                    seen,
                )?;
                continue;
            }
            if path.is_symlink() && !options.follow_symlinks {
                snapshot.warnings.push(DiscoveryWarning {
                    code: "contract_alias.symlink_skipped".into(),
                    message: format!("skipping symlink {}", path.display()),
                    path: Some(path),
                    severity: WarningSeverity::Info,
                });
                continue;
            }
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let alias = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            let network = network_hint.clone().unwrap_or_else(|| "testnet".into());
            let dedupe_key = format!(
                "{}:{}",
                network.to_ascii_lowercase(),
                alias.to_ascii_lowercase()
            );
            if !seen.insert(dedupe_key.clone()) {
                snapshot.warnings.push(DiscoveryWarning {
                    code: "contract_alias.duplicate".into(),
                    message: format!("duplicate contract alias '{}'", alias),
                    path: Some(path.clone()),
                    severity: WarningSeverity::Error,
                });
            }
            if file_too_large(&path, options.max_file_bytes) {
                continue;
            }
            let contents = fs::read_to_string(&path)?;
            match StellarConfigParser::parse_contract_alias_file(
                &alias, &network, &path, &contents, source,
            ) {
                Ok(record) => {
                    snapshot
                        .contract_aliases
                        .insert(record.canonical_key(), record);
                }
                Err(e) => snapshot.warnings.push(DiscoveryWarning {
                    code: "contract_alias.parse_failed".into(),
                    message: e.to_string(),
                    path: Some(path),
                    severity: WarningSeverity::Warning,
                }),
            }
        }
        Ok(())
    }

    walk(dir, None, source, options, snapshot, &mut seen)
}

fn file_too_large(path: &Path, max: u64) -> bool {
    fs::metadata(path).map(|m| m.len() > max).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_stellar_fixture(root: &Path) {
        let networks = root.join("network");
        fs::create_dir_all(&networks).unwrap();
        fs::write(
            networks.join("testnet.toml"),
            r#"
horizon_url = "https://horizon-testnet.stellar.org"
rpc_url = "https://soroban-testnet.stellar.org"
network_passphrase = "Test SDF Network ; September 2015"
"#,
        )
        .unwrap();

        let identities = root.join("identities");
        fs::create_dir_all(&identities).unwrap();
        fs::write(
            identities.join("alice.toml"),
            r#"public_key = "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T""#,
        )
        .unwrap();

        let aliases = root.join("contract-ids").join("testnet");
        fs::create_dir_all(&aliases).unwrap();
        fs::write(
            aliases.join("token.json"),
            r#"{"ids":{"contract_id":"CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A","network":"testnet"}}"#,
        )
        .unwrap();
    }

    #[test]
    fn discovers_stellar_cli_layout() {
        let dir = tempdir().unwrap();
        write_stellar_fixture(dir.path());
        let options = DiscoveryOptions {
            stellar_config_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let snap = discover_stellar_cli(&options).unwrap();
        assert_eq!(snap.network_count(), 1);
        assert_eq!(snap.identity_count(), 1);
        assert_eq!(snap.contract_alias_count(), 1);
        assert!(snap.aggregate_fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn discover_is_read_only() {
        let dir = tempdir().unwrap();
        write_stellar_fixture(dir.path());
        let before = fs::read_dir(dir.path()).unwrap().count();
        let options = DiscoveryOptions {
            stellar_config_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let _ = discover_stellar_cli(&options).unwrap();
        let after = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(before, after);
    }
}
