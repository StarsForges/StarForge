//! Selective import/export/sync with explicit precedence policies.

use crate::interop::domain::*;
use crate::interop::stellar::parser::StellarConfigParser;
use crate::interop::stellar::permissions::PermissionValidator;
use crate::interop::stellar::starforge::StarforgeConfigAdapter;
use crate::signer_rotation::{create_private_directory, write_private_text_atomic};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub struct SyncEngine;

impl SyncEngine {
    pub fn apply(
        starforge: &mut ConfigSnapshot,
        stellar: &mut ConfigSnapshot,
        diff: &DiffReport,
        options: &SyncOptions,
        stellar_config_dir: Option<PathBuf>,
    ) -> Result<Vec<SyncActionResult>> {
        let mut actions = Vec::new();

        for entry in &diff.entries {
            if entry.kind == ConflictKind::Equivalent {
                actions.push(SyncActionResult {
                    category: entry.category,
                    name: entry.name.clone(),
                    action: SyncAction::NoOp,
                    success: true,
                    message: "records are equivalent".into(),
                });
                continue;
            }

            if !category_enabled(entry.category, &options.categories) {
                actions.push(SyncActionResult {
                    category: entry.category,
                    name: entry.name.clone(),
                    action: SyncAction::Skipped,
                    success: true,
                    message: "category not selected".into(),
                });
                continue;
            }

            if !matches_name_filter(&entry.name.to_ascii_lowercase(), &options.names) {
                actions.push(SyncActionResult {
                    category: entry.category,
                    name: entry.name.clone(),
                    action: SyncAction::Skipped,
                    success: true,
                    message: "name filter excluded".into(),
                });
                continue;
            }

            let result = Self::apply_entry(
                starforge,
                stellar,
                entry,
                options,
                stellar_config_dir.as_deref(),
            )?;
            actions.push(result);
        }

        Ok(actions)
    }

    fn apply_entry(
        starforge: &mut ConfigSnapshot,
        stellar: &mut ConfigSnapshot,
        entry: &DiffEntry,
        options: &SyncOptions,
        stellar_config_dir: Option<&Path>,
    ) -> Result<SyncActionResult> {
        if options.dry_run {
            return Ok(SyncActionResult {
                category: entry.category,
                name: entry.name.clone(),
                action: SyncAction::NoOp,
                success: true,
                message: format!("dry-run: would handle {:?}", entry.kind),
            });
        }

        if entry.blocking && matches!(options.precedence, PrecedencePolicy::FailOnConflict) {
            return Ok(SyncActionResult {
                category: entry.category,
                name: entry.name.clone(),
                action: SyncAction::Rejected,
                success: false,
                message: format!("blocked by conflict: {:?}", entry.kind),
            });
        }

        match options.direction {
            SyncDirection::ImportToStarforge => {
                Self::import_to_starforge(starforge, stellar, entry, options)
            }
            SyncDirection::ExportToStellarCli => {
                Self::export_to_stellar(starforge, stellar, entry, options, stellar_config_dir)
            }
            SyncDirection::Bidirectional => {
                if entry.kind == ConflictKind::MissingInTarget {
                    Self::import_to_starforge(starforge, stellar, entry, options)
                } else if entry.kind == ConflictKind::MissingInSource {
                    Self::export_to_stellar(starforge, stellar, entry, options, stellar_config_dir)
                } else {
                    Self::resolve_conflict(starforge, stellar, entry, options, stellar_config_dir)
                }
            }
        }
    }

    fn import_to_starforge(
        starforge: &mut ConfigSnapshot,
        stellar: &ConfigSnapshot,
        entry: &DiffEntry,
        options: &SyncOptions,
    ) -> Result<SyncActionResult> {
        match entry.category {
            DiffCategory::Network => {
                let key = entry.name.to_ascii_lowercase();
                if let Some(net) = stellar.networks.get(&key) {
                    if options.dry_run {
                        return Ok(dry_run_action(entry, "import network"));
                    }
                    StarforgeConfigAdapter::upsert_network(net)?;
                    starforge.networks.insert(key, net.clone());
                    Ok(success_action(
                        entry,
                        SyncAction::Created,
                        "imported network",
                    ))
                } else {
                    Ok(skip_action(entry, "network not in source"))
                }
            }
            DiffCategory::Identity => {
                let key = entry.name.to_ascii_lowercase();
                if let Some(id) = stellar.identities.get(&key) {
                    if id.has_secret() && !options.include_secrets {
                        return Ok(SyncActionResult {
                            category: entry.category,
                            name: entry.name.clone(),
                            action: SyncAction::Skipped,
                            success: true,
                            message: "public-only import; secret skipped".into(),
                        });
                    }
                    if id.has_secret() && options.require_secure_permissions {
                        if let Some(path) = &id.source_path {
                            PermissionValidator::check_secret_file(path)?;
                        }
                    }
                    if options.dry_run {
                        return Ok(dry_run_action(entry, "import identity"));
                    }
                    StarforgeConfigAdapter::upsert_identity(id, options.include_secrets)?;
                    starforge.identities.insert(key, id.clone());
                    Ok(success_action(
                        entry,
                        SyncAction::Created,
                        "imported identity",
                    ))
                } else {
                    Ok(skip_action(entry, "identity not in source"))
                }
            }
            DiffCategory::ContractAlias => {
                let key = stellar
                    .contract_aliases
                    .values()
                    .find(|a| a.alias.eq_ignore_ascii_case(&entry.name))
                    .map(|a| a.canonical_key());
                if let Some(key) = key {
                    if let Some(alias) = stellar.contract_aliases.get(&key) {
                        if options.dry_run {
                            return Ok(dry_run_action(entry, "import contract alias"));
                        }
                        StarforgeConfigAdapter::upsert_contract_alias(alias)?;
                        starforge.contract_aliases.insert(key, alias.clone());
                        return Ok(success_action(
                            entry,
                            SyncAction::Created,
                            "imported contract alias",
                        ));
                    }
                }
                Ok(skip_action(entry, "contract alias not in source"))
            }
            DiffCategory::Store => Ok(skip_action(entry, "store-level changes not supported")),
        }
    }

    fn export_to_stellar(
        starforge: &ConfigSnapshot,
        stellar: &mut ConfigSnapshot,
        entry: &DiffEntry,
        options: &SyncOptions,
        stellar_config_dir: Option<&Path>,
    ) -> Result<SyncActionResult> {
        let root = stellar_config_dir
            .map(PathBuf::from)
            .or_else(|| crate::interop::stellar::discovery::resolve_stellar_config_dir(None).ok())
            .context("stellar config directory required for export")?;

        match entry.category {
            DiffCategory::Network => {
                let key = entry.name.to_ascii_lowercase();
                if let Some(net) = starforge.networks.get(&key) {
                    if options.dry_run {
                        return Ok(dry_run_action(entry, "export network"));
                    }
                    let dir = root.join("network");
                    create_private_directory(&dir)?;
                    let path = dir.join(format!("{}.toml", net.name));
                    if path.exists() && !options.confirm_overwrites && entry.blocking {
                        bail!(
                            "refusing to overwrite existing Stellar CLI network '{}'; pass --yes to confirm",
                            net.name
                        );
                    }
                    let contents = StellarConfigParser::serialize_network(net);
                    write_private_text_atomic(&path, &contents)?;
                    PermissionValidator::set_private_file(&path)?;
                    stellar.networks.insert(key, net.clone());
                    Ok(success_action(
                        entry,
                        SyncAction::Created,
                        "exported network",
                    ))
                } else {
                    Ok(skip_action(entry, "network not in starforge"))
                }
            }
            DiffCategory::Identity => {
                let key = entry.name.to_ascii_lowercase();
                if let Some(id) = starforge.identities.get(&key) {
                    if id.has_secret() && !options.include_secrets {
                        return Ok(SyncActionResult {
                            category: entry.category,
                            name: entry.name.clone(),
                            action: SyncAction::Skipped,
                            success: true,
                            message: "public-only export; secret skipped".into(),
                        });
                    }
                    if options.dry_run {
                        return Ok(dry_run_action(entry, "export identity"));
                    }
                    let dir = root.join("identities");
                    create_private_directory(&dir)?;
                    let path = dir.join(format!("{}.toml", id.name));
                    if path.exists() && !options.confirm_overwrites {
                        bail!(
                            "refusing to overwrite Stellar CLI identity '{}'; pass --yes to confirm",
                            id.name
                        );
                    }
                    let contents = if options.include_secrets {
                        if let Some(secret) = StarforgeConfigAdapter::load_identity_secret(id)? {
                            if options.require_secure_permissions {
                                PermissionValidator::check_secret_file(&path)?;
                            }
                            StellarConfigParser::serialize_identity_with_secret(id, &secret)?
                        } else {
                            StellarConfigParser::serialize_identity_public(id)
                        }
                    } else {
                        StellarConfigParser::serialize_identity_public(id)
                    };
                    write_private_text_atomic(&path, &contents)?;
                    PermissionValidator::set_private_file(&path)?;
                    stellar.identities.insert(key, id.clone());
                    Ok(success_action(
                        entry,
                        SyncAction::Created,
                        "exported identity",
                    ))
                } else {
                    Ok(skip_action(entry, "identity not in starforge"))
                }
            }
            DiffCategory::ContractAlias => {
                let alias_record = starforge
                    .contract_aliases
                    .values()
                    .find(|a| a.alias.eq_ignore_ascii_case(&entry.name));
                if let Some(alias) = alias_record {
                    if options.dry_run {
                        return Ok(dry_run_action(entry, "export contract alias"));
                    }
                    let dir = root.join("contract-ids").join(&alias.network);
                    create_private_directory(&dir)?;
                    let path = dir.join(format!("{}.json", alias.alias));
                    if path.exists() && !options.confirm_overwrites && entry.blocking {
                        bail!(
                            "refusing to overwrite Stellar CLI contract alias '{}'; pass --yes to confirm",
                            alias.alias
                        );
                    }
                    let contents = StellarConfigParser::serialize_contract_alias(alias);
                    write_private_text_atomic(&path, &contents)?;
                    PermissionValidator::set_private_file(&path)?;
                    stellar
                        .contract_aliases
                        .insert(alias.canonical_key(), alias.clone());
                    Ok(success_action(
                        entry,
                        SyncAction::Created,
                        "exported contract alias",
                    ))
                } else {
                    Ok(skip_action(entry, "contract alias not in starforge"))
                }
            }
            DiffCategory::Store => Ok(skip_action(entry, "store-level changes not supported")),
        }
    }

    fn resolve_conflict(
        starforge: &mut ConfigSnapshot,
        stellar: &mut ConfigSnapshot,
        entry: &DiffEntry,
        options: &SyncOptions,
        stellar_config_dir: Option<&Path>,
    ) -> Result<SyncActionResult> {
        match options.precedence {
            PrecedencePolicy::StarforgeWins => {
                Self::export_to_stellar(starforge, stellar, entry, options, stellar_config_dir)
            }
            PrecedencePolicy::StellarCliWins => {
                Self::import_to_starforge(starforge, stellar, entry, options)
            }
            PrecedencePolicy::NewestFingerprint => {
                let source_fp = entry.source_fingerprint.as_deref().unwrap_or("");
                let target_fp = entry.target_fingerprint.as_deref().unwrap_or("");
                if source_fp > target_fp {
                    Self::import_to_starforge(starforge, stellar, entry, options)
                } else if target_fp > source_fp {
                    Self::export_to_stellar(starforge, stellar, entry, options, stellar_config_dir)
                } else {
                    Ok(SyncActionResult {
                        category: entry.category,
                        name: entry.name.clone(),
                        action: SyncAction::Rejected,
                        success: false,
                        message: "fingerprint tie requires explicit resolution".into(),
                    })
                }
            }
            PrecedencePolicy::AdditiveOnly => Ok(SyncActionResult {
                category: entry.category,
                name: entry.name.clone(),
                action: SyncAction::Skipped,
                success: true,
                message: "additive-only policy skips conflicts".into(),
            }),
            PrecedencePolicy::FailOnConflict => Ok(SyncActionResult {
                category: entry.category,
                name: entry.name.clone(),
                action: SyncAction::Rejected,
                success: false,
                message: "fail-on-conflict policy rejects mismatch".into(),
            }),
        }
    }
}

fn success_action(entry: &DiffEntry, action: SyncAction, msg: &str) -> SyncActionResult {
    SyncActionResult {
        category: entry.category,
        name: entry.name.clone(),
        action,
        success: true,
        message: msg.into(),
    }
}

fn skip_action(entry: &DiffEntry, msg: &str) -> SyncActionResult {
    SyncActionResult {
        category: entry.category,
        name: entry.name.clone(),
        action: SyncAction::Skipped,
        success: true,
        message: msg.into(),
    }
}

fn dry_run_action(entry: &DiffEntry, msg: &str) -> SyncActionResult {
    SyncActionResult {
        category: entry.category,
        name: entry.name.clone(),
        action: SyncAction::NoOp,
        success: true,
        message: format!("dry-run: {msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn snap(source: ConfigSource) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            source,
            root_path: PathBuf::from("/tmp"),
            discovered_at: Utc::now(),
            networks: BTreeMap::new(),
            identities: BTreeMap::new(),
            contract_aliases: BTreeMap::new(),
            warnings: vec![],
            aggregate_fingerprint: String::new(),
        }
    }

    #[test]
    fn dry_run_does_not_write() {
        let mut sf = snap(ConfigSource::StarForge);
        let mut st = snap(ConfigSource::StellarCli);
        let entry = DiffEntry {
            kind: ConflictKind::MissingInTarget,
            category: DiffCategory::Network,
            name: "testnet".into(),
            source_fingerprint: None,
            target_fingerprint: None,
            message: "missing".into(),
            blocking: false,
            requires_confirmation: false,
            field_diffs: vec![],
        };
        let diff = DiffReport::from_entries(
            ConfigSource::StellarCli,
            ConfigSource::StarForge,
            SyncDirection::ImportToStarforge,
            PrecedencePolicy::AdditiveOnly,
            true,
            vec![entry],
        );
        let options = SyncOptions {
            dry_run: true,
            ..Default::default()
        };
        let actions = SyncEngine::apply(&mut sf, &mut st, &diff, &options, None).unwrap();
        assert!(actions.iter().all(|a| a.success));
    }
}
