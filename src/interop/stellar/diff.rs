//! Dry-run diffing and conflict classification between configuration snapshots.

use crate::interop::domain::*;
use std::collections::BTreeMap;

pub struct DiffEngine;

impl DiffEngine {
    pub fn compare(
        source: &ConfigSnapshot,
        target: &ConfigSnapshot,
        direction: SyncDirection,
        precedence: PrecedencePolicy,
        dry_run: bool,
        categories: &std::collections::BTreeSet<DiffCategory>,
        names: &std::collections::BTreeSet<String>,
    ) -> DiffReport {
        let mut entries = Vec::new();

        if category_enabled(DiffCategory::Network, categories) {
            entries.extend(Self::diff_networks(source, target, names));
        }
        if category_enabled(DiffCategory::Identity, categories) {
            entries.extend(Self::diff_identities(source, target, names));
        }
        if category_enabled(DiffCategory::ContractAlias, categories) {
            entries.extend(Self::diff_contract_aliases(source, target, names));
        }

        entries.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.kind.cmp(&b.kind))
        });

        let _ = (direction, precedence, dry_run);
        DiffReport::from_entries(
            source.source,
            target.source,
            direction,
            precedence,
            dry_run,
            entries,
        )
    }

    fn diff_networks(
        source: &ConfigSnapshot,
        target: &ConfigSnapshot,
        names: &std::collections::BTreeSet<String>,
    ) -> Vec<DiffEntry> {
        let mut entries = Vec::new();
        let all_keys: BTreeMap<String, ()> = source
            .networks
            .keys()
            .chain(target.networks.keys())
            .map(|k| (k.clone(), ()))
            .collect();

        for key in all_keys.keys() {
            let name = source
                .networks
                .get(key)
                .or_else(|| target.networks.get(key))
                .map(|n| n.name.clone())
                .unwrap_or_else(|| key.clone());

            if !matches_name_filter(&name.to_ascii_lowercase(), names) {
                continue;
            }

            match (source.networks.get(key), target.networks.get(key)) {
                (Some(s), Some(t)) => {
                    if s.fingerprint == t.fingerprint {
                        entries.push(Self::equivalent(DiffCategory::Network, &name, s, t));
                    } else {
                        entries.push(Self::network_mismatch(&name, s, t));
                    }
                }
                (Some(s), None) => {
                    entries.push(Self::missing_in_target(DiffCategory::Network, &name, s))
                }
                (None, Some(t)) => {
                    entries.push(Self::missing_in_source(DiffCategory::Network, &name, t))
                }
                (None, None) => {}
            }
        }
        entries
    }

    fn diff_identities(
        source: &ConfigSnapshot,
        target: &ConfigSnapshot,
        names: &std::collections::BTreeSet<String>,
    ) -> Vec<DiffEntry> {
        let mut entries = Vec::new();
        let all_keys: BTreeMap<String, ()> = source
            .identities
            .keys()
            .chain(target.identities.keys())
            .map(|k| (k.clone(), ()))
            .collect();

        for key in all_keys.keys() {
            let name = source
                .identities
                .get(key)
                .or_else(|| target.identities.get(key))
                .map(|i| i.name.clone())
                .unwrap_or_else(|| key.clone());

            if !matches_name_filter(&name.to_ascii_lowercase(), names) {
                continue;
            }

            match (source.identities.get(key), target.identities.get(key)) {
                (Some(s), Some(t)) => {
                    if s.fingerprint == t.fingerprint {
                        entries.push(Self::equivalent(DiffCategory::Identity, &name, s, t));
                    } else if s.public_key != t.public_key {
                        entries.push(Self::identity_mismatch(&name, s, t));
                    } else {
                        entries.push(Self::value_mismatch(DiffCategory::Identity, &name, s, t));
                    }
                    if s.has_secret()
                        && matches!(s.secret_material, SecretMaterialKind::EncryptedSecret)
                    {
                        entries.push(DiffEntry {
                            kind: ConflictKind::EncryptedSecret,
                            category: DiffCategory::Identity,
                            name: name.clone(),
                            source_fingerprint: Some(s.fingerprint.clone()),
                            target_fingerprint: Some(t.fingerprint.clone()),
                            message: format!(
                                "identity '{}' has encrypted secret material; use --include-secrets with permission checks to migrate",
                                name
                            ),
                            blocking: false,
                            requires_confirmation: true,
                            field_diffs: vec![],
                        });
                    }
                }
                (Some(s), None) => {
                    entries.push(Self::missing_in_target(DiffCategory::Identity, &name, s));
                    if s.has_secret() {
                        entries.push(DiffEntry {
                            kind: ConflictKind::EncryptedSecret,
                            category: DiffCategory::Identity,
                            name: name.clone(),
                            source_fingerprint: Some(s.fingerprint.clone()),
                            target_fingerprint: None,
                            message: format!(
                                "identity '{}' will be imported without secrets unless --include-secrets is set",
                                name
                            ),
                            blocking: false,
                            requires_confirmation: true,
                            field_diffs: vec![],
                        });
                    }
                }
                (None, Some(t)) => {
                    entries.push(Self::missing_in_source(DiffCategory::Identity, &name, t))
                }
                (None, None) => {}
            }
        }
        entries
    }

    fn diff_contract_aliases(
        source: &ConfigSnapshot,
        target: &ConfigSnapshot,
        names: &std::collections::BTreeSet<String>,
    ) -> Vec<DiffEntry> {
        let mut entries = Vec::new();
        let all_keys: BTreeMap<String, ()> = source
            .contract_aliases
            .keys()
            .chain(target.contract_aliases.keys())
            .map(|k| (k.clone(), ()))
            .collect();

        for key in all_keys.keys() {
            let name = source
                .contract_aliases
                .get(key)
                .or_else(|| target.contract_aliases.get(key))
                .map(|a| a.alias.clone())
                .unwrap_or_else(|| key.clone());

            if !matches_name_filter(&name.to_ascii_lowercase(), names) {
                continue;
            }

            match (
                source.contract_aliases.get(key),
                target.contract_aliases.get(key),
            ) {
                (Some(s), Some(t)) => {
                    if s.fingerprint == t.fingerprint {
                        entries.push(Self::equivalent(DiffCategory::ContractAlias, &name, s, t));
                    } else if s.contract_id != t.contract_id {
                        entries.push(Self::contract_alias_mismatch(&name, s, t));
                    } else {
                        entries.push(Self::value_mismatch(
                            DiffCategory::ContractAlias,
                            &name,
                            s,
                            t,
                        ));
                    }
                }
                (Some(s), None) => entries.push(Self::missing_in_target(
                    DiffCategory::ContractAlias,
                    &name,
                    s,
                )),
                (None, Some(t)) => entries.push(Self::missing_in_source(
                    DiffCategory::ContractAlias,
                    &name,
                    t,
                )),
                (None, None) => {}
            }
        }
        entries
    }

    fn equivalent<T: Fingerprinted>(
        category: DiffCategory,
        name: &str,
        source: &T,
        target: &T,
    ) -> DiffEntry {
        DiffEntry {
            kind: ConflictKind::Equivalent,
            category,
            name: name.to_string(),
            source_fingerprint: Some(source.fingerprint()),
            target_fingerprint: Some(target.fingerprint()),
            message: format!("'{name}' is equivalent in both stores"),
            blocking: false,
            requires_confirmation: false,
            field_diffs: vec![],
        }
    }

    fn missing_in_target<T: Fingerprinted>(
        category: DiffCategory,
        name: &str,
        source: &T,
    ) -> DiffEntry {
        DiffEntry {
            kind: ConflictKind::MissingInTarget,
            category,
            name: name.to_string(),
            source_fingerprint: Some(source.fingerprint()),
            target_fingerprint: None,
            message: format!("'{name}' exists in source but not in target"),
            blocking: false,
            requires_confirmation: false,
            field_diffs: vec![],
        }
    }

    fn missing_in_source<T: Fingerprinted>(
        category: DiffCategory,
        name: &str,
        target: &T,
    ) -> DiffEntry {
        DiffEntry {
            kind: ConflictKind::MissingInSource,
            category,
            name: name.to_string(),
            source_fingerprint: None,
            target_fingerprint: Some(target.fingerprint()),
            message: format!("'{name}' exists in target but not in source"),
            blocking: false,
            requires_confirmation: false,
            field_diffs: vec![],
        }
    }

    fn network_mismatch(
        name: &str,
        source: &NormalizedNetwork,
        target: &NormalizedNetwork,
    ) -> DiffEntry {
        let mut field_diffs = Vec::new();
        if source.horizon_url != target.horizon_url {
            field_diffs.push(FieldDiff {
                field: "horizon_url".into(),
                source_value: Some(source.horizon_url.clone()),
                target_value: Some(target.horizon_url.clone()),
            });
        }
        if source.rpc_url != target.rpc_url {
            field_diffs.push(FieldDiff {
                field: "rpc_url".into(),
                source_value: source.rpc_url.clone(),
                target_value: target.rpc_url.clone(),
            });
        }
        DiffEntry {
            kind: ConflictKind::NetworkMismatch,
            category: DiffCategory::Network,
            name: name.to_string(),
            source_fingerprint: Some(source.fingerprint.clone()),
            target_fingerprint: Some(target.fingerprint.clone()),
            message: format!("network '{}' endpoints differ between stores", name),
            blocking: true,
            requires_confirmation: true,
            field_diffs,
        }
    }

    fn identity_mismatch(
        name: &str,
        source: &NormalizedIdentity,
        target: &NormalizedIdentity,
    ) -> DiffEntry {
        DiffEntry {
            kind: ConflictKind::IdentityMismatch,
            category: DiffCategory::Identity,
            name: name.to_string(),
            source_fingerprint: Some(source.fingerprint.clone()),
            target_fingerprint: Some(target.fingerprint.clone()),
            message: format!("identity '{}' public keys differ between stores", name),
            blocking: true,
            requires_confirmation: true,
            field_diffs: vec![FieldDiff {
                field: "public_key".into(),
                source_value: Some(source.public_key.clone()),
                target_value: Some(target.public_key.clone()),
            }],
        }
    }

    fn contract_alias_mismatch(
        name: &str,
        source: &NormalizedContractAlias,
        target: &NormalizedContractAlias,
    ) -> DiffEntry {
        DiffEntry {
            kind: ConflictKind::ContractAliasMismatch,
            category: DiffCategory::ContractAlias,
            name: name.to_string(),
            source_fingerprint: Some(source.fingerprint.clone()),
            target_fingerprint: Some(target.fingerprint.clone()),
            message: format!("contract alias '{}' maps to different contract IDs", name),
            blocking: true,
            requires_confirmation: true,
            field_diffs: vec![FieldDiff {
                field: "contract_id".into(),
                source_value: Some(source.contract_id.clone()),
                target_value: Some(target.contract_id.clone()),
            }],
        }
    }

    fn value_mismatch<T: Fingerprinted>(
        category: DiffCategory,
        name: &str,
        source: &T,
        target: &T,
    ) -> DiffEntry {
        DiffEntry {
            kind: ConflictKind::ValueMismatch,
            category,
            name: name.to_string(),
            source_fingerprint: Some(source.fingerprint()),
            target_fingerprint: Some(target.fingerprint()),
            message: format!("'{name}' differs between stores"),
            blocking: true,
            requires_confirmation: true,
            field_diffs: vec![],
        }
    }
}

trait Fingerprinted {
    fn fingerprint(&self) -> String;
}

impl Fingerprinted for NormalizedNetwork {
    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

impl Fingerprinted for NormalizedIdentity {
    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

impl Fingerprinted for NormalizedContractAlias {
    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn empty_snap(source: ConfigSource) -> ConfigSnapshot {
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
    fn detects_missing_network_in_target() {
        let mut source = empty_snap(ConfigSource::StellarCli);
        let target = empty_snap(ConfigSource::StarForge);
        let mut net = NormalizedNetwork {
            name: "testnet".into(),
            horizon_url: "https://horizon-testnet.stellar.org".into(),
            rpc_url: None,
            friendbot_url: None,
            passphrase: None,
            format_version: 1,
            source: ConfigSource::StellarCli,
            source_path: None,
            fingerprint: "fp1".into(),
        };
        net.fingerprint = net.compute_fingerprint();
        source.networks.insert(net.canonical_key(), net);

        let categories: std::collections::BTreeSet<DiffCategory> =
            [DiffCategory::Network].into_iter().collect();
        let names = std::collections::BTreeSet::new();
        let report = DiffEngine::compare(
            &source,
            &target,
            SyncDirection::ImportToStarforge,
            PrecedencePolicy::FailOnConflict,
            true,
            &categories,
            &names,
        );
        assert_eq!(report.summary.missing_in_target, 1);
    }
}
