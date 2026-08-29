//! Apply interoperability changes to StarForge configuration.

use crate::interop::domain::*;
use crate::utils::config::{self, NetworkConfig, WalletEntry};
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;

pub struct StarforgeConfigAdapter;

impl StarforgeConfigAdapter {
    pub fn upsert_network(network: &NormalizedNetwork) -> Result<()> {
        let mut cfg = config::load()?;
        cfg.networks.insert(
            network.name.clone(),
            NetworkConfig {
                horizon_url: network.horizon_url.clone(),
                soroban_rpc_url: network.rpc_url.clone(),
                friendbot_url: network.friendbot_url.clone(),
                passphrase: network.passphrase.clone(),
            },
        );
        config::save(&cfg).context("failed to save StarForge config after network import")
    }

    pub fn upsert_identity(identity: &NormalizedIdentity, include_secrets: bool) -> Result<()> {
        let mut cfg = config::load()?;
        let secret_key = if include_secrets {
            Self::read_stellar_identity_secret(identity)?
        } else {
            None
        };

        if let Some(idx) = cfg
            .wallets
            .iter()
            .position(|w| w.name.eq_ignore_ascii_case(&identity.name))
        {
            cfg.wallets[idx].public_key = identity.public_key.clone();
            cfg.wallets[idx].network = identity
                .network
                .clone()
                .unwrap_or_else(|| cfg.network.clone());
            if include_secrets {
                cfg.wallets[idx].secret_key = secret_key;
            }
        } else {
            cfg.wallets.push(WalletEntry {
                name: identity.name.clone(),
                public_key: identity.public_key.clone(),
                secret_key,
                network: identity
                    .network
                    .clone()
                    .unwrap_or_else(|| cfg.network.clone()),
                created_at: identity
                    .created_at
                    .clone()
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
                funded: false,
                rotation_history: vec![],
            });
        }
        config::save(&cfg).context("failed to save StarForge config after identity import")
    }

    pub fn upsert_contract_alias(alias: &NormalizedContractAlias) -> Result<()> {
        let dir = config::config_dir().join("contract-aliases");
        fs::create_dir_all(&dir).context("failed to create contract-aliases directory")?;
        let path = dir.join(format!("{}.json", alias.alias));
        let contents =
            crate::interop::stellar::parser::StellarConfigParser::serialize_contract_alias(alias);
        crate::signer_rotation::write_private_text_atomic(&path, &contents)?;
        Ok(())
    }

    pub fn load_identity_secret(identity: &NormalizedIdentity) -> Result<Option<String>> {
        Self::read_stellar_identity_secret(identity)
    }

    fn read_stellar_identity_secret(identity: &NormalizedIdentity) -> Result<Option<String>> {
        let path = match &identity.source_path {
            Some(p) => p.clone(),
            None => return Ok(None),
        };
        if !path.exists() {
            return Ok(None);
        }
        let contents = fs::read_to_string(&path).context("failed to read identity source file")?;
        if let Ok(v2) =
            toml::from_str::<crate::interop::stellar::parser::StellarIdentityTomlV2>(&contents)
        {
            return Ok(v2.secret_key);
        }
        if let Ok(v1) =
            toml::from_str::<crate::interop::stellar::parser::StellarIdentityTomlV1>(&contents)
        {
            return Ok(v1.secret_key);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::domain::ConfigSource;
    use tempfile::tempdir;

    #[test]
    fn upsert_network_adds_custom_network() {
        let home = tempdir().unwrap();
        std::env::set_var("HOME", home.path());
        let network = NormalizedNetwork {
            name: "custom".into(),
            horizon_url: "https://custom.example/horizon".into(),
            rpc_url: Some("https://custom.example/rpc".into()),
            friendbot_url: None,
            passphrase: Some("Custom Network".into()),
            format_version: 1,
            source: ConfigSource::StellarCli,
            source_path: None,
            fingerprint: String::new(),
        };
        StarforgeConfigAdapter::upsert_network(&network).unwrap();
        let cfg = config::load().unwrap();
        assert!(cfg.networks.contains_key("custom"));
        std::env::remove_var("HOME");
    }
}
