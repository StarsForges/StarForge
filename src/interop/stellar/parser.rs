//! Parse Stellar CLI network, identity, and contract-alias configuration files.

use crate::interop::domain::*;
use crate::utils::config::{validate_contract_id, validate_public_key, validate_secret_key};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Raw network TOML (Stellar CLI v1).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StellarNetworkTomlV1 {
    pub rpc_url: Option<String>,
    pub horizon_url: Option<String>,
    pub network_passphrase: Option<String>,
    pub friendbot_url: Option<String>,
    #[serde(default)]
    pub header: Option<BTreeMap<String, String>>,
}

/// Raw identity TOML v1 (seed phrase based).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StellarIdentityTomlV1 {
    pub seed_phrase: Option<String>,
    pub secret_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Raw identity TOML v2 (encrypted secret support).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StellarIdentityTomlV2 {
    pub public_key: String,
    pub secret_key: Option<String>,
    pub seed_phrase: Option<String>,
    #[serde(default)]
    pub encrypted_secret: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
}

/// Contract alias JSON v1 (flat contract_id).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StellarContractAliasJsonV1 {
    pub contract_id: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub wasm_hash: Option<String>,
}

/// Contract alias JSON v2 (nested ids object).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StellarContractAliasJsonV2 {
    pub ids: ContractAliasIdsV2,
    #[serde(default)]
    pub wasm_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContractAliasIdsV2 {
    pub contract_id: String,
    pub network: String,
}

pub struct StellarConfigParser;

impl StellarConfigParser {
    pub fn parse_network_file(
        name: &str,
        path: &Path,
        contents: &str,
        source: ConfigSource,
    ) -> Result<NormalizedNetwork> {
        let raw: StellarNetworkTomlV1 = toml::from_str(contents)
            .with_context(|| format!("invalid network TOML at {}", path.display()))?;

        let horizon_url = raw
            .horizon_url
            .or_else(|| raw.rpc_url.clone())
            .unwrap_or_default();
        if horizon_url.is_empty() {
            anyhow::bail!(
                "network '{}' at {} has no horizon_url or rpc_url",
                name,
                path.display()
            );
        }

        let mut network = NormalizedNetwork {
            name: name.to_string(),
            horizon_url,
            rpc_url: raw.rpc_url,
            friendbot_url: raw.friendbot_url,
            passphrase: raw.network_passphrase,
            format_version: STELLAR_NETWORK_FORMAT_V1,
            source,
            source_path: Some(path.to_path_buf()),
            fingerprint: String::new(),
        };
        network.fingerprint = network.compute_fingerprint();
        Ok(network)
    }

    pub fn parse_identity_file(
        name: &str,
        path: &Path,
        contents: &str,
        source: ConfigSource,
    ) -> Result<NormalizedIdentity> {
        if let Ok(v2) = toml::from_str::<StellarIdentityTomlV2>(contents) {
            return Self::from_identity_v2(name, path, v2, source);
        }
        let v1: StellarIdentityTomlV1 = toml::from_str(contents)
            .with_context(|| format!("invalid identity TOML at {}", path.display()))?;
        Self::from_identity_v1(name, path, v1, source)
    }

    fn from_identity_v1(
        name: &str,
        path: &Path,
        raw: StellarIdentityTomlV1,
        source: ConfigSource,
    ) -> Result<NormalizedIdentity> {
        let (secret_material, secret_hint, public_key) = if raw.seed_phrase.is_some() {
            (
                SecretMaterialKind::SeedPhrase,
                Some("[REDACTED_SEED_PHRASE]".into()),
                raw.public_key
                    .unwrap_or_else(|| format!("G...[derived:{name}]")),
            )
        } else if let Some(secret) = raw.secret_key.as_ref() {
            validate_secret_key(secret)?;
            (
                if secret.contains(':') {
                    SecretMaterialKind::EncryptedSecret
                } else {
                    SecretMaterialKind::PlaintextSecret
                },
                Some(crate::interop::stellar::redact::redact_secret_hint(secret)),
                derive_public_from_secret(secret)
                    .unwrap_or_else(|_| format!("G...[derived:{name}]")),
            )
        } else if let Some(pk) = raw.public_key.as_ref() {
            validate_public_key(pk)?;
            (SecretMaterialKind::None, None, pk.clone())
        } else {
            anyhow::bail!(
                "identity '{}' at {} has no seed_phrase, secret_key, or public_key",
                name,
                path.display()
            );
        };

        let fingerprint = NormalizedIdentity::compute_fingerprint(&public_key, &None);
        Ok(NormalizedIdentity {
            name: name.to_string(),
            public_key,
            secret_material,
            secret_hint,
            network: None,
            format_version: STELLAR_IDENTITY_FORMAT_V1,
            source,
            source_path: Some(path.to_path_buf()),
            fingerprint,
            created_at: None,
        })
    }

    fn from_identity_v2(
        name: &str,
        path: &Path,
        raw: StellarIdentityTomlV2,
        source: ConfigSource,
    ) -> Result<NormalizedIdentity> {
        validate_public_key(&raw.public_key)?;

        let (secret_material, secret_hint) = if raw.encrypted_secret.is_some() {
            (
                SecretMaterialKind::EncryptedSecret,
                Some("[REDACTED_ENCRYPTED_SECRET]".into()),
            )
        } else if raw.seed_phrase.is_some() {
            (
                SecretMaterialKind::SeedPhrase,
                Some("[REDACTED_SEED_PHRASE]".into()),
            )
        } else if let Some(secret) = raw.secret_key.as_ref() {
            validate_secret_key(secret)?;
            let kind = if secret.contains(':') {
                SecretMaterialKind::EncryptedSecret
            } else {
                SecretMaterialKind::PlaintextSecret
            };
            (
                kind,
                Some(crate::interop::stellar::redact::redact_secret_hint(secret)),
            )
        } else {
            (SecretMaterialKind::None, None)
        };

        let fingerprint = NormalizedIdentity::compute_fingerprint(&raw.public_key, &raw.network);
        Ok(NormalizedIdentity {
            name: name.to_string(),
            public_key: raw.public_key,
            secret_material,
            secret_hint,
            network: raw.network,
            format_version: STELLAR_IDENTITY_FORMAT_V2,
            source,
            source_path: Some(path.to_path_buf()),
            fingerprint,
            created_at: None,
        })
    }

    pub fn parse_contract_alias_file(
        alias: &str,
        network: &str,
        path: &Path,
        contents: &str,
        source: ConfigSource,
    ) -> Result<NormalizedContractAlias> {
        if let Ok(v2) = serde_json::from_str::<StellarContractAliasJsonV2>(contents) {
            validate_contract_id(&v2.ids.contract_id)?;
            let fingerprint =
                NormalizedContractAlias::compute_fingerprint(&v2.ids.contract_id, &v2.ids.network);
            return Ok(NormalizedContractAlias {
                alias: alias.to_string(),
                contract_id: v2.ids.contract_id,
                network: v2.ids.network,
                wasm_hash: v2.wasm_hash,
                format_version: STELLAR_CONTRACT_ALIAS_FORMAT_V2,
                source,
                source_path: Some(path.to_path_buf()),
                fingerprint,
            });
        }

        let v1: StellarContractAliasJsonV1 = serde_json::from_str(contents)
            .with_context(|| format!("invalid contract alias JSON at {}", path.display()))?;
        validate_contract_id(&v1.contract_id)?;
        let net = v1.network.unwrap_or_else(|| network.to_string());
        let fingerprint = NormalizedContractAlias::compute_fingerprint(&v1.contract_id, &net);
        Ok(NormalizedContractAlias {
            alias: alias.to_string(),
            contract_id: v1.contract_id,
            network: net,
            wasm_hash: v1.wasm_hash,
            format_version: STELLAR_CONTRACT_ALIAS_FORMAT_V1,
            source,
            source_path: Some(path.to_path_buf()),
            fingerprint,
        })
    }

    /// Serialize a network to Stellar CLI TOML format.
    pub fn serialize_network(network: &NormalizedNetwork) -> String {
        let raw = StellarNetworkTomlV1 {
            rpc_url: network.rpc_url.clone(),
            horizon_url: Some(network.horizon_url.clone()),
            network_passphrase: network.passphrase.clone(),
            friendbot_url: network.friendbot_url.clone(),
            header: None,
        };
        toml::to_string_pretty(&raw).unwrap_or_default()
    }

    /// Serialize a public-only identity to Stellar CLI TOML (no secrets).
    pub fn serialize_identity_public(identity: &NormalizedIdentity) -> String {
        let raw = StellarIdentityTomlV2 {
            public_key: identity.public_key.clone(),
            secret_key: None,
            seed_phrase: None,
            encrypted_secret: None,
            network: identity.network.clone(),
        };
        toml::to_string_pretty(&raw).unwrap_or_default()
    }

    /// Serialize identity with explicit secret (guarded export path only).
    pub fn serialize_identity_with_secret(
        identity: &NormalizedIdentity,
        secret_key: &str,
    ) -> Result<String> {
        validate_secret_key(secret_key)?;
        let raw = StellarIdentityTomlV2 {
            public_key: identity.public_key.clone(),
            secret_key: Some(secret_key.to_string()),
            seed_phrase: None,
            encrypted_secret: None,
            network: identity.network.clone(),
        };
        toml::to_string_pretty(&raw).context("failed to serialize identity TOML")
    }

    /// Serialize contract alias to Stellar CLI JSON v2.
    pub fn serialize_contract_alias(alias: &NormalizedContractAlias) -> String {
        let raw = StellarContractAliasJsonV2 {
            ids: ContractAliasIdsV2 {
                contract_id: alias.contract_id.clone(),
                network: alias.network.clone(),
            },
            wasm_hash: alias.wasm_hash.clone(),
        };
        serde_json::to_string_pretty(&raw).unwrap_or_default()
    }
}

fn derive_public_from_secret(secret: &str) -> Result<String> {
    if secret.contains(':') {
        anyhow::bail!("cannot derive public key from encrypted secret without decryption");
    }
    use ed25519_dalek::SigningKey;
    use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};
    let pk = StellarPrivateKey::from_string(secret).context("invalid secret key strkey")?;
    let bytes: [u8; 32] = pk.0;
    let signing = SigningKey::from_bytes(&bytes);
    let verifying = signing.verifying_key();
    let stellar_pk = StellarPublicKey(verifying.to_bytes());
    Ok(stellar_pk.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_network_toml() {
        let contents = r#"
rpc_url = "https://soroban-testnet.stellar.org"
horizon_url = "https://horizon-testnet.stellar.org"
network_passphrase = "Test SDF Network ; September 2015"
friendbot_url = "https://friendbot.stellar.org"
"#;
        let net = StellarConfigParser::parse_network_file(
            "testnet",
            Path::new("/tmp/testnet.toml"),
            contents,
            ConfigSource::StellarCli,
        )
        .unwrap();
        assert_eq!(net.name, "testnet");
        assert!(net.rpc_url.is_some());
        assert!(!net.fingerprint.is_empty());
    }

    #[test]
    fn parses_identity_v1_seed_phrase() {
        let contents = r#"
seed_phrase = "word one two three four five six seven eight nine ten eleven twelve"
"#;
        let id = StellarConfigParser::parse_identity_file(
            "alice",
            Path::new("/tmp/alice.toml"),
            contents,
            ConfigSource::StellarCli,
        )
        .unwrap();
        assert_eq!(id.secret_material, SecretMaterialKind::SeedPhrase);
        assert!(id.secret_hint.as_ref().unwrap().contains("REDACTED"));
    }

    #[test]
    fn parses_contract_alias_v2() {
        let contents = r#"{"ids":{"contract_id":"CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A","network":"testnet"}}"#;
        let alias = StellarConfigParser::parse_contract_alias_file(
            "token",
            "testnet",
            Path::new("/tmp/token.json"),
            contents,
            ConfigSource::StellarCli,
        )
        .unwrap();
        assert_eq!(alias.format_version, STELLAR_CONTRACT_ALIAS_FORMAT_V2);
        assert_eq!(alias.network, "testnet");
    }

    #[test]
    fn round_trip_network_serialization() {
        let network = NormalizedNetwork {
            name: "testnet".into(),
            horizon_url: "https://horizon-testnet.stellar.org".into(),
            rpc_url: Some("https://soroban-testnet.stellar.org".into()),
            friendbot_url: None,
            passphrase: Some("Test SDF Network ; September 2015".into()),
            format_version: 1,
            source: ConfigSource::StellarCli,
            source_path: None,
            fingerprint: String::new(),
        };
        let toml = StellarConfigParser::serialize_network(&network);
        let parsed = StellarConfigParser::parse_network_file(
            "testnet",
            Path::new("/tmp/testnet.toml"),
            &toml,
            ConfigSource::StellarCli,
        )
        .unwrap();
        assert_eq!(parsed.horizon_url, network.horizon_url);
    }
}
