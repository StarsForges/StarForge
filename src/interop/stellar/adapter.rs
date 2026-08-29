//! Format version adapters for forward compatibility.

use crate::interop::domain::*;
use anyhow::Result;

pub struct FormatAdapter;

impl FormatAdapter {
    pub fn migrate_network(raw_version: u32, _network: &mut NormalizedNetwork) -> Result<()> {
        match raw_version {
            v if v <= STELLAR_NETWORK_FORMAT_V1 => Ok(()),
            v => anyhow::bail!("unsupported network format version {v}"),
        }
    }

    pub fn migrate_identity(raw_version: u32, identity: &mut NormalizedIdentity) -> Result<()> {
        match raw_version {
            STELLAR_IDENTITY_FORMAT_V1 => {
                if identity.network.is_none() {
                    identity.network = Some("testnet".into());
                }
                Ok(())
            }
            v if v <= STELLAR_IDENTITY_FORMAT_V2 => Ok(()),
            v => anyhow::bail!("unsupported identity format version {v}"),
        }
    }

    pub fn migrate_contract_alias(
        raw_version: u32,
        alias: &mut NormalizedContractAlias,
    ) -> Result<()> {
        match raw_version {
            STELLAR_CONTRACT_ALIAS_FORMAT_V1 => {
                if alias.network.is_empty() {
                    alias.network = "testnet".into();
                }
                alias.format_version = STELLAR_CONTRACT_ALIAS_FORMAT_V2;
                alias.fingerprint = NormalizedContractAlias::compute_fingerprint(
                    &alias.contract_id,
                    &alias.network,
                );
                Ok(())
            }
            v if v <= STELLAR_CONTRACT_ALIAS_FORMAT_V2 => Ok(()),
            v => anyhow::bail!("unsupported contract alias format version {v}"),
        }
    }

    pub fn supports_provenance(version: u32) -> bool {
        version <= PROVENANCE_SCHEMA_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::domain::ConfigSource;

    #[test]
    fn migrates_v1_contract_alias_to_v2() {
        let mut alias = NormalizedContractAlias {
            alias: "token".into(),
            contract_id: "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A".into(),
            network: String::new(),
            wasm_hash: None,
            format_version: STELLAR_CONTRACT_ALIAS_FORMAT_V1,
            source: ConfigSource::StellarCli,
            source_path: None,
            fingerprint: String::new(),
        };
        FormatAdapter::migrate_contract_alias(STELLAR_CONTRACT_ALIAS_FORMAT_V1, &mut alias)
            .unwrap();
        assert_eq!(alias.format_version, STELLAR_CONTRACT_ALIAS_FORMAT_V2);
        assert_eq!(alias.network, "testnet");
    }
}
