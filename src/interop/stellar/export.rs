//! Export redacted interoperability bundles.

use crate::interop::domain::*;
use crate::interop::stellar::redact;
use anyhow::Result;
use chrono::Utc;

pub struct ExportEngine;

impl ExportEngine {
    pub fn bundle(
        mut snapshot: ConfigSnapshot,
        provenance: ProvenanceRecord,
        redact_secrets: bool,
    ) -> Result<InteropExportBundle> {
        if redact_secrets {
            redact::redact_snapshot(&mut snapshot);
        }
        snapshot.finalize_fingerprint();
        Ok(InteropExportBundle {
            schema_version: INTEROP_SCHEMA_VERSION,
            exported_at: Utc::now(),
            source: snapshot.source,
            snapshot,
            provenance,
            redacted: redact_secrets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::domain::ConfigSource;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn export_bundle_is_versioned() {
        let snap = ConfigSnapshot {
            schema_version: INTEROP_SCHEMA_VERSION,
            source: ConfigSource::StarForge,
            root_path: PathBuf::from("/tmp"),
            discovered_at: Utc::now(),
            networks: BTreeMap::new(),
            identities: BTreeMap::new(),
            contract_aliases: BTreeMap::new(),
            warnings: vec![],
            aggregate_fingerprint: String::new(),
        };
        let bundle = ExportEngine::bundle(snap, ProvenanceRecord::default(), true).unwrap();
        assert_eq!(bundle.schema_version, INTEROP_SCHEMA_VERSION);
        assert!(bundle.redacted);
    }
}
