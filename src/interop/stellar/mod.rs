//! Stellar CLI configuration interoperability engine and submodules.

mod adapter;
mod diff;
mod discovery;
mod doctor;
mod export;
mod parser;
mod permissions;
mod redact;
mod starforge;
mod store;
mod sync;

pub use adapter::FormatAdapter;
pub use diff::DiffEngine;
pub use discovery::{discover_starforge, discover_stellar_cli, resolve_stellar_config_dir};
pub use doctor::DoctorEngine;
pub use export::ExportEngine;
pub use parser::StellarConfigParser;
pub use starforge::StarforgeConfigAdapter;
pub use store::ProvenanceStore;
pub use sync::SyncEngine;

use crate::interop::domain::*;
use anyhow::Result;

/// High-level orchestrator for Stellar CLI interoperability workflows.
#[derive(Default)]
pub struct StellarInteropEngine {
    pub discovery: DiscoveryOptions,
    pub sync: SyncOptions,
    pub provenance_store: ProvenanceStore,
}

impl StellarInteropEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_discovery(mut self, options: DiscoveryOptions) -> Self {
        self.discovery = options;
        self
    }

    pub fn with_sync(mut self, options: SyncOptions) -> Self {
        self.sync = options;
        self
    }

    /// Discover both configuration stores without modifying any files.
    pub fn discover_all(&self) -> Result<(ConfigSnapshot, ConfigSnapshot)> {
        let starforge = discover_starforge()?;
        let stellar = discover_stellar_cli(&self.discovery)?;
        Ok((starforge, stellar))
    }

    /// Produce a dry-run or live diff between StarForge and Stellar CLI.
    pub fn diff(&self) -> Result<DiffReport> {
        let (starforge, stellar) = self.discover_all()?;
        let (source, target, direction) = match self.sync.direction {
            SyncDirection::ImportToStarforge => (
                stellar.clone(),
                starforge.clone(),
                SyncDirection::ImportToStarforge,
            ),
            SyncDirection::ExportToStellarCli => (
                starforge.clone(),
                stellar.clone(),
                SyncDirection::ExportToStellarCli,
            ),
            SyncDirection::Bidirectional => (
                stellar.clone(),
                starforge.clone(),
                SyncDirection::Bidirectional,
            ),
        };
        Ok(DiffEngine::compare(
            &source,
            &target,
            direction,
            self.sync.precedence,
            self.sync.dry_run,
            &self.sync.categories,
            &self.sync.names,
        ))
    }

    /// Import, export, or bidirectionally synchronize configuration.
    pub fn sync(&mut self) -> Result<SyncReport> {
        let (mut starforge, mut stellar) = self.discover_all()?;
        let diff = DiffEngine::compare(
            &stellar,
            &starforge,
            self.sync.direction,
            self.sync.precedence,
            self.sync.dry_run,
            &self.sync.categories,
            &self.sync.names,
        );

        if diff.has_blocking_conflicts()
            && matches!(self.sync.precedence, PrecedencePolicy::FailOnConflict)
            && !self.sync.dry_run
        {
            anyhow::bail!(
                "sync aborted: {} blocking conflict(s) detected; rerun with --dry-run to inspect or choose a precedence policy",
                diff.summary.blocking
            );
        }

        let actions = SyncEngine::apply(
            &mut starforge,
            &mut stellar,
            &diff,
            &self.sync,
            self.discovery.stellar_config_dir.clone(),
        )?;

        let (sf_fp, st_fp) = {
            starforge.finalize_fingerprint();
            stellar.finalize_fingerprint();
            (
                starforge.aggregate_fingerprint.clone(),
                stellar.aggregate_fingerprint.clone(),
            )
        };

        let provenance = if self.sync.dry_run {
            self.provenance_store.load()?
        } else {
            self.provenance_store.record_sync(
                self.sync.direction,
                &sf_fp,
                &st_fp,
                actions.iter().filter(|a| a.success).count(),
                false,
            )?
        };

        Ok(SyncReport {
            schema_version: INTEROP_SCHEMA_VERSION,
            generated_at: chrono::Utc::now(),
            direction: self.sync.direction,
            precedence: self.sync.precedence,
            include_secrets: self.sync.include_secrets,
            dry_run: self.sync.dry_run,
            actions,
            diff,
            provenance,
        })
    }

    /// Run health checks across both configuration stores.
    pub fn doctor(&self) -> Result<DoctorReport> {
        let (starforge, stellar) = self.discover_all()?;
        let provenance = self.provenance_store.load()?;
        let stellar_root =
            resolve_stellar_config_dir(self.discovery.stellar_config_dir.as_deref())?;
        Ok(DoctorEngine::evaluate(
            starforge,
            stellar,
            discovery::starforge_root(),
            stellar_root,
            provenance,
        ))
    }

    /// Export a redacted snapshot bundle for automation.
    pub fn export(&self, source: ConfigSource, redact: bool) -> Result<InteropExportBundle> {
        let snapshot = match source {
            ConfigSource::StarForge => discover_starforge()?,
            ConfigSource::StellarCli | ConfigSource::LegacySorobanCli => {
                discover_stellar_cli(&self.discovery)?
            }
        };
        let provenance = self.provenance_store.load()?;
        ExportEngine::bundle(snapshot, provenance, redact)
    }
}
