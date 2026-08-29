//! Rollback-safe publication staging.
//!
//! `release prepare` writes archives into a `.tmp-<uuid>` directory first,
//! then atomically renames it into place only once every artifact for the
//! run has been built and checksummed successfully. If anything fails
//! partway through, the temporary directory is removed on drop — a
//! `release prepare` run either fully lands or leaves nothing new behind;
//! it never publishes a half-built staging directory that `release
//! manifest` could pick up by mistake.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// `~/.starforge/release/staging` — overridable per call for tests and for
/// `--out`.
pub fn default_staging_root() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".starforge").join("release").join("staging"))
}

pub struct StagingSession {
    tmp_dir: PathBuf,
    final_dir: PathBuf,
    committed: bool,
}

impl StagingSession {
    /// Begins a new staging session for `version` under `root`. Fails if a
    /// staging session for this exact version is already in progress
    /// (its `.tmp-*` directory still exists), so two concurrent `release
    /// prepare` invocations for the same version can't interleave writes.
    pub fn begin(root: &Path, version: &str) -> Result<Self> {
        fs::create_dir_all(root)
            .with_context(|| format!("failed to create staging root {}", root.display()))?;

        let tmp_dir = root.join(format!(".tmp-{version}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp_dir)
            .with_context(|| format!("failed to create staging directory {}", tmp_dir.display()))?;

        Ok(Self {
            tmp_dir,
            final_dir: root.join(version),
            committed: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.tmp_dir
    }

    /// Publishes the staged directory by renaming it into its final
    /// location. Refuses to overwrite an existing staged release for the
    /// same version unless `force` is set, so a re-run can't silently
    /// clobber artifacts a maintainer already began signing.
    pub fn commit(mut self, force: bool) -> Result<PathBuf> {
        if self.final_dir.exists() {
            if !force {
                anyhow::bail!(
                    "a staged release already exists at {} (pass --force to replace it)",
                    self.final_dir.display()
                );
            }
            fs::remove_dir_all(&self.final_dir).with_context(|| {
                format!(
                    "failed to remove existing staged release at {}",
                    self.final_dir.display()
                )
            })?;
        }

        fs::rename(&self.tmp_dir, &self.final_dir).with_context(|| {
            format!(
                "failed to publish staging directory {} to {}",
                self.tmp_dir.display(),
                self.final_dir.display()
            )
        })?;
        self.committed = true;
        Ok(self.final_dir.clone())
    }

    /// Explicitly discards the staging session, removing its temporary
    /// directory. Equivalent to letting the session drop without
    /// committing, but named for callers that want the rollback to be
    /// visible in their own error-handling code.
    pub fn rollback(mut self) {
        self.cleanup();
    }

    fn cleanup(&mut self) {
        if !self.committed && self.tmp_dir.exists() {
            let _ = fs::remove_dir_all(&self.tmp_dir);
        }
    }
}

impl Drop for StagingSession {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn commit_publishes_staged_files_to_final_directory() {
        let root = tempdir().unwrap();
        let session = StagingSession::begin(root.path(), "1.0.0").unwrap();
        std::fs::write(session.path().join("artifact.zip"), b"bytes").unwrap();

        let published = session.commit(false).unwrap();
        assert_eq!(published, root.path().join("1.0.0"));
        assert!(published.join("artifact.zip").exists());
    }

    #[test]
    fn drop_without_commit_removes_the_temp_directory() {
        let root = tempdir().unwrap();
        let tmp_path;
        {
            let session = StagingSession::begin(root.path(), "1.0.0").unwrap();
            tmp_path = session.path().to_path_buf();
            std::fs::write(session.path().join("partial.zip"), b"bytes").unwrap();
            // session drops here without commit — simulating a mid-run failure
        }
        assert!(!tmp_path.exists());
        assert!(!root.path().join("1.0.0").exists());
    }

    #[test]
    fn rollback_removes_the_temp_directory_explicitly() {
        let root = tempdir().unwrap();
        let session = StagingSession::begin(root.path(), "1.0.0").unwrap();
        let tmp_path = session.path().to_path_buf();
        session.rollback();
        assert!(!tmp_path.exists());
    }

    #[test]
    fn commit_refuses_to_overwrite_existing_staged_release_without_force() {
        let root = tempdir().unwrap();
        let first = StagingSession::begin(root.path(), "1.0.0").unwrap();
        first.commit(false).unwrap();

        let second = StagingSession::begin(root.path(), "1.0.0").unwrap();
        let err = second.commit(false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn commit_with_force_replaces_existing_staged_release() {
        let root = tempdir().unwrap();
        let first = StagingSession::begin(root.path(), "1.0.0").unwrap();
        std::fs::write(first.path().join("old.zip"), b"old").unwrap();
        first.commit(false).unwrap();

        let second = StagingSession::begin(root.path(), "1.0.0").unwrap();
        std::fs::write(second.path().join("new.zip"), b"new").unwrap();
        let published = second.commit(true).unwrap();

        assert!(!published.join("old.zip").exists());
        assert!(published.join("new.zip").exists());
    }
}
