//! Deterministic archive creation.
//!
//! `cargo build` output is not byte-reproducible on its own (path-dependent
//! debug info, file timestamps, directory ordering), but the *archive* we
//! ship can be made reproducible by controlling the three things a naive zip
//! writer leaves to chance: entry order, per-entry timestamps, and per-entry
//! permissions. Given the same input files and the same `source_date_epoch`,
//! [`build_deterministic_archive`] always produces byte-identical output.

use super::checksum::sha256_file;
use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::FileOptions;
use zip::{DateTime as ZipDateTime, ZipWriter};

/// The default timestamp stamped on archive entries when no
/// `source_date_epoch` is supplied: the MS-DOS/zip format epoch. Using a
/// fixed constant (rather than "now") keeps unpinned builds from producing
/// spuriously different archives run to run, even though they are not
/// declared `reproducible` in the manifest without an explicit epoch.
const ZIP_FORMAT_EPOCH_YEAR: u16 = 1980;

/// A single file to place inside the archive, addressed by its
/// archive-relative path (always forward-slash separated).
pub struct ArchiveEntry {
    pub archive_path: String,
    pub source_path: PathBuf,
}

#[derive(Debug)]
pub struct NormalizedArchive {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

fn zip_timestamp(source_date_epoch: Option<i64>) -> Result<ZipDateTime> {
    let epoch = match source_date_epoch {
        Some(e) => e,
        None => {
            return ZipDateTime::from_date_and_time(ZIP_FORMAT_EPOCH_YEAR, 1, 1, 0, 0, 0)
                .map_err(|_| anyhow::anyhow!("failed to build default zip timestamp"));
        }
    };

    let dt: DateTime<Utc> = DateTime::from_timestamp(epoch, 0)
        .ok_or_else(|| anyhow::anyhow!("source_date_epoch {} is out of range", epoch))?;

    ZipDateTime::from_date_and_time(
        dt.year() as u16,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        dt.second() as u8,
    )
    .map_err(|_| {
        anyhow::anyhow!(
            "source_date_epoch {} cannot be represented in zip DOS time (must be >= 1980)",
            epoch
        )
    })
}

/// Builds a deterministic zip archive from `entries` at `out_path`.
///
/// Entries are written in a caller-controlled order — callers must sort
/// `entries` by `archive_path` before calling this, so archive layout never
/// depends on file-system iteration order. All regular files get `0o755`
/// permissions and the same timestamp, so two builds from identical input
/// bytes always produce an identical archive.
pub fn build_deterministic_archive(
    entries: &[ArchiveEntry],
    out_path: &Path,
    source_date_epoch: Option<i64>,
) -> Result<NormalizedArchive> {
    if entries.is_empty() {
        anyhow::bail!("cannot build a release archive with zero entries");
    }

    let timestamp = zip_timestamp(source_date_epoch)?;

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create archive directory {}", parent.display()))?;
    }

    let file = File::create(out_path)
        .with_context(|| format!("failed to create archive {}", out_path.display()))?;
    let mut writer = ZipWriter::new(file);

    let options: FileOptions = FileOptions::default()
        .last_modified_time(timestamp)
        .unix_permissions(0o755);

    for entry in entries {
        writer
            .start_file(entry.archive_path.clone(), options)
            .with_context(|| format!("failed to start archive entry {}", entry.archive_path))?;
        let mut source = File::open(&entry.source_path).with_context(|| {
            format!(
                "failed to open source file {} for archive entry {}",
                entry.source_path.display(),
                entry.archive_path
            )
        })?;
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).with_context(|| {
            format!("failed to read source file {}", entry.source_path.display())
        })?;
        writer
            .write_all(&buf)
            .with_context(|| format!("failed to write archive entry {}", entry.archive_path))?;
    }

    writer
        .finish()
        .context("failed to finalize release archive")?;

    let sha256 = sha256_file(out_path)?;
    let size_bytes = std::fs::metadata(out_path)
        .with_context(|| format!("failed to stat archive {}", out_path.display()))?
        .len();

    Ok(NormalizedArchive {
        path: out_path.to_path_buf(),
        sha256,
        size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_fixture(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn same_input_and_epoch_produce_byte_identical_archives() {
        let src = tempdir().unwrap();
        let bin = write_fixture(src.path(), "starforge", b"pretend binary bytes");
        let license = write_fixture(src.path(), "LICENSE", b"MIT");

        let entries = vec![
            ArchiveEntry {
                archive_path: "LICENSE".to_string(),
                source_path: license.clone(),
            },
            ArchiveEntry {
                archive_path: "starforge".to_string(),
                source_path: bin.clone(),
            },
        ];

        let out_dir = tempdir().unwrap();
        let a = build_deterministic_archive(
            &entries,
            &out_dir.path().join("a.zip"),
            Some(1_700_000_000),
        )
        .unwrap();
        let b = build_deterministic_archive(
            &entries,
            &out_dir.path().join("b.zip"),
            Some(1_700_000_000),
        )
        .unwrap();

        assert_eq!(a.sha256, b.sha256);
        let bytes_a = std::fs::read(&a.path).unwrap();
        let bytes_b = std::fs::read(&b.path).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn different_source_date_epoch_changes_the_digest() {
        let src = tempdir().unwrap();
        let bin = write_fixture(src.path(), "starforge", b"pretend binary bytes");
        let entries = vec![ArchiveEntry {
            archive_path: "starforge".to_string(),
            source_path: bin,
        }];

        let out_dir = tempdir().unwrap();
        let a = build_deterministic_archive(
            &entries,
            &out_dir.path().join("a.zip"),
            Some(1_700_000_000),
        )
        .unwrap();
        let b = build_deterministic_archive(
            &entries,
            &out_dir.path().join("b.zip"),
            Some(1_800_000_000),
        )
        .unwrap();

        assert_ne!(a.sha256, b.sha256);
    }

    #[test]
    fn different_file_contents_change_the_digest() {
        let src = tempdir().unwrap();
        let bin_v1 = write_fixture(src.path(), "starforge-v1", b"version one");
        let bin_v2 = write_fixture(src.path(), "starforge-v2", b"version two");

        let out_dir = tempdir().unwrap();
        let a = build_deterministic_archive(
            &[ArchiveEntry {
                archive_path: "starforge".to_string(),
                source_path: bin_v1,
            }],
            &out_dir.path().join("a.zip"),
            Some(1_700_000_000),
        )
        .unwrap();
        let b = build_deterministic_archive(
            &[ArchiveEntry {
                archive_path: "starforge".to_string(),
                source_path: bin_v2,
            }],
            &out_dir.path().join("b.zip"),
            Some(1_700_000_000),
        )
        .unwrap();

        assert_ne!(a.sha256, b.sha256);
    }

    #[test]
    fn rejects_empty_entry_list() {
        let out_dir = tempdir().unwrap();
        let err =
            build_deterministic_archive(&[], &out_dir.path().join("empty.zip"), None).unwrap_err();
        assert!(err.to_string().contains("zero entries"));
    }

    #[test]
    fn rejects_source_date_epoch_before_zip_format_epoch() {
        // 1970-01-01, well before the zip format's 1980 floor.
        let src = tempdir().unwrap();
        let bin = write_fixture(src.path(), "starforge", b"x");
        let out_dir = tempdir().unwrap();
        let err = build_deterministic_archive(
            &[ArchiveEntry {
                archive_path: "starforge".to_string(),
                source_path: bin,
            }],
            &out_dir.path().join("a.zip"),
            Some(0),
        )
        .unwrap_err();
        assert!(err.to_string().contains("1980"));
    }
}
