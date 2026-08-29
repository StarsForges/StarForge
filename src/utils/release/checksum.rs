//! SHA-256 checksums for release artifacts, and a `SHA256SUMS`-style
//! sidecar file compatible with `sha256sum -c`.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

const CHUNK_SIZE: usize = 64 * 1024;

/// Streams `path` through SHA-256 without loading the whole file into
/// memory, so large platform archives stay bounded in memory use.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("failed to read {} while hashing", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Hashes an in-memory byte slice. Used for small, already-materialized
/// artifacts such as the SBOM and manifest JSON documents.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Writes a `sha256sum -c`-compatible checksums file: one
/// `<hex digest>  <file name>` line per entry, sorted by file name for
/// deterministic output regardless of build order.
pub fn write_checksums_file(entries: &[(String, String)], out_path: &Path) -> Result<()> {
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    for (file_name, digest) in sorted {
        out.push_str(&format!("{}  {}\n", digest, file_name));
    }

    let mut file = File::create(out_path)
        .with_context(|| format!("failed to create checksums file {}", out_path.display()))?;
    file.write_all(out.as_bytes())
        .with_context(|| format!("failed to write checksums file {}", out_path.display()))?;
    Ok(())
}

/// Parses a `sha256sum`-style checksums file into `file name -> digest`.
/// Blank lines and `#`-prefixed comments are ignored.
pub fn parse_checksums_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read checksums file {}", path.display()))?;

    let mut map = BTreeMap::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, "  ");
        let digest = parts.next().unwrap_or_default().trim();
        let file_name = parts.next().unwrap_or_default().trim();
        if digest.is_empty() || file_name.is_empty() {
            anyhow::bail!(
                "malformed checksums line {} in {}: '{}'",
                line_no + 1,
                path.display(),
                line
            );
        }
        map.insert(file_name.to_string(), digest.to_lowercase());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sha256_bytes_matches_known_vector() {
        // SHA-256("") — the canonical empty-input test vector.
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_file_matches_sha256_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("artifact.bin");
        std::fs::write(&path, b"reproducible bytes").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            sha256_bytes(b"reproducible bytes")
        );
    }

    #[test]
    fn sha256_file_is_deterministic_across_repeated_hashing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("artifact.bin");
        std::fs::write(&path, vec![7u8; 200_000]).unwrap();
        let first = sha256_file(&path).unwrap();
        let second = sha256_file(&path).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn checksums_file_roundtrips_and_is_sorted() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("SHA256SUMS");
        write_checksums_file(
            &[
                ("z-artifact.zip".to_string(), "deadbeef".to_string()),
                ("a-artifact.zip".to_string(), "cafef00d".to_string()),
            ],
            &out,
        )
        .unwrap();

        let contents = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines[0], "cafef00d  a-artifact.zip");
        assert_eq!(lines[1], "deadbeef  z-artifact.zip");

        let parsed = parse_checksums_file(&out).unwrap();
        assert_eq!(parsed.get("a-artifact.zip"), Some(&"cafef00d".to_string()));
        assert_eq!(parsed.get("z-artifact.zip"), Some(&"deadbeef".to_string()));
    }

    #[test]
    fn parse_checksums_file_rejects_malformed_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.sums");
        std::fs::write(&path, "not-a-valid-line\n").unwrap();
        assert!(parse_checksums_file(&path).is_err());
    }
}
