//! Locating (or producing) the compiled binary for a release target.
//!
//! Cross-compiling every supported target requires toolchains this sandbox
//! and most CI runners don't have installed, so `--skip-build` (reusing an
//! already-built `target/**/release/<binary>`) is the path exercised by
//! automated tests and CI; invoking `cargo build` directly is the path a
//! maintainer's release machine uses. Both funnel through
//! [`locate_or_build_binary`] so `release prepare` behaves identically
//! either way from the archive step onward.

use super::targets::{binary_file_name, NATIVE_PSEUDO_TARGET};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

fn target_release_dir(repo_root: &Path, target: &str) -> PathBuf {
    if target == NATIVE_PSEUDO_TARGET {
        repo_root.join("target").join("release")
    } else {
        repo_root.join("target").join(target).join("release")
    }
}

/// Resolves the path to the built binary for `target`, building it first
/// with `cargo build --release --locked` unless `skip_build` is set.
pub fn locate_or_build_binary(
    repo_root: &Path,
    target: &str,
    binary_name: &str,
    skip_build: bool,
) -> Result<PathBuf> {
    if !skip_build {
        let mut cmd = Command::new("cargo");
        cmd.arg("build").arg("--release").arg("--locked");
        if target != NATIVE_PSEUDO_TARGET {
            cmd.arg("--target").arg(target);
        }
        cmd.current_dir(repo_root);

        let output = cmd
            .output()
            .with_context(|| format!("failed to invoke `cargo build` for target '{target}'"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_lines: Vec<&str> = stderr.lines().collect();
            let tail_start = stderr_lines.len().saturating_sub(20);
            anyhow::bail!(
                "cargo build failed for target '{}' (exit {}):\n{}",
                target,
                output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                stderr_lines[tail_start..].join("\n")
            );
        }
    }

    let file_name = binary_file_name(binary_name, target);
    let path = target_release_dir(repo_root, target).join(&file_name);
    if !path.exists() {
        anyhow::bail!(
            "expected built binary at {} but it does not exist. {}",
            path.display(),
            if skip_build {
                "Run `cargo build --release` first, or omit --skip-build.".to_string()
            } else {
                "cargo build reported success but did not produce the expected output path — \
                 check that --binary-name matches the [[bin]] name in Cargo.toml."
                    .to_string()
            }
        );
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn locate_with_skip_build_finds_native_binary() {
        let repo = tempdir().unwrap();
        let release_dir = repo.path().join("target").join("release");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("starforge"), b"fake binary").unwrap();

        let path =
            locate_or_build_binary(repo.path(), NATIVE_PSEUDO_TARGET, "starforge", true).unwrap();
        assert_eq!(path, release_dir.join("starforge"));
    }

    #[test]
    fn locate_with_skip_build_finds_cross_target_binary() {
        let repo = tempdir().unwrap();
        let release_dir = repo
            .path()
            .join("target")
            .join("x86_64-pc-windows-msvc")
            .join("release");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("starforge.exe"), b"fake binary").unwrap();

        let path = locate_or_build_binary(repo.path(), "x86_64-pc-windows-msvc", "starforge", true)
            .unwrap();
        assert_eq!(path, release_dir.join("starforge.exe"));
    }

    #[test]
    fn locate_with_skip_build_errors_clearly_when_binary_missing() {
        let repo = tempdir().unwrap();
        let err = locate_or_build_binary(repo.path(), NATIVE_PSEUDO_TARGET, "starforge", true)
            .unwrap_err();
        assert!(err.to_string().contains("does not exist"));
        assert!(err.to_string().contains("--skip-build"));
    }
}
