//! Supported release targets and the pinned toolchain used to build them.

use anyhow::{Context, Result};
use std::path::Path;

/// Target triples StarForge release orchestration knows how to name,
/// archive, and describe in provenance. `cargo build --target <t>` still
/// requires the matching Rust target and (for cross-compilation) linker to
/// be installed locally — `starforge release prepare` reports a clear error
/// for a target that isn't installed rather than silently skipping it.
pub const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// Pseudo-target meaning "whatever this host already has built in
/// `target/release`" — used by `--skip-build` and by CI, which only has a
/// native toolchain available.
pub const NATIVE_PSEUDO_TARGET: &str = "native";

pub fn is_supported(target: &str) -> bool {
    target == NATIVE_PSEUDO_TARGET || SUPPORTED_TARGETS.contains(&target)
}

/// The binary file name `cargo build` produces for a given target, before
/// archiving. Only the Windows targets get the `.exe` suffix.
pub fn binary_file_name(binary_name: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("{binary_name}.exe")
    } else {
        binary_name.to_string()
    }
}

/// Reads the pinned toolchain channel from `rust-toolchain.toml` at the
/// given repository root, so release metadata records the exact channel
/// used rather than "whatever `rustc` happened to resolve to".
pub fn read_pinned_toolchain(repo_root: &Path) -> Result<String> {
    let path = repo_root.join("rust-toolchain.toml");
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read pinned toolchain at {}", path.display()))?;
    let value: toml::Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {} as TOML", path.display()))?;
    let channel = value
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} is missing the required [toolchain].channel key",
                path.display()
            )
        })?;
    Ok(channel.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn native_and_known_triples_are_supported() {
        assert!(is_supported(NATIVE_PSEUDO_TARGET));
        assert!(is_supported("x86_64-unknown-linux-gnu"));
        assert!(!is_supported("not-a-real-target"));
    }

    #[test]
    fn binary_file_name_adds_exe_only_for_windows() {
        assert_eq!(
            binary_file_name("starforge", "x86_64-unknown-linux-gnu"),
            "starforge"
        );
        assert_eq!(
            binary_file_name("starforge", "x86_64-pc-windows-msvc"),
            "starforge.exe"
        );
    }

    #[test]
    fn read_pinned_toolchain_parses_channel() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.89.0\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        assert_eq!(read_pinned_toolchain(dir.path()).unwrap(), "1.89.0");
    }

    #[test]
    fn read_pinned_toolchain_errors_when_channel_missing() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("rust-toolchain.toml"), "[toolchain]\n").unwrap();
        assert!(read_pinned_toolchain(dir.path()).is_err());
    }

    #[test]
    fn read_pinned_toolchain_errors_when_file_missing() {
        let dir = tempdir().unwrap();
        assert!(read_pinned_toolchain(dir.path()).is_err());
    }
}
