//! Artifact naming rules for release archives.
//!
//! Every published artifact must follow `<name>-<version>-<target>.<ext>` so
//! that automation (and the `release verify` naming check) can recover the
//! version and target triple from the file name alone, without trusting the
//! manifest to be internally consistent.

use anyhow::{anyhow, Result};

/// Builds the canonical file name for a release artifact.
pub fn expected_file_name(app_name: &str, version: &str, target: &str, extension: &str) -> String {
    format!("{app_name}-{version}-{target}.{extension}")
}

/// Validates that `file_name` matches `<app_name>-<version>-<target>.<ext>`
/// for the given `app_name`/`version`, and that `target` is a non-empty
/// token containing only characters legal in a Rust target triple or the
/// `native` pseudo-target.
pub fn validate_file_name(file_name: &str, app_name: &str, version: &str) -> Result<()> {
    let prefix = format!("{app_name}-{version}-");
    let rest = file_name.strip_prefix(&prefix).ok_or_else(|| {
        anyhow!(
            "artifact file name '{}' does not start with the required '{}' prefix",
            file_name,
            prefix
        )
    })?;

    let (target, ext) = rest.rsplit_once('.').ok_or_else(|| {
        anyhow!(
            "artifact file name '{}' is missing a file extension after the target",
            file_name
        )
    })?;

    if target.is_empty() {
        return Err(anyhow!(
            "artifact file name '{}' has an empty target segment",
            file_name
        ));
    }

    let valid_target_chars = target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid_target_chars {
        return Err(anyhow!(
            "artifact file name '{}' has an invalid target segment '{}'",
            file_name,
            target
        ));
    }

    if ext.is_empty() {
        return Err(anyhow!(
            "artifact file name '{}' has an empty extension",
            file_name
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_file_name_matches_convention() {
        assert_eq!(
            expected_file_name("starforge", "1.2.3", "x86_64-unknown-linux-gnu", "zip"),
            "starforge-1.2.3-x86_64-unknown-linux-gnu.zip"
        );
    }

    #[test]
    fn validate_file_name_accepts_well_formed_names() {
        assert!(validate_file_name(
            "starforge-1.2.3-x86_64-unknown-linux-gnu.zip",
            "starforge",
            "1.2.3"
        )
        .is_ok());
        assert!(validate_file_name("starforge-1.2.3-native.zip", "starforge", "1.2.3").is_ok());
    }

    #[test]
    fn validate_file_name_rejects_wrong_prefix() {
        let err = validate_file_name("other-1.2.3-native.zip", "starforge", "1.2.3").unwrap_err();
        assert!(err.to_string().contains("prefix"));
    }

    #[test]
    fn validate_file_name_rejects_missing_extension() {
        let err = validate_file_name("starforge-1.2.3-native", "starforge", "1.2.3").unwrap_err();
        assert!(err.to_string().contains("extension"));
    }

    #[test]
    fn validate_file_name_rejects_empty_target() {
        let err = validate_file_name("starforge-1.2.3-.zip", "starforge", "1.2.3").unwrap_err();
        assert!(err.to_string().contains("empty target"));
    }

    #[test]
    fn validate_file_name_rejects_invalid_target_characters() {
        let err = validate_file_name("starforge-1.2.3-not a target!.zip", "starforge", "1.2.3")
            .unwrap_err();
        assert!(err.to_string().contains("invalid target segment"));
    }
}
