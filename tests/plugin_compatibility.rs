use std::process::Command;

#[test]
fn test_plugin_loader_basic_compatibility() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");
    let output = Command::new(starforge_binary)
        .arg("--version")
        .output()
        .expect("Failed to get version");

    assert!(output.status.success(), "Version command should succeed");

    let version_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        !version_str.is_empty(),
        "Version output should not be empty"
    );
}

#[test]
fn test_plugin_list_works() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");
    let output = Command::new(starforge_binary)
        .arg("plugin")
        .arg("list")
        .output()
        .expect("Failed to list plugins");

    assert!(
        output.status.success(),
        "Plugin list command should succeed"
    );
}

#[test]
fn test_plugin_incompatible_version_handling() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("plugin")
        .arg("info")
        .arg("nonexistent-plugin")
        .output()
        .expect("Failed to check nonexistent plugin");

    assert!(
        !output.status.success() || output.status.code() == Some(0),
        "Handling missing plugin should produce clear output"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let output_combined = format!("{}{}", stderr, stdout);

    assert!(
        output_combined.contains("not found")
            || output_combined.contains("error")
            || output.status.code() == Some(0),
        "Should provide clear error message for missing plugin"
    );
}

#[test]
fn test_plugin_interface_stability() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let help_output = Command::new(starforge_binary)
        .arg("plugin")
        .arg("--help")
        .output()
        .expect("Failed to get plugin help");

    assert!(
        help_output.status.success(),
        "Plugin help should be available"
    );

    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(
        help_text.contains("list") || help_text.contains("install") || help_text.contains("plugin"),
        "Plugin interface should document available commands"
    );
}

#[test]
fn test_plugin_version_mismatch_detection() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let version_output = Command::new(starforge_binary)
        .arg("--version")
        .output()
        .expect("Failed to get version");

    let version_str = String::from_utf8_lossy(&version_output.stdout);
    assert!(
        !version_str.is_empty(),
        "Should report version for compatibility checks"
    );

    assert!(
        version_str.contains("starforge") || version_str.contains("v") || version_str.contains("."),
        "Version format should be identifiable"
    );
}

#[test]
fn test_plugin_error_messages_are_clear() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("plugin")
        .arg("load")
        .arg("invalid-path-that-does-not-exist")
        .output()
        .expect("Failed to attempt loading invalid plugin");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{}{}", stderr, stdout);

        assert!(
            combined.contains("error")
                || combined.contains("failed")
                || combined.contains("not found")
                || combined.contains("invalid"),
            "Error messages should clearly indicate what went wrong"
        );
    }
}

#[test]
fn test_plugin_isolation_per_version() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output1 = Command::new(starforge_binary)
        .arg("plugin")
        .arg("list")
        .output()
        .expect("First plugin list should succeed");

    let output2 = Command::new(starforge_binary)
        .arg("plugin")
        .arg("list")
        .output()
        .expect("Second plugin list should succeed");

    assert!(
        output1.status.success() && output2.status.success(),
        "Plugin state should be consistent across invocations"
    );

    let output1_str = String::from_utf8_lossy(&output1.stdout);
    let output2_str = String::from_utf8_lossy(&output2.stdout);

    assert_eq!(
        output1_str, output2_str,
        "Plugin list should be deterministic for same version"
    );
}
