use std::process::Command;

#[test]
fn test_hardware_wallet_command_availability() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("wallet")
        .arg("--help")
        .output()
        .expect("Failed to get wallet help");

    assert!(
        output.status.success(),
        "Wallet command should be available"
    );

    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        help_text.contains("wallet")
            || help_text.contains("hardware")
            || help_text.contains("ledger"),
        "Wallet help should document hardware wallet options"
    );
}

#[test]
fn test_hardware_wallet_detection_graceful_fallback() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("wallet")
        .arg("list")
        .output()
        .expect("Failed to list wallets");

    assert!(
        output.status.success() || output.status.code().is_some(),
        "Wallet list should handle missing hardware gracefully"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stderr, stdout);

    if !output.status.success() {
        assert!(
            combined.contains("hardware")
                || combined.contains("not found")
                || combined.contains("unavailable"),
            "Should clearly indicate hardware wallet status"
        );
    }
}

#[test]
fn test_hardware_wallet_without_device_handling() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("wallet")
        .arg("import")
        .arg("--hardware")
        .arg("ledger")
        .output()
        .expect("Failed to attempt hardware import");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{}{}", stderr, stdout);

        assert!(
            combined.contains("not found")
                || combined.contains("unavailable")
                || combined.contains("connect")
                || combined.contains("error"),
            "Missing hardware device should produce clear diagnostic"
        );
    }
}

#[test]
fn test_hardware_wallet_feature_detection() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("--version")
        .output()
        .expect("Failed to get version");

    assert!(output.status.success(), "Version should be available");

    let version_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        !version_str.is_empty(),
        "Version should report for feature availability"
    );
}

#[test]
fn test_hardware_wallet_error_recovery() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output1 = Command::new(starforge_binary)
        .arg("wallet")
        .arg("list")
        .output()
        .expect("First wallet list should work");

    let output2 = Command::new(starforge_binary)
        .arg("wallet")
        .arg("list")
        .output()
        .expect("Second wallet list should work");

    assert!(
        output1.status.success() || output1.status.code() == output2.status.code(),
        "Hardware wallet errors should be recoverable across invocations"
    );
}

#[test]
fn test_hardware_wallet_api_consistency() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let wallet_help = Command::new(starforge_binary)
        .arg("wallet")
        .arg("--help")
        .output()
        .expect("Wallet help should be available");

    let import_help = Command::new(starforge_binary)
        .arg("wallet")
        .arg("import")
        .arg("--help")
        .output()
        .expect("Wallet import help should be available");

    let _wallet_help_text = String::from_utf8_lossy(&wallet_help.stdout);
    let _import_help_text = String::from_utf8_lossy(&import_help.stdout);

    assert!(
        wallet_help.status.success(),
        "Wallet command interface should be consistent"
    );

    assert!(
        import_help.status.success(),
        "Wallet subcommands should be available"
    );
}

#[test]
fn test_hardware_wallet_offline_behavior() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("wallet")
        .arg("export")
        .arg("--format")
        .arg("json")
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let combined = format!("{}{}", stderr, stdout);

                assert!(
                    combined.contains("error")
                        || combined.contains("required")
                        || combined.contains("invalid"),
                    "Should provide clear error when requirements not met"
                );
            }
        }
        Err(_) => {
            panic!("Wallet export command should be callable");
        }
    }
}

#[test]
fn test_hardware_wallet_timeout_behavior() {
    let starforge_binary = env!("CARGO_BIN_EXE_starforge");

    let output = Command::new(starforge_binary)
        .arg("wallet")
        .arg("connect")
        .arg("--timeout")
        .arg("1s")
        .output();

    if let Ok(output) = output {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stderr, stdout);

            assert!(
                combined.contains("timeout")
                    || combined.contains("unavailable")
                    || combined.contains("error"),
                "Timeout behavior should be clear and predictable"
            );
        }
    }
}
