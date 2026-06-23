/// Error handling and edge case tests for deployment preparation
/// Tests failure scenarios, invalid inputs, and error recovery
#[cfg(test)]
mod deployment_error_handling_tests {
    const VALID_PUBLIC_KEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Mock structures
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct WalletEntry {
        name: String,
        public_key: String,
        funded: bool,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct WasmFile {
        path: String,
        size_bytes: usize,
        hash: String,
        valid: bool,
    }

    #[derive(Debug, Clone)]
    struct DeploymentValidator {
        wallets: Vec<WalletEntry>,
    }

    impl DeploymentValidator {
        fn new() -> Self {
            Self {
                wallets: Vec::new(),
            }
        }

        fn add_wallet(&mut self, name: String, public_key: String, funded: bool) {
            self.wallets.push(WalletEntry {
                name,
                public_key,
                funded,
            });
        }

        fn validate_wasm_file(&self, wasm: &WasmFile) -> Result<(), String> {
            if !wasm.valid {
                return Err("WASM file not found or invalid".to_string());
            }

            if wasm.size_bytes == 0 {
                return Err("WASM file is empty".to_string());
            }

            if wasm.hash.is_empty() {
                return Err("Failed to compute WASM hash".to_string());
            }

            Ok(())
        }

        fn validate_wallet_for_deployment(&self, wallet_name: &str) -> Result<(), String> {
            let wallet = self
                .wallets
                .iter()
                .find(|w| w.name == wallet_name)
                .ok_or_else(|| format!("Wallet '{}' not found", wallet_name))?;

            if !wallet.funded {
                return Err(format!("Wallet '{}' is not funded", wallet_name));
            }

            Ok(())
        }

        fn validate_public_key(&self, public_key: &str) -> Result<(), String> {
            if !public_key.starts_with('G') {
                return Err("Public key must start with 'G'".to_string());
            }

            if public_key.len() != 56 {
                return Err(format!(
                    "Public key must be 56 characters, got {}",
                    public_key.len()
                ));
            }

            if !public_key.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err("Public key contains invalid characters".to_string());
            }

            Ok(())
        }

        fn validate_network(&self, network: &str) -> Result<(), String> {
            match network {
                "testnet" | "mainnet" | "docker-testnet" => Ok(()),
                _ => Err(format!("Unknown network: {}", network)),
            }
        }

        fn check_xlm_balance(&self, balance: f64) -> Result<(), String> {
            if balance < 0.0 {
                return Err("XLM balance cannot be negative".to_string());
            }

            if balance < 1.0 {
                return Err("Insufficient XLM balance for deployment".to_string());
            }

            Ok(())
        }
    }

    // ── WASM FILE VALIDATION ERROR TESTS ─────────────────────────────────

    #[test]
    fn test_wasm_file_not_found() {
        let validator = DeploymentValidator::new();
        let wasm = WasmFile {
            path: "/nonexistent/contract.wasm".to_string(),
            size_bytes: 0,
            hash: "".to_string(),
            valid: false,
        };

        let result = validator.validate_wasm_file(&wasm);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_file_empty() {
        let validator = DeploymentValidator::new();
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 0,
            hash: "abc123".to_string(),
            valid: true,
        };

        let result = validator.validate_wasm_file(&wasm);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_wasm_hash_computation_failed() {
        let validator = DeploymentValidator::new();
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "".to_string(),
            valid: true,
        };

        let result = validator.validate_wasm_file(&wasm);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hash"));
    }

    #[test]
    fn test_wasm_file_valid() {
        let validator = DeploymentValidator::new();
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123def456".to_string(),
            valid: true,
        };

        let result = validator.validate_wasm_file(&wasm);
        assert!(result.is_ok());
    }

    // ── WALLET VALIDATION ERROR TESTS ────────────────────────────────────

    #[test]
    fn test_wallet_not_found() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_wallet_for_deployment("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_wallet_not_funded() {
        let mut validator = DeploymentValidator::new();
        validator.add_wallet("deployer".to_string(), VALID_PUBLIC_KEY.to_string(), false);

        let result = validator.validate_wallet_for_deployment("deployer");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not funded"));
    }

    #[test]
    fn test_wallet_funded() {
        let mut validator = DeploymentValidator::new();
        validator.add_wallet("deployer".to_string(), VALID_PUBLIC_KEY.to_string(), true);

        let result = validator.validate_wallet_for_deployment("deployer");
        assert!(result.is_ok());
    }

    // ── PUBLIC KEY VALIDATION ERROR TESTS ────────────────────────────────

    #[test]
    fn test_public_key_invalid_prefix() {
        let validator = DeploymentValidator::new();
        let result = validator
            .validate_public_key("SABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("start with 'G'"));
    }

    #[test]
    fn test_public_key_too_short() {
        let validator = DeploymentValidator::new();
        let result = validator
            .validate_public_key("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("56 characters"));
    }

    #[test]
    fn test_public_key_too_long() {
        let validator = DeploymentValidator::new();
        let result = validator
            .validate_public_key("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("56 characters"));
    }

    #[test]
    fn test_public_key_invalid_characters() {
        let validator = DeploymentValidator::new();
        let result = validator
            .validate_public_key("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_public_key_valid() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_public_key(VALID_PUBLIC_KEY);
        assert!(result.is_ok());
    }

    // ── NETWORK VALIDATION ERROR TESTS ───────────────────────────────────

    #[test]
    fn test_network_testnet_valid() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_network("testnet");
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_mainnet_valid() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_network("mainnet");
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_docker_testnet_valid() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_network("docker-testnet");
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_unknown() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_network("unknown-network");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown network"));
    }

    // ── XLM BALANCE VALIDATION ERROR TESTS ───────────────────────────────

    #[test]
    fn test_xlm_balance_negative() {
        let validator = DeploymentValidator::new();
        let result = validator.check_xlm_balance(-1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("negative"));
    }

    #[test]
    fn test_xlm_balance_zero() {
        let validator = DeploymentValidator::new();
        let result = validator.check_xlm_balance(0.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient"));
    }

    #[test]
    fn test_xlm_balance_insufficient() {
        let validator = DeploymentValidator::new();
        let result = validator.check_xlm_balance(0.5);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient"));
    }

    #[test]
    fn test_xlm_balance_sufficient() {
        let validator = DeploymentValidator::new();
        let result = validator.check_xlm_balance(1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_xlm_balance_high() {
        let validator = DeploymentValidator::new();
        let result = validator.check_xlm_balance(1000.0);
        assert!(result.is_ok());
    }

    // ── COMBINED VALIDATION ERROR TESTS ──────────────────────────────────

    #[test]
    fn test_deployment_validation_all_checks_pass() {
        let mut validator = DeploymentValidator::new();
        validator.add_wallet("deployer".to_string(), VALID_PUBLIC_KEY.to_string(), true);

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123def456".to_string(),
            valid: true,
        };

        // All validations should pass
        assert!(validator.validate_wasm_file(&wasm).is_ok());
        assert!(validator.validate_wallet_for_deployment("deployer").is_ok());
        assert!(validator.validate_public_key(VALID_PUBLIC_KEY).is_ok());
        assert!(validator.validate_network("testnet").is_ok());
        assert!(validator.check_xlm_balance(10.0).is_ok());
    }

    #[test]
    fn test_deployment_validation_multiple_failures() {
        let validator = DeploymentValidator::new();

        let wasm = WasmFile {
            path: "/nonexistent/contract.wasm".to_string(),
            size_bytes: 0,
            hash: "".to_string(),
            valid: false,
        };

        // Multiple validations should fail
        assert!(validator.validate_wasm_file(&wasm).is_err());
        assert!(validator
            .validate_wallet_for_deployment("nonexistent")
            .is_err());
        assert!(validator.validate_public_key("INVALID").is_err());
        assert!(validator.validate_network("unknown").is_err());
        assert!(validator.check_xlm_balance(0.0).is_err());
    }

    // ── ERROR MESSAGE CLARITY TESTS ──────────────────────────────────────

    #[test]
    fn test_error_message_wallet_not_found() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_wallet_for_deployment("missing-wallet");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("missing-wallet"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_error_message_wallet_not_funded() {
        let mut validator = DeploymentValidator::new();
        validator.add_wallet(
            "poor-wallet".to_string(),
            VALID_PUBLIC_KEY.to_string(),
            false,
        );

        let result = validator.validate_wallet_for_deployment("poor-wallet");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("poor-wallet"));
        assert!(msg.contains("not funded"));
    }

    #[test]
    fn test_error_message_public_key_length() {
        let validator = DeploymentValidator::new();
        let result = validator.validate_public_key("GABC");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("56"));
        assert!(msg.contains("4")); // Actual length
    }

    #[test]
    fn test_error_message_insufficient_balance() {
        let validator = DeploymentValidator::new();
        let result = validator.check_xlm_balance(0.1);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Insufficient"));
    }

    // ── STATE CONSISTENCY TESTS ──────────────────────────────────────────

    #[test]
    fn test_validator_state_unchanged_after_errors() {
        let mut validator = DeploymentValidator::new();
        validator.add_wallet("deployer".to_string(), VALID_PUBLIC_KEY.to_string(), true);

        let initial_wallet_count = validator.wallets.len();

        // Perform failed validations
        let _ = validator.validate_wallet_for_deployment("nonexistent");
        let _ = validator.validate_network("unknown");
        let _ = validator.check_xlm_balance(-1.0);

        // State should be unchanged
        assert_eq!(validator.wallets.len(), initial_wallet_count);
        assert_eq!(validator.wallets[0].name, "deployer");
    }

    #[test]
    fn test_multiple_error_scenarios_dont_corrupt_state() {
        let mut validator = DeploymentValidator::new();
        validator.add_wallet("deployer".to_string(), VALID_PUBLIC_KEY.to_string(), true);

        // Try multiple error scenarios
        let _ = validator.validate_wallet_for_deployment("missing");
        let _ = validator.validate_public_key("INVALID");
        let _ = validator.validate_network("bad-network");
        let _ = validator.check_xlm_balance(-100.0);

        // Validator should still be usable
        assert!(validator.validate_wallet_for_deployment("deployer").is_ok());
    }
}
