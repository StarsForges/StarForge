/// Error handling and edge case tests for wallet operations
/// Tests failure scenarios, invalid inputs, and error recovery
#[cfg(test)]
mod wallet_error_handling_tests {
    const VALID_PUBLIC_KEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const VALID_PUBLIC_KEY_2: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const VALID_SECRET_KEY: &str = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Mock structures
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct WalletEntry {
        name: String,
        public_key: String,
        secret_key: Option<String>,
        network: String,
        funded: bool,
    }

    #[derive(Debug, Clone)]
    struct WalletConfig {
        wallets: Vec<WalletEntry>,
        network: String,
    }

    impl WalletConfig {
        fn new() -> Self {
            Self {
                wallets: Vec::new(),
                network: "testnet".to_string(),
            }
        }

        fn create_wallet(
            &mut self,
            name: String,
            public_key: String,
            secret_key: Option<String>,
        ) -> Result<(), String> {
            if name.is_empty() {
                return Err("Wallet name cannot be empty".to_string());
            }

            if name
                .chars()
                .any(|c| !c.is_alphanumeric() && c != '-' && c != '_')
            {
                return Err(format!("Invalid wallet name: {}", name));
            }

            if self.wallets.iter().any(|w| w.name == name) {
                return Err(format!("Wallet '{}' already exists", name));
            }

            if !public_key.starts_with('G')
                || public_key.len() != 56
                || !public_key.chars().all(|c| c.is_ascii_alphanumeric())
            {
                return Err("Invalid public key format".to_string());
            }

            if let Some(ref sk) = secret_key {
                if !sk.starts_with('S') && !sk.contains(':') {
                    return Err("Invalid secret key format".to_string());
                }
            }

            self.wallets.push(WalletEntry {
                name,
                public_key,
                secret_key,
                network: self.network.clone(),
                funded: false,
            });

            Ok(())
        }

        fn get_wallet(&self, name: &str) -> Option<&WalletEntry> {
            self.wallets.iter().find(|w| w.name == name)
        }

        fn decrypt_secret(&self, name: &str, password: &str) -> Result<String, String> {
            let wallet = self
                .get_wallet(name)
                .ok_or_else(|| format!("Wallet '{}' not found", name))?;

            let secret = wallet
                .secret_key
                .as_ref()
                .ok_or_else(|| format!("Wallet '{}' has no secret key", name))?;

            // Simulate encrypted secret (contains ':')
            if secret.contains(':') {
                if password.is_empty() {
                    return Err("Password cannot be empty".to_string());
                }
                if password.len() < 12 {
                    return Err("Password too short (minimum 12 characters)".to_string());
                }
                // Simulate decryption - in real code would use crypto
                Ok(format!("decrypted_{}", secret))
            } else {
                // Plaintext secret
                Ok(secret.clone())
            }
        }

        fn fund_wallet(&mut self, name: &str) -> Result<(), String> {
            if self.network == "mainnet" {
                return Err("Friendbot not available on mainnet".to_string());
            }

            if let Some(wallet) = self.wallets.iter_mut().find(|w| w.name == name) {
                wallet.funded = true;
                Ok(())
            } else {
                Err(format!("Wallet '{}' not found", name))
            }
        }

        fn remove_wallet(&mut self, name: &str) -> Result<(), String> {
            let initial_len = self.wallets.len();
            self.wallets.retain(|w| w.name != name);

            if self.wallets.len() < initial_len {
                Ok(())
            } else {
                Err(format!("Wallet '{}' not found", name))
            }
        }
    }

    // ── INVALID INPUT TESTS ──────────────────────────────────────────────

    #[test]
    fn test_create_wallet_with_empty_name() {
        let mut config = WalletConfig::new();
        let result = config.create_wallet("".to_string(), VALID_PUBLIC_KEY.to_string(), None);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_create_wallet_with_special_characters_in_name() {
        let mut config = WalletConfig::new();

        let invalid_names = vec!["alice@", "bob#", "charlie$", "dave%", "eve&"];

        for name in invalid_names {
            let result = config.create_wallet(name.to_string(), VALID_PUBLIC_KEY.to_string(), None);

            assert!(result.is_err(), "Name '{}' should be invalid", name);
        }
    }

    #[test]
    fn test_create_wallet_with_valid_name_characters() {
        let mut config = WalletConfig::new();

        let valid_names = ["alice", "bob-wallet", "charlie_wallet", "dave123"];

        for (i, name) in valid_names.iter().enumerate() {
            let public_key = format!("G{:0>55}", i);
            let result = config.create_wallet(name.to_string(), public_key, None);

            assert!(result.is_ok(), "Name '{}' should be valid", name);
        }
    }

    #[test]
    fn test_create_wallet_with_invalid_public_key_format() {
        let mut config = WalletConfig::new();

        let invalid_keys = vec![
            "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Starts with S
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // Too short
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX", // Too long
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@", // Invalid char
        ];

        for key in invalid_keys {
            let result = config.create_wallet("wallet".to_string(), key.to_string(), None);
            assert!(result.is_err(), "Key '{}' should be invalid", key);
        }
    }

    #[test]
    fn test_create_wallet_with_invalid_secret_key_format() {
        let mut config = WalletConfig::new();

        let invalid_secrets = vec![
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH", // Starts with G
            "XABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH", // Starts with X
        ];

        for secret in invalid_secrets {
            let result = config.create_wallet(
                "wallet".to_string(),
                VALID_PUBLIC_KEY.to_string(),
                Some(secret.to_string()),
            );
            assert!(result.is_err(), "Secret '{}' should be invalid", secret);
        }
    }

    // ── DUPLICATE WALLET TESTS ───────────────────────────────────────────

    #[test]
    fn test_create_duplicate_wallet_fails() {
        let mut config = WalletConfig::new();

        config
            .create_wallet("alice".to_string(), VALID_PUBLIC_KEY.to_string(), None)
            .unwrap();

        let result =
            config.create_wallet("alice".to_string(), VALID_PUBLIC_KEY_2.to_string(), None);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_duplicate_check_is_case_sensitive() {
        let mut config = WalletConfig::new();

        config
            .create_wallet("Alice".to_string(), VALID_PUBLIC_KEY.to_string(), None)
            .unwrap();

        // Different case should be allowed (case-sensitive)
        let result =
            config.create_wallet("alice".to_string(), VALID_PUBLIC_KEY_2.to_string(), None);

        assert!(result.is_ok());
    }

    // ── MISSING WALLET TESTS ─────────────────────────────────────────────

    #[test]
    fn test_get_nonexistent_wallet() {
        let config = WalletConfig::new();
        let wallet = config.get_wallet("nonexistent");
        assert!(wallet.is_none());
    }

    #[test]
    fn test_fund_nonexistent_wallet() {
        let mut config = WalletConfig::new();
        let result = config.fund_wallet("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_remove_nonexistent_wallet() {
        let mut config = WalletConfig::new();
        let result = config.remove_wallet("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    // ── SECRET KEY DECRYPTION TESTS ──────────────────────────────────────

    #[test]
    fn test_decrypt_plaintext_secret() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                VALID_PUBLIC_KEY.to_string(),
                Some(VALID_SECRET_KEY.to_string()),
            )
            .unwrap();

        let result = config.decrypt_secret("alice", "any_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_encrypted_secret_with_valid_password() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                VALID_PUBLIC_KEY.to_string(),
                Some("salt:nonce:ciphertext".to_string()), // Encrypted format
            )
            .unwrap();

        let result = config.decrypt_secret("alice", "valid_password_12chars");
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_encrypted_secret_with_empty_password() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                VALID_PUBLIC_KEY.to_string(),
                Some("salt:nonce:ciphertext".to_string()),
            )
            .unwrap();

        let result = config.decrypt_secret("alice", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_decrypt_encrypted_secret_with_short_password() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                VALID_PUBLIC_KEY.to_string(),
                Some("salt:nonce:ciphertext".to_string()),
            )
            .unwrap();

        let result = config.decrypt_secret("alice", "short");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_decrypt_nonexistent_wallet() {
        let config = WalletConfig::new();
        let result = config.decrypt_secret("nonexistent", "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_decrypt_wallet_without_secret_key() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                VALID_PUBLIC_KEY.to_string(),
                None, // No secret key
            )
            .unwrap();

        let result = config.decrypt_secret("alice", "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no secret key"));
    }

    // ── NETWORK-SPECIFIC ERROR TESTS ─────────────────────────────────────

    #[test]
    fn test_fund_wallet_on_mainnet_fails() {
        let mut config = WalletConfig::new();
        config.network = "mainnet".to_string();

        config
            .create_wallet("alice".to_string(), VALID_PUBLIC_KEY.to_string(), None)
            .unwrap();

        let result = config.fund_wallet("alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mainnet"));
    }

    #[test]
    fn test_fund_wallet_on_testnet_succeeds() {
        let mut config = WalletConfig::new();
        config.network = "testnet".to_string();

        config
            .create_wallet("alice".to_string(), VALID_PUBLIC_KEY.to_string(), None)
            .unwrap();

        let result = config.fund_wallet("alice");
        assert!(result.is_ok());
    }

    // ── EDGE CASE TESTS ──────────────────────────────────────────────────

    #[test]
    fn test_wallet_name_with_numbers() {
        let mut config = WalletConfig::new();
        let result =
            config.create_wallet("wallet123".to_string(), VALID_PUBLIC_KEY.to_string(), None);

        assert!(result.is_ok());
    }

    #[test]
    fn test_wallet_name_with_dashes_and_underscores() {
        let mut config = WalletConfig::new();

        let result1 = config.create_wallet(
            "wallet-name".to_string(),
            VALID_PUBLIC_KEY.to_string(),
            None,
        );

        let result2 = config.create_wallet(
            "wallet_name".to_string(),
            VALID_PUBLIC_KEY_2.to_string(),
            None,
        );

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_very_long_wallet_name() {
        let mut config = WalletConfig::new();
        let long_name = "a".repeat(1000);

        let result = config.create_wallet(long_name, VALID_PUBLIC_KEY.to_string(), None);

        // Should succeed - no length limit enforced
        assert!(result.is_ok());
    }

    #[test]
    fn test_wallet_state_consistency_after_errors() {
        let mut config = WalletConfig::new();

        config
            .create_wallet("alice".to_string(), VALID_PUBLIC_KEY.to_string(), None)
            .unwrap();

        // Try to create duplicate
        let _ = config.create_wallet("alice".to_string(), VALID_PUBLIC_KEY_2.to_string(), None);

        // State should be unchanged
        assert_eq!(config.wallets.len(), 1);
        assert_eq!(config.wallets[0].name, "alice");
    }

    #[test]
    fn test_multiple_errors_dont_corrupt_state() {
        let mut config = WalletConfig::new();

        config
            .create_wallet("alice".to_string(), VALID_PUBLIC_KEY.to_string(), None)
            .unwrap();

        // Multiple failed operations
        let _ = config.fund_wallet("nonexistent");
        let _ = config.remove_wallet("nonexistent");
        let _ = config.create_wallet("alice".to_string(), VALID_PUBLIC_KEY_2.to_string(), None);

        // State should still be consistent
        assert_eq!(config.wallets.len(), 1);
        assert_eq!(config.wallets[0].name, "alice");
    }
}
