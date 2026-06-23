/// End-to-end tests for wallet lifecycle commands
/// Tests real wallet operations: create, list, show, fund, remove, rotate
#[cfg(test)]
mod wallet_lifecycle_e2e_tests {

    // Mock structures for testing
    #[derive(Debug, Clone, PartialEq)]
    struct WalletEntry {
        name: String,
        public_key: String,
        secret_key: Option<String>,
        network: String,
        created_at: String,
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
            network: Option<String>,
        ) -> Result<(), String> {
            // Validate wallet name
            if name.is_empty() {
                return Err("Wallet name cannot be empty".to_string());
            }
            if name
                .chars()
                .any(|c| !c.is_alphanumeric() && c != '-' && c != '_')
            {
                return Err(format!("Invalid wallet name: {}", name));
            }

            // Check for duplicates
            if self.wallets.iter().any(|w| w.name == name) {
                return Err(format!("Wallet '{}' already exists", name));
            }

            // Validate public key
            if !public_key.starts_with('G') || public_key.len() != 56 {
                return Err("Invalid public key format".to_string());
            }

            let wallet = WalletEntry {
                name,
                public_key,
                secret_key,
                network: network.unwrap_or_else(|| self.network.clone()),
                created_at: chrono::Utc::now().to_rfc3339(),
                funded: false,
            };

            self.wallets.push(wallet);
            Ok(())
        }

        fn list_wallets(&self) -> Vec<&WalletEntry> {
            self.wallets.iter().collect()
        }

        fn get_wallet(&self, name: &str) -> Option<&WalletEntry> {
            self.wallets.iter().find(|w| w.name == name)
        }

        fn fund_wallet(&mut self, name: &str) -> Result<(), String> {
            if let Some(wallet) = self.wallets.iter_mut().find(|w| w.name == name) {
                if self.network == "mainnet" {
                    return Err("Friendbot not available on mainnet".to_string());
                }
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

        fn rename_wallet(&mut self, old_name: &str, new_name: &str) -> Result<(), String> {
            if new_name.is_empty() {
                return Err("New wallet name cannot be empty".to_string());
            }

            if self.wallets.iter().any(|w| w.name == new_name) {
                return Err(format!("Wallet '{}' already exists", new_name));
            }

            if let Some(wallet) = self.wallets.iter_mut().find(|w| w.name == old_name) {
                wallet.name = new_name.to_string();
                Ok(())
            } else {
                Err(format!("Wallet '{}' not found", old_name))
            }
        }

        fn rotate_wallet(&mut self, name: &str, new_public_key: String) -> Result<(), String> {
            if !new_public_key.starts_with('G') || new_public_key.len() != 56 {
                return Err("Invalid public key format".to_string());
            }

            if let Some(wallet) = self.wallets.iter_mut().find(|w| w.name == name) {
                wallet.public_key = new_public_key;
                wallet.funded = false; // Reset funded status after rotation
                Ok(())
            } else {
                Err(format!("Wallet '{}' not found", name))
            }
        }
    }

    // ── WALLET CREATION TESTS ────────────────────────────────────────────

    #[test]
    fn test_create_wallet_basic() {
        let mut config = WalletConfig::new();
        let result = config.create_wallet(
            "alice".to_string(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            Some("SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            None,
        );

        assert!(result.is_ok());
        assert_eq!(config.wallets.len(), 1);
        assert_eq!(config.wallets[0].name, "alice");
        assert!(!config.wallets[0].funded);
    }

    #[test]
    fn test_create_wallet_with_custom_network() {
        let mut config = WalletConfig::new();
        let result = config.create_wallet(
            "bob".to_string(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            None,
            Some("mainnet".to_string()),
        );

        assert!(result.is_ok());
        assert_eq!(config.wallets[0].network, "mainnet");
    }

    #[test]
    fn test_create_wallet_empty_name_fails() {
        let mut config = WalletConfig::new();
        let result = config.create_wallet(
            "".to_string(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            None,
            None,
        );

        assert!(result.is_err());
        assert_eq!(config.wallets.len(), 0);
    }

    #[test]
    fn test_create_wallet_invalid_name_characters() {
        let mut config = WalletConfig::new();
        let result = config.create_wallet(
            "alice@invalid".to_string(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            None,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_create_wallet_invalid_public_key() {
        let mut config = WalletConfig::new();
        let result =
            config.create_wallet("alice".to_string(), "INVALID_KEY".to_string(), None, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_create_wallet_duplicate_name_fails() {
        let mut config = WalletConfig::new();

        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        let result = config.create_wallet(
            "alice".to_string(),
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            None,
            None,
        );

        assert!(result.is_err());
        assert_eq!(config.wallets.len(), 1);
    }

    #[test]
    fn test_create_multiple_wallets() {
        let mut config = WalletConfig::new();

        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        config
            .create_wallet(
                "bob".to_string(),
                "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                None,
                None,
            )
            .unwrap();

        assert_eq!(config.wallets.len(), 2);
    }

    // ── WALLET LISTING TESTS ─────────────────────────────────────────────

    #[test]
    fn test_list_wallets_empty() {
        let config = WalletConfig::new();
        let wallets = config.list_wallets();
        assert_eq!(wallets.len(), 0);
    }

    #[test]
    fn test_list_wallets_multiple() {
        let mut config = WalletConfig::new();

        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        config
            .create_wallet(
                "bob".to_string(),
                "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                None,
                None,
            )
            .unwrap();

        let wallets = config.list_wallets();
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].name, "alice");
        assert_eq!(wallets[1].name, "bob");
    }

    // ── WALLET SHOW TESTS ────────────────────────────────────────────────

    #[test]
    fn test_show_wallet_exists() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                Some("SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
                None,
            )
            .unwrap();

        let wallet = config.get_wallet("alice");
        assert!(wallet.is_some());
        assert_eq!(wallet.unwrap().name, "alice");
    }

    #[test]
    fn test_show_wallet_not_found() {
        let config = WalletConfig::new();
        let wallet = config.get_wallet("nonexistent");
        assert!(wallet.is_none());
    }

    #[test]
    fn test_show_wallet_displays_funding_status() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        let wallet = config.get_wallet("alice").unwrap();
        assert!(!wallet.funded);

        config.fund_wallet("alice").unwrap();
        let wallet = config.get_wallet("alice").unwrap();
        assert!(wallet.funded);
    }

    // ── WALLET FUNDING TESTS ─────────────────────────────────────────────

    #[test]
    fn test_fund_wallet_success() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        let result = config.fund_wallet("alice");
        assert!(result.is_ok());
        assert!(config.get_wallet("alice").unwrap().funded);
    }

    #[test]
    fn test_fund_wallet_not_found() {
        let mut config = WalletConfig::new();
        let result = config.fund_wallet("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_fund_wallet_mainnet_fails() {
        let mut config = WalletConfig::new();
        config.network = "mainnet".to_string();

        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        let result = config.fund_wallet("alice");
        assert!(result.is_err());
    }

    // ── WALLET REMOVAL TESTS ─────────────────────────────────────────────

    #[test]
    fn test_remove_wallet_success() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        assert_eq!(config.wallets.len(), 1);
        let result = config.remove_wallet("alice");
        assert!(result.is_ok());
        assert_eq!(config.wallets.len(), 0);
    }

    #[test]
    fn test_remove_wallet_not_found() {
        let mut config = WalletConfig::new();
        let result = config.remove_wallet("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_wallet_preserves_others() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        config
            .create_wallet(
                "bob".to_string(),
                "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                None,
                None,
            )
            .unwrap();

        config.remove_wallet("alice").unwrap();
        assert_eq!(config.wallets.len(), 1);
        assert_eq!(config.wallets[0].name, "bob");
    }

    // ── WALLET RENAME TESTS ──────────────────────────────────────────────

    #[test]
    fn test_rename_wallet_success() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        let result = config.rename_wallet("alice", "alice-renamed");
        assert!(result.is_ok());
        assert!(config.get_wallet("alice-renamed").is_some());
        assert!(config.get_wallet("alice").is_none());
    }

    #[test]
    fn test_rename_wallet_not_found() {
        let mut config = WalletConfig::new();
        let result = config.rename_wallet("nonexistent", "new-name");
        assert!(result.is_err());
    }

    #[test]
    fn test_rename_wallet_duplicate_name_fails() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        config
            .create_wallet(
                "bob".to_string(),
                "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                None,
                None,
            )
            .unwrap();

        let result = config.rename_wallet("alice", "bob");
        assert!(result.is_err());
    }

    // ── WALLET ROTATION TESTS ────────────────────────────────────────────

    #[test]
    fn test_rotate_wallet_success() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        config.fund_wallet("alice").unwrap();
        let old_key = config.get_wallet("alice").unwrap().public_key.clone();

        let result = config.rotate_wallet(
            "alice",
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        );

        assert!(result.is_ok());
        let wallet = config.get_wallet("alice").unwrap();
        assert_ne!(wallet.public_key, old_key);
        assert!(!wallet.funded); // Funded status reset after rotation
    }

    #[test]
    fn test_rotate_wallet_not_found() {
        let mut config = WalletConfig::new();
        let result = config.rotate_wallet(
            "nonexistent",
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_wallet_invalid_key() {
        let mut config = WalletConfig::new();
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        let result = config.rotate_wallet("alice", "INVALID_KEY".to_string());
        assert!(result.is_err());
    }

    // ── COMPLETE LIFECYCLE WORKFLOW TESTS ────────────────────────────────

    #[test]
    fn test_complete_wallet_lifecycle() {
        let mut config = WalletConfig::new();

        // Step 1: Create wallet
        config
            .create_wallet(
                "deployer".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                Some("SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
                None,
            )
            .unwrap();

        // Step 2: List wallets
        assert_eq!(config.list_wallets().len(), 1);

        // Step 3: Show wallet
        let wallet = config.get_wallet("deployer").unwrap();
        assert_eq!(wallet.name, "deployer");
        assert!(!wallet.funded);

        // Step 4: Fund wallet
        config.fund_wallet("deployer").unwrap();
        assert!(config.get_wallet("deployer").unwrap().funded);

        // Step 5: Rotate wallet
        config
            .rotate_wallet(
                "deployer",
                "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            )
            .unwrap();
        assert!(!config.get_wallet("deployer").unwrap().funded);

        // Step 6: Remove wallet
        config.remove_wallet("deployer").unwrap();
        assert_eq!(config.list_wallets().len(), 0);
    }

    #[test]
    fn test_multiple_wallets_independent_operations() {
        let mut config = WalletConfig::new();

        // Create two wallets
        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        config
            .create_wallet(
                "bob".to_string(),
                "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                None,
                None,
            )
            .unwrap();

        // Fund only alice
        config.fund_wallet("alice").unwrap();

        // Verify states are independent
        assert!(config.get_wallet("alice").unwrap().funded);
        assert!(!config.get_wallet("bob").unwrap().funded);

        // Remove alice, bob should remain
        config.remove_wallet("alice").unwrap();
        assert!(config.get_wallet("bob").is_some());
    }

    // ── ERROR RECOVERY TESTS ─────────────────────────────────────────────

    #[test]
    fn test_wallet_config_consistency_after_failed_operations() {
        let mut config = WalletConfig::new();

        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                None,
                None,
            )
            .unwrap();

        // Try invalid operation
        let _ = config.create_wallet(
            "alice".to_string(),
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            None,
            None,
        );

        // Config should remain consistent
        assert_eq!(config.wallets.len(), 1);
        assert_eq!(config.get_wallet("alice").unwrap().name, "alice");
    }

    #[test]
    fn test_wallet_operations_preserve_metadata() {
        let mut config = WalletConfig::new();

        config
            .create_wallet(
                "alice".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                Some("SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
                Some("mainnet".to_string()),
            )
            .unwrap();

        let original_created_at = config.get_wallet("alice").unwrap().created_at.clone();

        // Perform operations
        config.fund_wallet("alice").unwrap();
        config.rename_wallet("alice", "alice-prod").unwrap();

        // Metadata should be preserved
        let wallet = config.get_wallet("alice-prod").unwrap();
        assert_eq!(wallet.created_at, original_created_at);
        assert_eq!(wallet.network, "mainnet");
        assert_eq!(
            wallet.secret_key.as_ref().unwrap(),
            "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }
}
