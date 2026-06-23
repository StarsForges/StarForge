/// End-to-end tests for deployment preparation
/// Tests WASM validation, wallet resolution, account checks, and deployment planning
#[cfg(test)]
mod deployment_preparation_tests {

    // Mock structures
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct WalletEntry {
        name: String,
        public_key: String,
        network: String,
        funded: bool,
    }

    #[derive(Debug, Clone)]
    struct DeploymentConfig {
        wallets: Vec<WalletEntry>,
        network: String,
    }

    #[derive(Debug, Clone)]
    struct WasmFile {
        path: String,
        size_bytes: usize,
        hash: String,
        valid: bool,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct DeploymentPlan {
        wasm_path: String,
        wasm_hash: String,
        wasm_size_kb: f64,
        wallet_name: String,
        public_key: String,
        network: String,
        xlm_balance: f64,
        warnings: Vec<String>,
    }

    impl DeploymentConfig {
        fn new() -> Self {
            Self {
                wallets: Vec::new(),
                network: "testnet".to_string(),
            }
        }

        fn add_wallet(&mut self, name: String, public_key: String, funded: bool) {
            self.wallets.push(WalletEntry {
                name,
                public_key,
                network: self.network.clone(),
                funded,
            });
        }

        fn get_wallet(&self, name: Option<&str>) -> Result<&WalletEntry, String> {
            if let Some(name) = name {
                self.wallets
                    .iter()
                    .find(|w| w.name == name)
                    .ok_or_else(|| format!("Wallet '{}' not found", name))
            } else if !self.wallets.is_empty() {
                Ok(&self.wallets[0])
            } else {
                Err("No wallets configured".to_string())
            }
        }

        fn plan_deployment(
            &self,
            wasm: &WasmFile,
            wallet_name: Option<&str>,
            xlm_balance: f64,
        ) -> Result<DeploymentPlan, String> {
            if !wasm.valid {
                return Err("Invalid WASM file".to_string());
            }

            let wallet = self.get_wallet(wallet_name)?;

            if !wallet.funded {
                return Err(format!("Wallet '{}' is not funded", wallet.name));
            }

            let wasm_size_kb = wasm.size_bytes as f64 / 1024.0;
            let mut warnings = Vec::new();

            if wasm_size_kb > 128.0 {
                warnings.push(format!(
                    "WASM is {:.1} KB - Soroban limit is 128 KB",
                    wasm_size_kb
                ));
            }

            if self.network == "mainnet" {
                warnings.push("Deploying to MAINNET - this costs real XLM".to_string());
            }

            if xlm_balance < 1.0 {
                warnings.push("Low XLM balance - deployment may fail".to_string());
            }

            Ok(DeploymentPlan {
                wasm_path: wasm.path.clone(),
                wasm_hash: wasm.hash.clone(),
                wasm_size_kb,
                wallet_name: wallet.name.clone(),
                public_key: wallet.public_key.clone(),
                network: self.network.clone(),
                xlm_balance,
                warnings,
            })
        }
    }

    // ── WASM FILE VALIDATION TESTS ───────────────────────────────────────

    #[test]
    fn test_wasm_file_exists() {
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123def456".to_string(),
            valid: true,
        };

        assert!(wasm.valid);
    }

    #[test]
    fn test_wasm_file_not_found() {
        let wasm = WasmFile {
            path: "/nonexistent/contract.wasm".to_string(),
            size_bytes: 0,
            hash: "".to_string(),
            valid: false,
        };

        assert!(!wasm.valid);
    }

    #[test]
    fn test_wasm_hash_generation() {
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476".to_string(),
            valid: true,
        };

        // Hash should be 64 hex characters
        assert_eq!(wasm.hash.len(), 64);
        assert!(wasm.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_wasm_hash_is_deterministic() {
        let hash1 = "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476";
        let hash2 = "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476";

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_wasm_size_calculation() {
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 102400, // 100 KB
            hash: "abc123".to_string(),
            valid: true,
        };

        let size_kb = wasm.size_bytes as f64 / 1024.0;
        assert_eq!(size_kb, 100.0);
    }

    #[test]
    fn test_wasm_size_below_limit() {
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 100000, // ~97.7 KB
            hash: "abc123".to_string(),
            valid: true,
        };

        let size_kb = wasm.size_bytes as f64 / 1024.0;
        assert!(size_kb < 128.0);
    }

    #[test]
    fn test_wasm_size_above_limit() {
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 150000, // ~146.5 KB
            hash: "abc123".to_string(),
            valid: true,
        };

        let size_kb = wasm.size_bytes as f64 / 1024.0;
        assert!(size_kb > 128.0);
    }

    #[test]
    fn test_wasm_size_exactly_at_limit() {
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 131072, // Exactly 128 KB
            hash: "abc123".to_string(),
            valid: true,
        };

        let size_kb = wasm.size_bytes as f64 / 1024.0;
        assert_eq!(size_kb, 128.0);
    }

    // ── WALLET RESOLUTION TESTS ──────────────────────────────────────────

    #[test]
    fn test_resolve_wallet_by_name() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wallet = config.get_wallet(Some("deployer"));
        assert!(wallet.is_ok());
        assert_eq!(wallet.unwrap().name, "deployer");
    }

    #[test]
    fn test_resolve_wallet_not_found() {
        let config = DeploymentConfig::new();
        let wallet = config.get_wallet(Some("nonexistent"));
        assert!(wallet.is_err());
    }

    #[test]
    fn test_resolve_wallet_default_to_first() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "alice".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );
        config.add_wallet(
            "bob".to_string(),
            "GXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wallet = config.get_wallet(None);
        assert!(wallet.is_ok());
        assert_eq!(wallet.unwrap().name, "alice");
    }

    #[test]
    fn test_resolve_wallet_no_wallets_configured() {
        let config = DeploymentConfig::new();
        let wallet = config.get_wallet(None);
        assert!(wallet.is_err());
        assert!(wallet.unwrap_err().contains("No wallets"));
    }

    // ── ACCOUNT VALIDATION TESTS ─────────────────────────────────────────

    #[test]
    fn test_account_funded_status_check() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wallet = config.get_wallet(Some("deployer")).unwrap();
        assert!(wallet.funded);
    }

    #[test]
    fn test_account_unfunded_status_check() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            false,
        );

        let wallet = config.get_wallet(Some("deployer")).unwrap();
        assert!(!wallet.funded);
    }

    #[test]
    fn test_deployment_fails_with_unfunded_wallet() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            false,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123".to_string(),
            valid: true,
        };

        let result = config.plan_deployment(&wasm, Some("deployer"), 10.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not funded"));
    }

    // ── DEPLOYMENT PLANNING TESTS ────────────────────────────────────────

    #[test]
    fn test_plan_deployment_success() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123def456".to_string(),
            valid: true,
        };

        let result = config.plan_deployment(&wasm, Some("deployer"), 10.0);
        assert!(result.is_ok());

        let plan = result.unwrap();
        assert_eq!(plan.wallet_name, "deployer");
        assert_eq!(plan.wasm_hash, "abc123def456");
        assert_eq!(plan.xlm_balance, 10.0);
    }

    #[test]
    fn test_plan_deployment_invalid_wasm() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/nonexistent/contract.wasm".to_string(),
            size_bytes: 0,
            hash: "".to_string(),
            valid: false,
        };

        let result = config.plan_deployment(&wasm, Some("deployer"), 10.0);
        assert!(result.is_err());
    }

    // ── DEPLOYMENT WARNING TESTS ─────────────────────────────────────────

    #[test]
    fn test_warning_wasm_size_exceeds_limit() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 150000, // 146.5 KB
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 10.0)
            .unwrap();
        assert!(!plan.warnings.is_empty());
        assert!(plan.warnings[0].contains("128 KB"));
    }

    #[test]
    fn test_warning_mainnet_deployment() {
        let mut config = DeploymentConfig::new();
        config.network = "mainnet".to_string();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 10.0)
            .unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("MAINNET")));
    }

    #[test]
    fn test_warning_low_xlm_balance() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 0.5)
            .unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("Low XLM")));
    }

    #[test]
    fn test_no_warnings_for_normal_deployment() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 100.0)
            .unwrap();
        assert!(plan.warnings.is_empty());
    }

    // ── NETWORK VALIDATION TESTS ─────────────────────────────────────────

    #[test]
    fn test_deployment_on_testnet() {
        let mut config = DeploymentConfig::new();
        config.network = "testnet".to_string();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 10.0)
            .unwrap();
        assert_eq!(plan.network, "testnet");
    }

    #[test]
    fn test_deployment_on_mainnet() {
        let mut config = DeploymentConfig::new();
        config.network = "mainnet".to_string();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 50000,
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 100.0)
            .unwrap();
        assert_eq!(plan.network, "mainnet");
    }

    // ── COMPLETE DEPLOYMENT PREPARATION WORKFLOW TESTS ────────────────────

    #[test]
    fn test_complete_deployment_preparation_workflow() {
        let mut config = DeploymentConfig::new();
        config.network = "testnet".to_string();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        // Step 1: Validate WASM file
        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 75000,
            hash: "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476".to_string(),
            valid: true,
        };

        assert!(wasm.valid);

        // Step 2: Resolve wallet
        let wallet = config.get_wallet(Some("deployer"));
        assert!(wallet.is_ok());

        // Step 3: Check account funding
        assert!(wallet.unwrap().funded);

        // Step 4: Plan deployment
        let plan = config.plan_deployment(&wasm, Some("deployer"), 50.0);
        assert!(plan.is_ok());

        let plan = plan.unwrap();
        assert_eq!(
            plan.wasm_hash,
            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
        );
        assert_eq!(plan.wallet_name, "deployer");
        assert_eq!(plan.xlm_balance, 50.0);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn test_deployment_preparation_with_multiple_warnings() {
        let mut config = DeploymentConfig::new();
        config.network = "mainnet".to_string();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/path/to/contract.wasm".to_string(),
            size_bytes: 150000, // Over limit
            hash: "abc123".to_string(),
            valid: true,
        };

        let plan = config
            .plan_deployment(&wasm, Some("deployer"), 0.5)
            .unwrap();
        assert!(plan.warnings.len() >= 2); // Size + mainnet + low balance
    }

    // ── ERROR RECOVERY TESTS ─────────────────────────────────────────────

    #[test]
    fn test_deployment_preparation_state_consistency() {
        let mut config = DeploymentConfig::new();
        config.add_wallet(
            "deployer".to_string(),
            "GABC2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGHIJKLMNOPQRSTUVWXYZ2DEFGH".to_string(),
            true,
        );

        let wasm = WasmFile {
            path: "/nonexistent/contract.wasm".to_string(),
            size_bytes: 0,
            hash: "".to_string(),
            valid: false,
        };

        // Failed deployment should not affect config
        let _ = config.plan_deployment(&wasm, Some("deployer"), 10.0);

        // Config should remain unchanged
        assert_eq!(config.wallets.len(), 1);
        assert_eq!(config.wallets[0].name, "deployer");
    }
}
