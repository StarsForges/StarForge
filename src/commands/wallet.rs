#![allow(clippy::items_after_test_module)]

use crate::utils::{
    config, confirmation, crypto, hardware_wallet, horizon, mnemonic, multisig, print as p,
};
use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use chrono::Utc;
use clap::Subcommand;
use colored::*;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};

const WALLET_BACKUP_VERSION: &str = "1";

fn kdf_options(
    mem: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u32>,
    config_default: Option<&crypto::KdfOptions>,
) -> Option<crypto::KdfOptions> {
    if mem.is_none() && iterations.is_none() && parallelism.is_none() && config_default.is_none() {
        return None;
    }

    let mut options = config_default.cloned().unwrap_or_default();
    if let Some(m) = mem {
        options.mem = Some(m);
    }
    if let Some(i) = iterations {
        options.iterations = Some(i);
    }
    if let Some(p) = parallelism {
        options.parallelism = Some(p);
    }
    Some(options)
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletBackup {
    version: String,
    exported_at: String,
    wallets: Vec<WalletBackupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletBackupEntry {
    name: String,
    public_key: String,
    secret_key: Option<String>,
    network: String,
    created_at: String,
    funded: bool,
}

impl From<&config::WalletEntry> for WalletBackupEntry {
    fn from(entry: &config::WalletEntry) -> Self {
        Self {
            name: entry.name.clone(),
            public_key: entry.public_key.clone(),
            secret_key: entry.secret_key.clone(),
            network: entry.network.clone(),
            created_at: entry.created_at.clone(),
            funded: entry.funded,
        }
    }
}

#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new keypair and save it locally
    Create {
        /// A friendly name for the wallet (e.g. "alice", "deployer")
        name: String,
        /// Fund the wallet via network-specific faucet immediately when available
        #[arg(long, default_value = "false")]
        fund: bool,
        /// Network to associate with this wallet (overrides global config)
        #[arg(long, value_parser = ["testnet", "mainnet"])]
        network: Option<String>,
        /// Encrypt the secret key with a passphrase at rest
        #[arg(long, default_value = "false")]
        encrypt: bool,
        /// Reject passphrases that score below "Strong" on the zxcvbn scale
        /// (requires --encrypt)
        #[arg(long, default_value = "false", requires = "encrypt")]
        strict: bool,
        /// Generate a BIP39 recovery phrase instead of a random key
        #[arg(long, default_value = "false")]
        mnemonic: bool,
        /// Mnemonic length: 12 or 24 words (requires --mnemonic)
        #[arg(long, default_value = "24", requires = "mnemonic", value_parser = ["12", "24"])]
        words: String,
        /// Account index for SEP-0005 path m/44'/148'/index' (requires --mnemonic)
        #[arg(long, default_value = "0", requires = "mnemonic")]
        account_index: u32,
        /// Argon2 memory cost in KiB (requires --encrypt)
        #[arg(long, requires = "encrypt")]
        mem: Option<u32>,
        /// Argon2 iteration count (requires --encrypt)
        #[arg(long, requires = "encrypt")]
        iterations: Option<u32>,
        /// Argon2 parallelism factor (requires --encrypt)
        #[arg(long, requires = "encrypt")]
        parallelism: Option<u32>,
    },
    /// List all saved wallets
    List,
    /// Show details of a saved wallet including live balance
    Show {
        /// Wallet name
        name: String,
        /// Reveal the secret key in plaintext
        #[arg(long, default_value = "false")]
        reveal: bool,
    },
    /// Fund a wallet via a configured network faucet
    Fund {
        /// Wallet name to fund
        name: String,
    },
    /// Remove a wallet from local storage
    Remove {
        /// Wallet name to remove
        name: String,
    },
    /// Rename a wallet
    Rename { old_name: String, new_name: String },
    /// Close a source account and send remaining XLM to a destination (account merge)
    Merge {
        /// Source wallet to close (must be saved in StarForge)
        #[arg(long)]
        from: String,
        /// Destination public key or wallet name that receives the balance
        #[arg(long)]
        to: String,
        /// Network to use (defaults to the source wallet's network)
        #[arg(long, value_parser = ["testnet", "mainnet"])]
        network: Option<String>,
        /// Skip the confirmation prompt
        #[arg(long, default_value = "false")]
        yes: bool,
        /// Remove the source wallet from local storage after a successful merge
        #[arg(long, default_value = "false")]
        remove_local: bool,
    },
    /// Rotate a wallet in place while keeping the same logical name
    Rotate {
        /// Wallet name to rotate
        name: String,
        /// Fund the new wallet via Friendbot immediately (testnet only)
        #[arg(long, default_value = "false")]
        fund: bool,
        /// Network to associate with the rotated wallet (overrides stored wallet network)
        #[arg(long, value_parser = ["testnet", "mainnet"])]
        network: Option<String>,
        /// Encrypt the replacement secret key with a passphrase at rest
        #[arg(long, default_value = "false")]
        encrypt: bool,
        /// Reject passphrases that score below "Strong" or reuse wallet details
        /// (requires --encrypt)
        #[arg(long, default_value = "false", requires = "encrypt")]
        strict: bool,
        /// Argon2 memory cost in KiB (requires --encrypt)
        #[arg(long, requires = "encrypt")]
        mem: Option<u32>,
        /// Argon2 iteration count (requires --encrypt)
        #[arg(long, requires = "encrypt")]
        iterations: Option<u32>,
        /// Argon2 parallelism factor (requires --encrypt)
        #[arg(long, requires = "encrypt")]
        parallelism: Option<u32>,
        /// Optional backup file path to save a snapshot before rotation
        #[arg(long)]
        backup: Option<PathBuf>,
    },
    /// Export a wallet to a JSON backup file
    Export {
        /// Optional wallet name to export (omit with --all)
        #[arg(long, conflicts_with = "all")]
        name: Option<String>,
        /// Export all wallets
        #[arg(long, short, conflicts_with = "name")]
        all: bool,
        /// Output file path for the backup JSON
        #[arg(long)]
        output: PathBuf,
        /// Reject passphrases that score below "Strong" or reuse wallet details
        #[arg(long, default_value = "false")]
        strict: bool,
    },
    /// Import a wallet from a JSON backup, BIP39 recovery phrase, or raw Stellar secret key
    Import {
        /// Wallet name (required with --mnemonic or --key)
        name: Option<String>,
        /// Path to backup JSON file
        #[arg(long, group = "source")]
        file: Option<PathBuf>,
        /// Import from a BIP39 recovery phrase (prompted interactively)
        #[arg(long, group = "source")]
        mnemonic: bool,
        /// Import from a raw Stellar secret key (starts with 'S', 56 characters)
        #[arg(long, group = "source")]
        key: Option<String>,
        /// Account index for SEP-0005 path m/44'/148'/index'
        #[arg(long, default_value = "0")]
        account_index: u32,
        /// Network to associate with this wallet
        #[arg(long, value_parser = ["testnet", "mainnet"])]
        network: Option<String>,
        /// Encrypt the imported secret key with a passphrase at rest
        #[arg(long, default_value = "false")]
        encrypt: bool,
        /// Reject passphrases that score below "Strong" or reuse wallet details
        /// (requires --encrypt)
        #[arg(long, default_value = "false", requires = "encrypt")]
        strict: bool,
    },

    /// Connect to a hardware wallet (Ledger/Trezor) and show device info
    Connect {
        #[arg(value_enum)]
        device: hardware_wallet::HardwareWalletKind,
    },

    /// Show the Stellar address derived from a connected hardware wallet
    HwAddress {
        /// Device type
        #[arg(value_enum)]
        device: hardware_wallet::HardwareWalletKind,
        /// HD derivation path (default: m/44'/148'/0')
        #[arg(long, default_value = hardware_wallet::STELLAR_HD_PATH)]
        path: String,
    },

    /// Show connection status of a hardware wallet without full connect
    HwStatus {
        #[arg(value_enum)]
        device: hardware_wallet::HardwareWalletKind,
    },

    /// Sign an arbitrary message using a local or hardware-backed key
    Sign {
        /// Wallet name to use (for local signing)
        name: String,
        /// Message to sign (utf-8)
        message: String,
        /// Use a hardware wallet instead of a local secret key
        #[arg(long, value_enum)]
        hardware: Option<hardware_wallet::HardwareWalletKind>,
    },
    /// Derive all 10 Stellar addresses (m/44'/148'/0..9') from a BIP39 recovery phrase
    Derive,
    /// Multi-signature account management
    #[command(subcommand)]
    Multisig(MultisigCommands),
}

#[derive(Subcommand)]
pub enum MultisigCommands {
    /// Create a multi-sig config for an existing wallet
    ///
    /// Example:
    /// starforge wallet multisig create treasury --threshold 2 --signers alice,bob,charlie
    Create {
        /// Wallet name to treat as the multi-sig account (e.g. "treasury")
        name: String,
        /// Required weight threshold to submit
        #[arg(long)]
        threshold: u8,
        /// Comma-separated wallet names to act as signers (e.g. alice,bob,charlie)
        #[arg(long)]
        signers: String,
        /// Override network for this config
        #[arg(long)]
        network: Option<String>,
        /// Optional file path to write a setup transaction JSON/XDR payload
        #[arg(long)]
        xdr_output: Option<PathBuf>,
    },
    /// Sign a multi-sig transaction JSON with all available local signer keys
    ///
    /// Example:
    /// starforge wallet multisig sign treasury --transaction tx.json
    Sign {
        /// Multi-sig account name (created via `multisig create`)
        name: String,
        /// Path to a MultiSigTransaction JSON file
        #[arg(long)]
        transaction: PathBuf,
        /// Output file (defaults to in-place update)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List multi-sig accounts stored locally
    List,
    /// Show a stored multi-sig account
    Show { name: String },
    /// Submit a fully-signed multi-sig transaction to Horizon
    ///
    /// Example:
    /// starforge wallet multisig submit treasury --transaction tx.json
    Submit {
        /// Multi-sig account name
        name: String,
        /// Path to a signed MultiSigTransaction JSON file
        #[arg(long)]
        transaction: PathBuf,
        /// Network to submit on (default: testnet)
        #[arg(long, value_parser = ["testnet", "mainnet", "docker-testnet"])]
        network: Option<String>,
    },
}

pub fn handle(cmd: WalletCommands) -> Result<()> {
    match cmd {
        WalletCommands::Create {
            name,
            fund,
            network,
            encrypt,
            strict,
            mnemonic: use_mnemonic,
            words,
            account_index,
            mem,
            iterations,
            parallelism,
        } => create(
            name,
            fund,
            network,
            encrypt,
            strict,
            use_mnemonic,
            words,
            account_index,
            mem,
            iterations,
            parallelism,
        ),
        WalletCommands::List => list(),
        WalletCommands::Show { name, reveal } => show(name, reveal),
        WalletCommands::Fund { name } => fund_wallet(name),
        WalletCommands::Remove { name } => remove(name),
        WalletCommands::Rename { old_name, new_name } => rename(old_name, new_name),
        WalletCommands::Merge {
            from,
            to,
            network,
            yes,
            remove_local,
        } => merge_wallet(from, to, network, yes, remove_local),
        WalletCommands::Rotate {
            name,
            fund,
            network,
            encrypt,
            strict,
            mem,
            iterations,
            parallelism,
            backup,
        } => rotate_wallet(
            name,
            fund,
            network,
            encrypt,
            strict,
            mem,
            iterations,
            parallelism,
            backup,
        ),
        WalletCommands::Export {
            name,
            all,
            output,
            strict,
        } => export_wallet(name, all, output, strict),
        WalletCommands::Import {
            name,
            file,
            mnemonic: from_mnemonic,
            key,
            account_index,
            network,
            encrypt,
            strict,
        } => import_wallet(
            name,
            file,
            from_mnemonic,
            key,
            account_index,
            network,
            encrypt,
            strict,
        ),
        WalletCommands::Connect { device } => connect_hardware(device),
        WalletCommands::HwAddress { device, path } => hw_address(device, &path),
        WalletCommands::HwStatus { device } => hw_status(device),
        WalletCommands::Sign {
            name,
            message,
            hardware,
        } => sign_message(name, message, hardware),
        WalletCommands::Derive => derive_addresses(),
        WalletCommands::Multisig(cmd) => handle_multisig(cmd),
    }
}

fn connect_hardware(device: hardware_wallet::HardwareWalletKind) -> Result<()> {
    p::header("Hardware Wallet â€” Connect");
    p::step(
        1,
        3,
        &format!("Initializing HID subsystem for {}â€¦", device),
    );
    let info = hardware_wallet::connect(device)?;
    p::step(
        2,
        3,
        &format!("{} HID device(s) visible", info.device_count),
    );
    p::step(3, 3, "Connection verified");
    println!();
    p::success(&format!("{} connected", device));
    p::kv("Devices visible", &info.device_count.to_string());
    p::kv("HD path", &info.hd_path);
    p::info("Run `starforge wallet hw-address <device>` to derive your Stellar address.");
    Ok(())
}

fn hw_address(device: hardware_wallet::HardwareWalletKind, path: &str) -> Result<()> {
    p::header("Hardware Wallet â€” Stellar Address");
    p::step(
        1,
        2,
        &format!("Requesting address from {} at {}", device, path),
    );
    let address = hardware_wallet::get_stellar_address(device, path)?;
    p::step(2, 2, "Address received");
    println!();
    p::kv("Device", &device.to_string());
    p::kv("HD Path", path);
    p::kv_accent("Stellar Address", &address);
    Ok(())
}

fn hw_status(device: hardware_wallet::HardwareWalletKind) -> Result<()> {
    p::header("Hardware Wallet â€” Status");
    let status = hardware_wallet::device_status(device)?;
    p::kv("Status", &status);
    Ok(())
}

fn sign_message(
    name: String,
    message: String,
    hardware: Option<hardware_wallet::HardwareWalletKind>,
) -> Result<()> {
    p::header("Sign Message");
    p::kv("Wallet", &name);

    let msg_bytes = message.as_bytes();

    if let Some(kind) = hardware {
        p::kv("Signer", &format!("{:?}", kind));
        let sig = hardware_wallet::sign(kind, msg_bytes)?;
        p::separator();
        p::kv_accent("Message", &message);
        p::kv("Signature (hex)", &hex::encode(sig));
        p::separator();
        return Ok(());
    }

    let cfg = config::load()?;
    let w = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    let sk = w
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' has no local secret key", name))?;

    let plain_sk = if !sk.contains(':') && sk.starts_with('S') && sk.len() == 56 {
        sk.clone()
    } else {
        let pwd = crypto::prompt_password(&format!("Enter password for wallet '{}'", name), false)?;
        crypto::decrypt_secret(&pwd, sk)
            .map_err(|_| anyhow::anyhow!("Incorrect password or unable to decrypt."))?
    };

    let decoded_secret = StellarPrivateKey::from_string(&plain_sk)?;
    let signing_key = SigningKey::from_bytes(&decoded_secret.0);
    let sig = signing_key.sign(msg_bytes);

    p::separator();
    p::kv_accent("Message", &message);
    p::kv("Signature (hex)", &hex::encode(sig.to_bytes()));
    p::separator();
    Ok(())
}

fn generate_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let public_key = StellarPublicKey(verifying_key.to_bytes()).to_string();
    let secret_key = StellarPrivateKey(seed).to_string();

    (public_key, secret_key)
}

fn parse_word_count(words: &str) -> Result<mnemonic::WordCount> {
    match words {
        "12" => Ok(mnemonic::WordCount::Words12),
        "24" => Ok(mnemonic::WordCount::Words24),
        _ => anyhow::bail!("--words must be 12 or 24"),
    }
}

fn prompt_recovery_phrase() -> Result<String> {
    use dialoguer::Input;
    let phrase: String = Input::new()
        .with_prompt("Enter recovery phrase (12 or 24 words)")
        .interact_text()
        .map_err(|e| anyhow::anyhow!("Failed to read recovery phrase: {}", e))?;
    if phrase.trim().is_empty() {
        anyhow::bail!("Recovery phrase cannot be empty");
    }
    Ok(phrase)
}

fn create(
    name: String,
    fund: bool,
    network_override: Option<String>,
    encrypt: bool,
    strict: bool,
    use_mnemonic: bool,
    words: String,
    account_index: u32,
    mem: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u32>,
) -> Result<()> {
    let mut cfg = config::load()?;

    config::validate_wallet_name(&name)?;

    if cfg.wallets.iter().any(|w| w.name == name) {
        anyhow::bail!("A wallet named '{}' already exists.", name);
    }

    let network = network_override.unwrap_or_else(|| cfg.network.clone());

    let steps = if fund { 3 } else { 2 };
    p::header(&format!("Creating wallet '{}'", name));

    let (public_key, secret_key) = if use_mnemonic {
        let word_count = parse_word_count(&words)?;
        p::step(
            1,
            steps,
            &format!("Generating {}-word recovery phrase…", word_count.as_usize()),
        );
        let phrase = mnemonic::generate_phrase(word_count)?;
        println!();
        p::warn("Write down this recovery phrase in order. Anyone with it can access your funds.");
        p::kv_accent("Recovery Phrase", &phrase);
        mnemonic::keypair_from_phrase(&phrase, "", account_index)?
    } else {
        p::step(1, steps, "Generating keypair…");
        generate_keypair()
    };
    println!();
    p::kv_accent("Public Key", &public_key);

    println!();
    let secret_to_store = if encrypt {
        if strict {
            p::info(&format!(
                "--strict mode active: passphrase must be {} characters or longer \
                 and score \"{}\" or better.",
                crypto::MIN_PASSPHRASE_LEN,
                "Strong"
            ));
        } else {
            p::info(&format!(
                "Passphrase must be at least {} characters. \
                 Add --strict to enforce a stronger passphrase.",
                crypto::MIN_PASSPHRASE_LEN
            ));
        }
        println!();
        let context = [name.as_str(), public_key.as_str(), network.as_str()];
        let pwd = crypto::prompt_passphrase_with_inputs(
            "Set a passphrase to encrypt this wallet",
            strict,
            &context,
        )?;
        crypto::encrypt_secret(
            &pwd,
            &secret_key,
            kdf_options(mem, iterations, parallelism, cfg.wallet_encryption.as_ref()).as_ref(),
        )?
    } else {
        secret_key.clone()
    };

    let status = if encrypt {
        "Encrypted and safely stored."
    } else {
        "Stored in plaintext (not recommended for mainnet)."
    };
    p::kv("Secret Key", status);
    println!();

    p::step(2, steps, "Saving to ~/.starforge/config.tomlâ€¦");
    let wallet = config::WalletEntry {
        name: name.clone(),
        public_key: public_key.clone(),
        secret_key: Some(secret_to_store),
        network: network.clone(),
        created_at: Utc::now().to_rfc3339(),
        funded: false,
        rotation_history: Vec::new(),
    };
    cfg.wallets.push(wallet);

    if fund {
        let net_cfg = config::get_network_config(&cfg, &network)?;
        if net_cfg.friendbot_url.is_none() && network == "mainnet" {
            p::warn("Friendbot is not available on Mainnet. Skipping fund step.");
        } else {
            p::step(3, steps, "Funding via network faucet…");
            match horizon::fund_account(&public_key, &network) {
                Ok(_) => {
                    if let Some(w) = cfg.wallets.iter_mut().find(|w| w.name == name) {
                        w.funded = true;
                    }
                    p::success("Account funded via configured faucet");
                }
                Err(e) => p::warn(&format!("Funding failed: {}", e)),
            }
        }
    }

    config::save(&cfg)?;
    println!();
    p::success(&format!("Wallet '{}' created and saved!", name));
    p::info(&format!(
        "View it with: {}",
        format!("starforge wallet show {}", name).cyan()
    ));
    Ok(())
}

fn list() -> Result<()> {
    let cfg = config::load()?;

    p::header("Saved Wallets");

    if cfg.wallets.is_empty() {
        p::info(&format!(
            "No wallets yet on {}. Run `starforge wallet create <name>` to get started.",
            cfg.network
        ));
        return Ok(());
    }

    p::separator();

    for (i, w) in cfg.wallets.iter().enumerate() {
        let status = if w.funded {
            "funded".green()
        } else {
            "unfunded".dimmed()
        };

        println!("  {:>2}. {} [{}]", i + 1, w.name.bold(), status);
        p::kv("Key", &w.public_key);
        p::kv("Net", &w.network);

        if i < cfg.wallets.len() - 1 {
            println!();
        }
    }

    p::separator();
    p::kv(
        &format!("{} wallet(s)", cfg.wallets.len()),
        &format!("on {} â€” {}", cfg.network, config::config_path().display()),
    );

    Ok(())
}

fn show(name: String, reveal: bool) -> Result<()> {
    let cfg = config::load()?;
    let w = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    p::header(&format!("Wallet: {}", w.name));
    p::separator();
    p::kv_accent("Public Key", &w.public_key);

    if reveal {
        if let Some(sk) = &w.secret_key {
            // Check if it's plaintext
            if !sk.contains(':') && sk.starts_with('S') && sk.len() == 56 {
                p::warn("Warning: This wallet is using an unencrypted legacy key!");
                p::kv("Secret Key", sk);
            } else {
                let pwd = crypto::prompt_password(
                    &format!("Enter password for wallet '{}'", name),
                    false,
                )?;
                match crypto::decrypt_secret(&pwd, sk) {
                    Ok(plain_sk) => p::kv("Secret Key", &plain_sk),
                    Err(_) => anyhow::bail!("Incorrect password or unable to decrypt."),
                }
            }
        }
    } else {
        p::kv(
            "Secret Key",
            &format!("{} (--reveal to show)", "*".repeat(20)),
        );
    }

    p::kv("Network", &w.network);
    p::kv("Funded", if w.funded { "yes" } else { "no" });
    p::kv("Created", &w.created_at);
    if !w.rotation_history.is_empty() {
        p::kv("Rotations", &w.rotation_history.len().to_string());
        if let Some(last_rotation) = w.rotation_history.last() {
            p::kv("Previous Key", &last_rotation.previous_public_key);
            p::kv("Rotated At", &last_rotation.rotated_at);
        }
    }
    p::separator();

    p::info(&format!("Fetching live balance on {}â€¦", w.network));
    match horizon::fetch_account(&w.public_key, &w.network) {
        Ok(account) => {
            println!();
            for bal in &account.balances {
                let asset = bal.asset_code.as_deref().unwrap_or("XLM");
                p::kv_accent(asset, &format!("{} {}", bal.balance, asset));
            }
        }
        Err(_) => {
            p::warn("Account not yet active on-chain. Fund it with `starforge wallet fund`");
        }
    }
    Ok(())
}

fn fund_wallet(name: String) -> Result<()> {
    config::validate_wallet_name(&name)?;
    let mut cfg = config::load()?;

    if cfg.network == "mainnet" {
        let net_cfg = config::get_network_config(&cfg, &cfg.network)?;
        if net_cfg.friendbot_url.is_none() {
            anyhow::bail!("Friendbot is not available on Mainnet.");
        }
    }

    let public_key = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .map(|w| w.public_key.clone())
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    p::info(&format!(
        "Funding '{}' via configured network faucet…",
        name
    ));
    horizon::fund_account(&public_key, &cfg.network)?;

    if let Some(w) = cfg.wallets.iter_mut().find(|w| w.name == name) {
        w.funded = true;
    }
    config::save(&cfg)?;

    println!();
    p::success("Account funded with 10,000 XLM on testnet!");
    p::kv_accent("Public Key", &public_key);
    Ok(())
}

fn remove(name: String) -> Result<()> {
    config::validate_wallet_name(&name)?;
    let mut cfg = config::load()?;
    let before = cfg.wallets.len();
    cfg.wallets.retain(|w| w.name != name);

    if cfg.wallets.len() == before {
        anyhow::bail!("No wallet named '{}' found", name);
    }

    config::save(&cfg)?;
    p::success(&format!("Wallet '{}' removed", name));
    Ok(())
}
fn resolve_merge_destination(to: &str, cfg: &config::Config) -> Result<String> {
    if to.starts_with('G') {
        config::validate_public_key(to)?;
        return Ok(to.to_string());
    }

    config::validate_wallet_name(to)?;
    cfg.wallets
        .iter()
        .find(|w| w.name == to)
        .map(|w| w.public_key.clone())
        .ok_or_else(|| anyhow::anyhow!("Destination wallet '{}' not found", to))
}

fn wallet_secret_key(wallet: &config::WalletEntry) -> Result<String> {
    let sk = wallet
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' has no secret key stored", wallet.name))?;

    if sk.contains(':') {
        let pwd = crypto::prompt_password(
            &format!("Enter password to decrypt wallet '{}'", wallet.name),
            false,
        )?;
        crypto::decrypt_secret(&pwd, sk)
            .map_err(|_| anyhow::anyhow!("Incorrect password or unable to decrypt."))
    } else {
        Ok(sk.clone())
    }
}

fn validate_account_mergeable(account: &horizon::AccountResponse) -> Result<()> {
    for balance in &account.balances {
        if balance.asset_type == "native" {
            continue;
        }
        let amount: f64 = balance.balance.parse().unwrap_or(0.0);
        if amount > 0.0 {
            let label = balance.asset_code.as_deref().unwrap_or(&balance.asset_type);
            anyhow::bail!(
                "Cannot merge: account still holds {} {}. Remove trustlines and balances first.",
                balance.balance,
                label
            );
        }
    }

    if account.subentry_count > 0 {
        anyhow::bail!(
            "Cannot merge: account has {} subentries (trustlines, signers, data, etc.). \
             Remove them before merging.",
            account.subentry_count
        );
    }

    Ok(())
}

fn native_xlm_balance(account: &horizon::AccountResponse) -> f64 {
    account
        .balances
        .iter()
        .find(|b| b.asset_type == "native")
        .and_then(|b| b.balance.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn merge_wallet(
    from: String,
    to: String,
    network_override: Option<String>,
    skip_confirm: bool,
    remove_local: bool,
) -> Result<()> {
    config::validate_wallet_name(&from)?;

    let cfg = config::load()?;
    let wallet = cfg.wallets.iter().find(|w| w.name == from).ok_or_else(|| {
        anyhow::anyhow!(
            "Wallet '{}' not found in StarForge. Run `starforge wallet list`",
            from
        )
    })?;

    let network = network_override
        .clone()
        .unwrap_or_else(|| wallet.network.clone());
    config::validate_network(&network)?;

    let destination = resolve_merge_destination(&to, &cfg)?;

    if wallet.public_key == destination {
        anyhow::bail!("Source and destination accounts must be different");
    }

    p::header("Account Merge");
    p::warn("This permanently closes the source account on-chain. This cannot be undone.");
    p::separator();
    p::kv("Source Wallet", &wallet.name);
    p::kv("Source Address", &wallet.public_key);
    p::kv("Destination", &destination);
    p::kv("Network", &network);

    if network == "mainnet" {
        p::warn("You are merging on MAINNET. All remaining XLM will move to the destination.");
    }

    p::separator();
    println!();
    p::step(1, 3, "Fetching source account…");
    let source_account = horizon::fetch_account(&wallet.public_key, &network).map_err(|e| {
        anyhow::anyhow!(
            "Source account not found on {}: {}\nIt may already be merged or never funded.",
            network,
            e
        )
    })?;

    validate_account_mergeable(&source_account)?;
    let xlm_balance = native_xlm_balance(&source_account);
    p::kv(
        "XLM to Transfer",
        &format!("{:.7} XLM (minus fee)", xlm_balance),
    );

    if xlm_balance <= 0.00001 {
        anyhow::bail!("Source account has insufficient XLM to cover transaction fees");
    }

    p::step(2, 3, "Validating destination account…");
    horizon::fetch_account(&destination, &network).map_err(|_| {
        anyhow::anyhow!(
            "Destination account does not exist on {}. \
             The destination must be funded before it can receive a merge.",
            network
        )
    })?;
    p::kv("Destination", "✓ Account exists");

    p::step(3, 3, "Building account merge transaction…");
    let tx_result = horizon::build_and_simulate_account_merge(
        &wallet.public_key,
        &destination,
        &source_account.sequence,
        &network,
    )?;

    p::kv(
        "Estimated Fee",
        &format!("{:.7} XLM", tx_result.fee as f64 / 10_000_000.0),
    );

    // Build operation summary for confirmation
    let risk_level = if network == "mainnet" {
        confirmation::RiskLevel::High
    } else {
        confirmation::RiskLevel::Medium
    };

    let summary = confirmation::OperationSummary::new(
        "Account Merge".to_string(),
        network.clone(),
        risk_level,
    )
    .add("Source Wallet", &wallet.name)
    .add("Source Address", &wallet.public_key)
    .add("Destination", &destination)
    .add(
        "XLM to Transfer",
        format!("{:.7} XLM (minus fee)", xlm_balance),
    )
    .add(
        "Estimated Fee",
        format!("{:.7} XLM", tx_result.fee as f64 / 10_000_000.0),
    )
    .add("Remove Local", if remove_local { "Yes" } else { "No" });

    let confirm_config = confirmation::ConfirmationConfig {
        risk_level,
        network: network.clone(),
        skip_confirm,
        dry_run: false,
        prompt: Some(format!(
            "Type '{}' to confirm merge of account {}:",
            wallet.name, wallet.name
        )),
        require_type_confirmation: true, // Always require type confirmation for merge
    };

    if !confirmation::confirm_operation(&summary, &confirm_config)? {
        return Ok(());
    }

    println!();
    let secret_key = wallet_secret_key(wallet)?;
    p::info("Submitting account merge…");
    let submit_result =
        horizon::submit_payment_transaction(&tx_result.transaction_xdr, &secret_key, &network)?;

    println!();
    p::separator();
    println!(
        "  {} {}",
        "✓".green().bold(),
        "Account merge submitted successfully!".bright_white()
    );
    println!();
    p::kv_accent("Transaction Hash", &submit_result.hash);

    let explorer_base = if network == "mainnet" {
        "https://stellar.expert/explorer/public/tx"
    } else {
        "https://stellar.expert/explorer/testnet/tx"
    };
    p::kv(
        "Stellar Expert",
        &format!("{}/{}", explorer_base, submit_result.hash),
    );
    p::separator();

    if remove_local {
        let mut cfg = config::load()?;
        let before = cfg.wallets.len();
        cfg.wallets.retain(|w| w.name != from);
        if cfg.wallets.len() < before {
            config::save(&cfg)?;
            p::success(&format!("Removed wallet '{}' from local storage", from));
        }
    } else {
        p::info(&format!(
            "Local wallet '{}' is still saved. Remove it with: {}",
            from,
            format!("starforge wallet remove {}", from).cyan()
        ));
    }

    Ok(())
}

fn rename(old_name: String, new_name: String) -> Result<()> {
    config::validate_wallet_name(&old_name)?;
    config::validate_wallet_name(&new_name)?;

    let mut cfg = config::load()?;
    if !cfg.wallets.iter().any(|w| w.name == old_name) {
        anyhow::bail!("No wallet named '{}' found", old_name);
    }

    if cfg.wallets.iter().any(|w| w.name == new_name) {
        anyhow::bail!("A wallet named '{}' already exists", new_name);
    }
    if let Some(w) = cfg.wallets.iter_mut().find(|w| w.name == old_name) {
        w.name = new_name.clone();
    }

    config::save(&cfg)?;
    println!();
    p::success(&format!("Wallet renamed: '{}' ? '{}'", old_name, new_name));
    p::info(&format!(
        "View it with: {}",
        format!("starforge wallet show {}", new_name).cyan()
    ));
    Ok(())
}

fn rotate_wallet(
    name: String,
    fund: bool,
    network_override: Option<String>,
    encrypt: bool,
    strict: bool,
    mem: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u32>,
    backup: Option<PathBuf>,
) -> Result<()> {
    config::validate_wallet_name(&name)?;
    let mut cfg = config::load()?;
    let wallet_index = cfg
        .wallets
        .iter()
        .position(|wallet| wallet.name == name)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    let stored_network = cfg.wallets[wallet_index].network.clone();
    let original_public_key = cfg.wallets[wallet_index].public_key.clone();
    let original_secret_key = cfg.wallets[wallet_index].secret_key.clone();
    let original_funded = cfg.wallets[wallet_index].funded;
    let network = network_override.unwrap_or(stored_network);

    let preserve_secret = backup.is_some();
    let steps = if fund { 4 } else { 3 };
    p::header(&format!("Rotating wallet '{}'", name));
    p::kv("Old Public Key", &original_public_key);
    p::kv("Network", &network);

    // ── Step 1: optional pre-rotation backup snapshot ────────────────────────
    if let Some(ref backup_path) = backup {
        p::step(1, steps, "Writing pre-rotation backup snapshot...");
        let snapshot = WalletBackup {
            version: WALLET_BACKUP_VERSION.to_string(),
            exported_at: Utc::now().to_rfc3339(),
            wallets: vec![WalletBackupEntry::from(&cfg.wallets[wallet_index])],
        };
        let json = serde_json::to_string_pretty(&snapshot)
            .context("Failed to serialize backup snapshot")?;
        if let Some(parent) = backup_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create {}", parent.display()))?;
            }
        }
        let passphrase =
            crypto::prompt_passphrase("Set a passphrase to encrypt the backup snapshot", false)?;
        let encrypted = crypto::encrypt_secret(&passphrase, &json, None)?;
        fs::write(backup_path, encrypted)
            .with_context(|| format!("Failed to write backup to {}", backup_path.display()))?;
        p::success(&format!("Backup written to {}", backup_path.display()));
        p::info("Keep this file safe — it contains the previous secret key.");
    } else {
        p::step(
            1,
            steps,
            "Skipping backup (pass --backup <file> to save a snapshot)...",
        );
    }

    p::step(2, steps, "Generating replacement keypair...");
    let (public_key, secret_key) = generate_keypair();

    let secret_to_store = if encrypt {
        let context = [
            name.as_str(),
            original_public_key.as_str(),
            public_key.as_str(),
            network.as_str(),
        ];
        let pwd = crypto::prompt_passphrase_with_inputs(
            "Set a secure passphrase to encrypt the rotated wallet",
            strict,
            &context,
        )?;
        crypto::encrypt_secret(
            &pwd,
            &secret_key,
            kdf_options(mem, iterations, parallelism, cfg.wallet_encryption.as_ref()).as_ref(),
        )?
    } else {
        secret_key.clone()
    };

    p::step(
        3,
        steps,
        "Archiving previous keypair in rotation history...",
    );
    {
        let wallet = &mut cfg.wallets[wallet_index];
        wallet.rotation_history.push(config::WalletRotationRecord {
            rotated_at: Utc::now().to_rfc3339(),
            previous_public_key: original_public_key.clone(),
            previous_network: wallet.network.clone(),
            previous_funded: wallet.funded,
            previous_secret_key: if preserve_secret {
                original_secret_key
            } else {
                None
            },
        });
        wallet.public_key = public_key.clone();
        wallet.secret_key = Some(secret_to_store);
        wallet.network = network.clone();
        wallet.funded = false;
    }

    if fund {
        if network == "mainnet" {
            p::warn("Friendbot is not available on Mainnet. Skipping fund step.");
        } else {
            p::step(4, steps, "Funding the replacement wallet via Friendbot...");
            match horizon::fund_account(&public_key, &network) {
                Ok(_) => {
                    if let Some(wallet) = cfg.wallets.iter_mut().find(|wallet| wallet.name == name)
                    {
                        wallet.funded = true;
                    }
                    p::success("Replacement wallet funded on testnet");
                }
                Err(e) => p::warn(&format!("Funding failed: {}", e)),
            }
        }
    }

    config::save(&cfg)?;

    println!();
    p::success(&format!("Wallet '{}' rotated", name));
    p::kv_accent("New Public Key", &public_key);
    p::warn(
        "The wallet name stayed the same, but the on-chain account changed. Update any funding, signer, or deploy flows that referenced the old public key.",
    );
    if original_funded {
        p::info("The previous key remains an on-chain account; rotation only updates the local wallet mapping.");
    }
    if preserve_secret {
        p::info("Previous secret key preserved in rotation history. View with: starforge wallet history <name> --reveal");
    }
    Ok(())
}

fn wallet_history(name: String, reveal: bool) -> Result<()> {
    config::validate_wallet_name(&name)?;
    let cfg = config::load()?;
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    p::header(&format!("Rotation history for '{}'", name));
    p::kv_accent("Current Public Key", &wallet.public_key);
    p::kv("Network", &wallet.network);
    p::kv("Funded", if wallet.funded { "yes" } else { "no" });

    if wallet.rotation_history.is_empty() {
        println!();
        p::info("No rotations recorded. This wallet has never been rotated.");
        return Ok(());
    }

    p::kv(
        "Total rotations",
        &wallet.rotation_history.len().to_string(),
    );
    p::separator();

    for (i, record) in wallet.rotation_history.iter().enumerate().rev() {
        println!("  Rotation #{}", i + 1);
        p::kv("  Rotated At", &record.rotated_at);
        p::kv("  Previous Public Key", &record.previous_public_key);
        p::kv("  Previous Network", &record.previous_network);
        p::kv(
            "  Was Funded",
            if record.previous_funded { "yes" } else { "no" },
        );

        match &record.previous_secret_key {
            Some(sk) if reveal => {
                if sk.contains(':') {
                    // Encrypted bundle — prompt for passphrase
                    let pwd = crypto::prompt_password(
                        &format!(
                            "Enter passphrase to decrypt previous key for rotation #{}",
                            i + 1
                        ),
                        false,
                    )?;
                    match crypto::decrypt_secret(&pwd, sk) {
                        Ok(plain) => p::kv("  Previous Secret Key", &plain),
                        Err(_) => {
                            p::warn("  Could not decrypt previous secret key (wrong passphrase?)")
                        }
                    }
                } else {
                    p::kv("  Previous Secret Key", sk);
                }
            }
            Some(_) => {
                p::kv("  Previous Secret Key", "(stored — use --reveal to show)");
            }
            None => {
                p::kv(
                    "  Previous Secret Key",
                    "(not preserved — use --backup on next rotation)",
                );
            }
        }

        if i > 0 {
            println!();
        }
    }

    p::separator();
    p::info("To export a full backup: starforge wallet export --name <name> --output backup.json");
    Ok(())
}

fn export_wallet(name_opt: Option<String>, all: bool, output: PathBuf, strict: bool) -> Result<()> {
    let cfg = config::load()?;
    let wallets_to_export: Vec<WalletBackupEntry> = if all {
        cfg.wallets
            .iter()
            .map(|w| WalletBackupEntry::from(w))
            .collect()
    } else {
        let name = name_opt
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Wallet name must be provided unless --all is used"))?;
        config::validate_wallet_name(name)?;
        let wallet = cfg
            .wallets
            .iter()
            .find(|w| &w.name == name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;
        vec![WalletBackupEntry::from(wallet)]
    };

    if output.exists() && output.is_dir() {
        anyhow::bail!("Output path is a directory: {}", output.display());
    }
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
    }

    let backup = WalletBackup {
        version: WALLET_BACKUP_VERSION.to_string(),
        exported_at: Utc::now().to_rfc3339(),
        wallets: wallets_to_export,
    };

    let context: Vec<&str> = backup
        .wallets
        .iter()
        .flat_map(|wallet| {
            [
                wallet.name.as_str(),
                wallet.public_key.as_str(),
                wallet.network.as_str(),
            ]
        })
        .collect();

    let json = serde_json::to_string_pretty(&backup)
        .with_context(|| "Failed to serialize wallet backup")?;
    let passphrase = crypto::prompt_passphrase_with_inputs(
        "Enter passphrase to encrypt backup",
        strict,
        &context,
    )?;
    let encrypted = crypto::encrypt_secret(&passphrase, &json, None)?;
    fs::write(&output, encrypted)
        .with_context(|| format!("Failed to write {}", output.display()))?;

    let name_display = if all {
        "all wallets".to_string()
    } else {
        name_opt.clone().unwrap()
    };
    p::success(&format!("Wallet(s) {} exported", name_display));
    p::kv("Backup file", &output.display().to_string());
    p::info("Secrets are only stored in the backup file; they are not printed to stdout.");
    Ok(())
}

fn import_wallet(
    name: Option<String>,
    file: Option<PathBuf>,
    from_mnemonic: bool,
    key: Option<String>,
    account_index: u32,
    network_override: Option<String>,
    encrypt: bool,
    strict: bool,
) -> Result<()> {
    if from_mnemonic {
        let name = name.ok_or_else(|| {
            anyhow::anyhow!("Wallet name is required for mnemonic import (e.g. starforge wallet import alice --mnemonic)")
        })?;
        return import_from_mnemonic(name, account_index, network_override, encrypt, strict);
    }

    if let Some(secret_key) = key {
        let name = name.ok_or_else(|| {
            anyhow::anyhow!(
                "Wallet name is required when using --key (e.g. starforge wallet import alice --key SXXX...)"
            )
        })?;
        return import_from_secret_key(name, secret_key, network_override, encrypt);
    }

    let file = file.ok_or_else(|| {
        anyhow::anyhow!(
            "Provide --file <backup.json>, --mnemonic, or --key <SXXX...> to import a wallet"
        )
    })?;
    import_wallets(file)
}

fn import_from_mnemonic(
    name: String,
    account_index: u32,
    network_override: Option<String>,
    encrypt: bool,
    strict: bool,
) -> Result<()> {
    let mut cfg = config::load()?;
    config::validate_wallet_name(&name)?;

    if cfg.wallets.iter().any(|w| w.name == name) {
        anyhow::bail!("A wallet named '{}' already exists.", name);
    }

    let network = network_override.unwrap_or_else(|| cfg.network.clone());
    p::header(&format!("Importing wallet '{}' from recovery phrase", name));

    let phrase = prompt_recovery_phrase()?;
    let (public_key, secret_key) = mnemonic::keypair_from_phrase(&phrase, "", account_index)?;

    println!();
    p::kv_accent("Public Key", &public_key);

    let secret_to_store = if encrypt {
        println!();
        let context = [name.as_str(), public_key.as_str(), network.as_str()];
        let pwd = crypto::prompt_passphrase_with_inputs(
            "Set a passphrase to encrypt this wallet",
            strict,
            &context,
        )?;
        crypto::encrypt_secret(&pwd, &secret_key, None)?
    } else {
        secret_key
    };

    cfg.wallets.push(config::WalletEntry {
        name: name.clone(),
        public_key,
        secret_key: Some(secret_to_store),
        network: network.clone(),
        created_at: Utc::now().to_rfc3339(),
        funded: false,
        rotation_history: Vec::new(),
    });

    config::save(&cfg)?;
    p::success(&format!("Wallet '{}' imported from recovery phrase", name));
    p::info(&format!(
        "View it with: {}",
        format!("starforge wallet show {}", name).cyan()
    ));
    Ok(())
}

fn import_from_secret_key(
    name: String,
    secret_key: String,
    network_override: Option<String>,
    encrypt: bool,
) -> Result<()> {
    if secret_key.contains(':') {
        anyhow::bail!(
            "--key expects a raw Stellar secret key (starts with 'S', 56 characters), \
             not an encrypted bundle. Use --file to import an encrypted backup."
        );
    }
    config::validate_secret_key(&secret_key)?;

    let mut cfg = config::load()?;
    config::validate_wallet_name(&name)?;

    if cfg.wallets.iter().any(|w| w.name == name) {
        anyhow::bail!("A wallet named '{}' already exists.", name);
    }

    let decoded_secret = StellarPrivateKey::from_string(&secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Stellar secret key format"))?;
    let signing_key = SigningKey::from_bytes(&decoded_secret.0);
    let public_key = StellarPublicKey(signing_key.verifying_key().to_bytes()).to_string();

    let network = network_override.unwrap_or_else(|| cfg.network.clone());

    p::header(&format!("Importing wallet '{}' from secret key", name));
    p::kv_accent("Public Key", &public_key);

    let secret_to_store = if encrypt {
        println!();
        let pwd = crypto::prompt_passphrase("Set a passphrase to encrypt this wallet", false)?;
        crypto::encrypt_secret(&pwd, &secret_key, None)?
    } else {
        secret_key
    };

    cfg.wallets.push(config::WalletEntry {
        name: name.clone(),
        public_key,
        secret_key: Some(secret_to_store),
        network,
        created_at: Utc::now().to_rfc3339(),
        funded: false,
        rotation_history: Vec::new(),
    });

    config::save(&cfg)?;
    p::success(&format!("Wallet '{}' imported from secret key", name));
    p::info(&format!(
        "View it with: {}",
        format!("starforge wallet show {}", name).cyan()
    ));
    Ok(())
}

fn import_wallets(file: PathBuf) -> Result<()> {
    config::validate_file_path(&file, Some("json"))?;
    let raw_contents =
        fs::read_to_string(&file).with_context(|| format!("Failed to read {}", file.display()))?;
    // Detect encrypted format (salt:nonce:ciphertext)
    let contents = if raw_contents.matches(':').count() == 2 {
        let passphrase = crypto::prompt_password("Enter passphrase to decrypt backup", false)?;
        crypto::decrypt_secret(&passphrase, &raw_contents)?
    } else {
        raw_contents
    };
    let backup: WalletBackup =
        serde_json::from_str(&contents).with_context(|| "Invalid backup JSON format")?;

    if backup.version != WALLET_BACKUP_VERSION {
        anyhow::bail!(
            "Unsupported backup version '{}'. Expected '{}'.",
            backup.version,
            WALLET_BACKUP_VERSION
        );
    }

    if backup.wallets.is_empty() {
        anyhow::bail!("Backup file contains no wallets.");
    }

    let mut seen = HashSet::new();
    for wallet in &backup.wallets {
        if !seen.insert(wallet.name.clone()) {
            anyhow::bail!("Duplicate wallet '{}' in backup file", wallet.name);
        }
    }

    let mut cfg = config::load()?;

    for wallet in &backup.wallets {
        config::validate_wallet_name(&wallet.name)?;
        config::validate_public_key(&wallet.public_key)?;
        if let Some(secret) = &wallet.secret_key {
            config::validate_secret_key(secret)?;
        }
        config::validate_network_exists(&cfg, &wallet.network)?;

        if cfg.wallets.iter().any(|w| w.name == wallet.name) {
            anyhow::bail!("Wallet '{}' already exists", wallet.name);
        }
    }

    let imported = backup.wallets.len();
    for wallet in backup.wallets {
        cfg.wallets.push(config::WalletEntry {
            name: wallet.name,
            public_key: wallet.public_key,
            secret_key: wallet.secret_key,
            network: wallet.network,
            created_at: wallet.created_at,
            funded: wallet.funded,
            rotation_history: Vec::new(),
        });
    }

    config::save(&cfg)?;
    p::success(&format!(
        "Imported {} wallet(s) from {}",
        imported,
        file.display()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::generate_keypair;
    use crate::utils::config::{WalletEntry, WalletRotationRecord};
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use std::collections::HashSet;
    use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};

    #[test]
    fn generates_valid_unique_stellar_ed25519_keypairs() {
        let mut public_keys = HashSet::new();
        let mut secret_keys = HashSet::new();
        let message = b"starforge wallet keypair validation";

        for _ in 0..1000 {
            let (public_key, secret_key) = generate_keypair();

            assert!(public_key.starts_with('G'));
            assert!(secret_key.starts_with('S'));
            assert!(public_keys.insert(public_key.clone()));
            assert!(secret_keys.insert(secret_key.clone()));

            let decoded_public = StellarPublicKey::from_string(&public_key).unwrap();
            let decoded_secret = StellarPrivateKey::from_string(&secret_key).unwrap();

            assert_eq!(decoded_public.to_string(), public_key);
            assert_eq!(decoded_secret.to_string(), secret_key);

            let signing_key = SigningKey::from_bytes(&decoded_secret.0);
            let verifying_key = VerifyingKey::from_bytes(&decoded_public.0).unwrap();

            assert_eq!(signing_key.verifying_key().to_bytes(), decoded_public.0);

            let signature = signing_key.sign(message);
            verifying_key.verify(message, &signature).unwrap();
        }
    }

    // ── Rotation history / backup tests ─────────────────────────────────────

    fn make_wallet(name: &str, public_key: &str) -> WalletEntry {
        WalletEntry {
            name: name.to_string(),
            public_key: public_key.to_string(),
            secret_key: Some(
                "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ),
            network: "testnet".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            funded: true,
            rotation_history: vec![],
        }
    }

    #[test]
    fn rotation_record_without_backup_has_no_secret() {
        let record = WalletRotationRecord {
            rotated_at: "2025-06-01T00:00:00Z".to_string(),
            previous_public_key: "GABC".to_string(),
            previous_network: "testnet".to_string(),
            previous_funded: true,
            previous_secret_key: None,
        };
        assert!(record.previous_secret_key.is_none());
    }

    #[test]
    fn rotation_record_with_backup_preserves_secret() {
        let secret = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let record = WalletRotationRecord {
            rotated_at: "2025-06-01T00:00:00Z".to_string(),
            previous_public_key: "GABC".to_string(),
            previous_network: "testnet".to_string(),
            previous_funded: true,
            previous_secret_key: Some(secret.to_string()),
        };
        assert_eq!(record.previous_secret_key.as_deref(), Some(secret));
    }

    #[test]
    fn rotation_history_accumulates_across_multiple_rotations() {
        let mut wallet = make_wallet("alice", "GABC");

        // Simulate two rotations
        for i in 0..2 {
            wallet.rotation_history.push(WalletRotationRecord {
                rotated_at: format!("2025-0{}-01T00:00:00Z", i + 1),
                previous_public_key: format!("GPREV{}", i),
                previous_network: "testnet".to_string(),
                previous_funded: false,
                previous_secret_key: Some(format!("SPREV{}", i)),
            });
        }

        assert_eq!(wallet.rotation_history.len(), 2);
        assert_eq!(wallet.rotation_history[0].previous_public_key, "GPREV0");
        assert_eq!(wallet.rotation_history[1].previous_public_key, "GPREV1");
    }

    #[test]
    fn rotation_record_serialises_without_secret_when_none() {
        let record = WalletRotationRecord {
            rotated_at: "2025-06-01T00:00:00Z".to_string(),
            previous_public_key: "GABC".to_string(),
            previous_network: "testnet".to_string(),
            previous_funded: false,
            previous_secret_key: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        // previous_secret_key should be omitted entirely (skip_serializing_if)
        assert!(!json.contains("previous_secret_key"));
    }

    #[test]
    fn rotation_record_serialises_with_secret_when_present() {
        let record = WalletRotationRecord {
            rotated_at: "2025-06-01T00:00:00Z".to_string(),
            previous_public_key: "GABC".to_string(),
            previous_network: "testnet".to_string(),
            previous_funded: false,
            previous_secret_key: Some("SKEY".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("previous_secret_key"));
        assert!(json.contains("SKEY"));
    }
}

fn derive_addresses() -> Result<()> {
    p::header("Derive Stellar Addresses from Mnemonic");
    p::info("Enter your BIP39 recovery phrase to derive all 10 Stellar addresses.");
    println!();

    let phrase = prompt_recovery_phrase()?;
    let passphrase = "";

    println!();
    p::step(1, 2, "Validating recovery phrase…");
    let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    let _ = Mnemonic::parse_in(Language::English, normalized)
        .map_err(|e| anyhow::anyhow!("Invalid recovery phrase: {}", e))?;
    p::success("Recovery phrase is valid");

    println!();
    p::step(2, 2, "Deriving addresses for account indices 0-9…");
    println!();
    p::separator();

    for account_index in 0..10 {
        let result = mnemonic::keypair_from_phrase(&phrase, passphrase, account_index);

        match result {
            Ok((public_key, _)) => {
                let derivation_path = format!("m/44'/148'/{}'", account_index);
                p::kv(&format!("[{}]", account_index), &derivation_path);
                p::kv_accent(&format!("    Address {}", account_index), &public_key);
                println!();
            }
            Err(e) => {
                p::warn(&format!(
                    "Failed to derive account {}: {}",
                    account_index, e
                ));
                println!();
            }
        }
    }

    p::separator();
    p::info(
        "These addresses are derived deterministically from your recovery phrase. \
         Entering the same phrase will always produce the same addresses.",
    );
    p::warn("Do not share your recovery phrase with anyone. Anyone with it can access all these addresses.");
    Ok(())
}

fn handle_multisig(cmd: MultisigCommands) -> Result<()> {
    match cmd {
        MultisigCommands::Create {
            name,
            threshold,
            signers,
            network,
            xdr_output,
        } => multisig_create(name, threshold, signers, network, xdr_output),
        MultisigCommands::Sign {
            name,
            transaction,
            output,
        } => multisig_sign(name, transaction, output),
        MultisigCommands::List => multisig_list(),
        MultisigCommands::Show { name } => multisig_show(name),
        MultisigCommands::Submit {
            name,
            transaction,
            network,
        } => multisig_submit(name, transaction, network),
    }
}

fn multisig_create(
    name: String,
    threshold: u8,
    signers: String,
    network: Option<String>,
    xdr_output: Option<PathBuf>,
) -> Result<()> {
    config::validate_wallet_name(&name)?;
    multisig::validate_threshold(threshold)?;

    let cfg = config::load()?;
    let wallet = cfg.wallets.iter().find(|w| w.name == name).ok_or_else(|| {
        anyhow::anyhow!(
            "Wallet '{}' not found. Create it first with `starforge wallet create {}`",
            name,
            name
        )
    })?;

    let network = network.unwrap_or_else(|| wallet.network.clone());
    config::validate_network(&network)?;

    let signer_names: Vec<String> = signers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if signer_names.is_empty() {
        anyhow::bail!("Provide at least one signer wallet via --signers alice,bob,...");
    }

    let mut signer_entries = Vec::new();
    for signer_name in signer_names {
        config::validate_wallet_name(&signer_name)?;
        let signer_wallet = cfg
            .wallets
            .iter()
            .find(|w| w.name == signer_name)
            .ok_or_else(|| {
                anyhow::anyhow!("Signer wallet '{}' not found in local config", signer_name)
            })?;
        signer_entries.push(multisig::Signer {
            public_key: signer_wallet.public_key.clone(),
            weight: 1,
            name: Some(signer_wallet.name.clone()),
        });
    }

    let total_weight = multisig::calculate_total_weight(&signer_entries);
    let thresholds = multisig::Thresholds {
        low: threshold,
        medium: threshold,
        high: threshold,
    };
    multisig::validate_thresholds(&thresholds, total_weight)?;

    let account = multisig::MultiSigAccount {
        name: name.clone(),
        account_id: wallet.public_key.clone(),
        signers: signer_entries,
        thresholds,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    multisig::save_account(&account)?;
    let setup_steps = multisig::build_stellar_cli_steps(&account, &network);

    println!();
    p::header(&format!("Multi-sig: {}", name));
    p::success("Multi-sig config saved");
    p::kv_accent("Account ID", &account.account_id);
    p::kv("Network", &network);
    p::kv("Threshold", &threshold.to_string());
    p::kv("Signers", &account.signers.len().to_string());
    if let Some(path) = xdr_output {
        let setup_tx = multisig::build_account_setup_transaction(&account, &network)?;
        multisig::save_transaction(&path, &setup_tx)?;
        p::kv("Setup XDR JSON", &path.display().to_string());
    }
    println!();
    p::info("Next steps to configure the account on-chain:");
    for (index, step) in setup_steps.iter().enumerate() {
        println!("  {}. {}", index + 1, step.title);
        println!("     {}", step.command.cyan());
    }
    println!();
    p::info("After your account is updated on-chain, collect signatures with:");
    println!(
        "  {}",
        format!(
            "starforge wallet multisig sign {} --transaction tx.json",
            account.name
        )
        .cyan()
    );
    Ok(())
}

fn multisig_sign(name: String, transaction: PathBuf, output: Option<PathBuf>) -> Result<()> {
    config::validate_wallet_name(&name)?;
    config::validate_file_path(&transaction, Some("json"))?;

    let account = multisig::load_account(&name)?;
    let cfg = config::load()?;

    let mut tx = multisig::load_transaction(&transaction)?;

    p::header(&format!("Multi-sig Sign: {}", name));
    p::kv("Account", &account.account_id);
    p::kv("Transaction", &transaction.display().to_string());

    // Attempt to sign with every configured signer that we have a local secret key for.
    let mut signed = 0u32;
    for s in &account.signers {
        let wallet_name = s.name.clone().unwrap_or_else(|| s.public_key.clone());
        let Some(w) = cfg.wallets.iter().find(|w| w.public_key == s.public_key) else {
            continue;
        };
        let Some(sk) = &w.secret_key else { continue };

        let plain_sk = if !sk.contains(':') && sk.starts_with('S') && sk.len() == 56 {
            sk.clone()
        } else {
            let pwd = crypto::prompt_password(
                &format!("Enter password for signer wallet '{}'", w.name),
                false,
            )?;
            crypto::decrypt_secret(&pwd, sk)
                .map_err(|_| anyhow::anyhow!("Incorrect password or unable to decrypt."))?
        };

        let sig = multisig::sign_transaction_partial(&tx.transaction_xdr, &plain_sk, "testnet")?;
        if multisig::add_signature_to_transaction(&mut tx, &wallet_name, sig).is_ok() {
            signed += 1;
        }
    }

    tx.threshold_required = account.thresholds.high;
    tx.current_weight = tx.signatures.len().min(u8::MAX as usize) as u8;
    if multisig::check_transaction_ready(&tx) {
        tx.status = multisig::TransactionStatus::ReadyToSubmit;
    }

    let out_path = output.unwrap_or_else(|| transaction.clone());
    multisig::save_transaction(&out_path, &tx)?;

    println!();
    p::success("Signatures updated");
    p::kv("Signatures added", &signed.to_string());
    p::kv("Total signatures", &tx.signatures.len().to_string());
    p::kv("Output", &out_path.display().to_string());

    if tx.status == multisig::TransactionStatus::ReadyToSubmit {
        p::info("Transaction meets threshold and is ready to submit.");
    } else {
        p::warn("Transaction does not yet meet threshold.");
    }

    Ok(())
}

fn multisig_list() -> Result<()> {
    p::header("Multi-Signature Accounts");
    let accounts = multisig::list_accounts().unwrap_or_default();
    if accounts.is_empty() {
        p::info("No multi-sig accounts found. Create one with: starforge wallet multisig create");
        return Ok(());
    }

    p::separator();
    for (i, acct) in accounts.iter().enumerate() {
        println!("  {:>2}. {}", i + 1, acct.name.bold());
        p::kv("Account ID", &acct.account_id);
        p::kv("Signers", &acct.signers.len().to_string());
        p::kv("Threshold", &acct.thresholds.high.to_string());
        if i < accounts.len() - 1 {
            println!();
        }
    }
    p::separator();
    Ok(())
}

fn multisig_show(name: String) -> Result<()> {
    let multisig_account = multisig::load_account(&name)?;

    p::header(&format!("Multi-Sig Account: {}", name));
    p::separator();
    p::kv_accent("Account ID", &multisig_account.account_id);
    p::kv("Created", &multisig_account.created_at);

    println!();
    p::info("Thresholds:");
    p::kv("  Low", &multisig_account.thresholds.low.to_string());
    p::kv("  Medium", &multisig_account.thresholds.medium.to_string());
    p::kv("  High", &multisig_account.thresholds.high.to_string());

    println!();
    p::info(&format!("Signers ({}):", multisig_account.signers.len()));

    if multisig_account.signers.is_empty() {
        p::warn("  No signers configured yet");
    } else {
        for (i, signer) in multisig_account.signers.iter().enumerate() {
            println!();
            p::kv(&format!("  [{}] Key", i + 1), &signer.public_key);
            p::kv(&format!("  [{}] Weight", i + 1), &signer.weight.to_string());
            if let Some(ref signer_name) = signer.name {
                p::kv(&format!("  [{}] Name", i + 1), signer_name);
            }
        }
    }

    let total_weight = multisig::calculate_total_weight(&multisig_account.signers);
    println!();
    p::kv_accent("Total Weight", &total_weight.to_string());

    p::separator();
    Ok(())
}

fn multisig_submit(name: String, transaction: PathBuf, network: Option<String>) -> Result<()> {
    config::validate_wallet_name(&name)?;
    config::validate_file_path(&transaction, Some("json"))?;

    let account = multisig::load_account(&name)?;
    let tx = multisig::load_transaction(&transaction)?;

    let network = network.unwrap_or_else(|| "testnet".to_string());
    config::validate_network(&network)?;

    p::header(&format!("Multi-Sig Submit: {}", name));
    p::kv("Account", &account.account_id);
    p::kv("Network", &network);
    p::kv("Signatures", &tx.signatures.len().to_string());
    p::kv("Threshold", &tx.threshold_required.to_string());

    if tx.status != multisig::TransactionStatus::ReadyToSubmit {
        anyhow::bail!(
            "Transaction is not ready to submit (status: {:?}). \
             Collect enough signatures first with `starforge wallet multisig sign`.",
            tx.status
        );
    }

    p::step(1, 2, "Combining signatures into final envelopeâ€¦");
    let signed_xdr = multisig::combine_signatures(&tx.transaction_xdr, &tx.signatures)?;

    p::step(2, 2, &format!("Submitting to Horizon ({})â€¦", network));
    let result = horizon::submit_multisig_transaction(&signed_xdr, &network)?;

    println!();
    p::success("Transaction submitted");
    p::kv_accent("Hash", &result.hash);
    p::kv("Successful", &result.successful.to_string());
    p::info(&format!(
        "View on explorer: https://stellar.expert/explorer/{}/tx/{}",
        network, result.hash
    ));
    Ok(())
}
