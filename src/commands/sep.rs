use crate::utils::{config, crypto, print as p, stellar_toml};
use anyhow::{Context, Result};
use base64::Engine;
use clap::Subcommand;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use stellar_strkey::ed25519::PrivateKey as StellarPrivateKey;
use stellar_xdr::curr::{
    BytesM, DecoratedSignature, Limits, OperationBody, Preconditions, ReadXdr,
    Signature as XdrSignature, SignatureHint, TransactionEnvelope, WriteXdr,
};

#[derive(Subcommand)]
pub enum SepCommands {
    /// SEP-10 Web Authentication — get a JWT from an anchor
    Auth {
        /// Anchor domain (e.g. testanchor.stellar.org)
        #[arg(long)]
        anchor: String,
        /// Name of the local wallet to authenticate with
        #[arg(long)]
        wallet: String,
    },
    /// SEP-24 Hosted Deposit — initiate an interactive deposit with an anchor
    Deposit {
        /// Anchor domain (e.g. testanchor.stellar.org)
        #[arg(long)]
        anchor: String,
        /// Asset code to deposit (e.g. USDC)
        #[arg(long)]
        asset: String,
        /// Amount to deposit
        #[arg(long)]
        amount: f64,
        /// Name of the local wallet to use
        #[arg(long)]
        wallet: String,
    },
}

pub fn handle(cmd: SepCommands) -> Result<()> {
    match cmd {
        SepCommands::Auth { anchor, wallet } => sep10_auth(&anchor, &wallet),
        SepCommands::Deposit {
            anchor,
            asset,
            amount,
            wallet,
        } => sep24_deposit(&anchor, &asset, amount, &wallet),
    }
}

// ── SEP-10 ───────────────────────────────────────────────────────────────────

fn sep10_auth(anchor: &str, wallet_name: &str) -> Result<()> {
    p::header("SEP-10 Web Authentication");

    // Load config and find wallet
    let cfg = config::load()?;
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == wallet_name)
        .with_context(|| {
            format!(
                "Wallet '{}' not found. Run `starforge wallet list` to see available wallets.",
                wallet_name
            )
        })?;
    let public_key = wallet.public_key.clone();

    p::info(&format!("Authenticating wallet '{}'", wallet_name));
    p::kv("Public Key", &public_key);

    // Step 1: Fetch stellar.toml
    p::step(1, 5, "Fetching stellar.toml...");
    let toml = stellar_toml::fetch(anchor)
        .with_context(|| format!("Failed to fetch stellar.toml from anchor '{}'", anchor))?;
    let web_auth_endpoint = toml.web_auth_endpoint.with_context(|| {
        format!(
            "Anchor '{}' does not publish WEB_AUTH_ENDPOINT in stellar.toml",
            anchor
        )
    })?;
    p::kv("WEB_AUTH_ENDPOINT", &web_auth_endpoint);

    // Step 2: GET challenge
    p::step(2, 5, "Fetching SEP-10 challenge...");
    let challenge_url = format!("{}?account={}", web_auth_endpoint, public_key);
    let challenge_resp = ureq::get(&challenge_url)
        .call()
        .with_context(|| format!("Failed to get challenge from {}", web_auth_endpoint))?;
    let challenge_json: serde_json::Value = challenge_resp
        .into_json()
        .context("Failed to parse challenge response as JSON")?;

    let challenge_xdr = challenge_json["transaction"]
        .as_str()
        .context("Challenge response missing 'transaction' field")?;
    let network_passphrase = challenge_json["network_passphrase"]
        .as_str()
        .unwrap_or("Test SDF Network ; September 2015");

    // Step 3: Decode and verify the challenge transaction
    p::step(3, 5, "Verifying challenge transaction...");
    let xdr_bytes = base64::engine::general_purpose::STANDARD
        .decode(challenge_xdr)
        .context("Failed to decode base64 challenge transaction")?;
    let envelope = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
        .context("Failed to parse challenge transaction XDR")?;

    // Verify in immutable scope, produce the sig to add
    let (new_sig, existing_sigs) = {
        let TransactionEnvelope::Tx(ref tx_v1) = envelope else {
            anyhow::bail!("Expected TransactionEnvelope::Tx (V1), got a different variant");
        };
        let tx = &tx_v1.tx;

        // Verify time bounds are present and not expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let max_time = match &tx.cond {
            Preconditions::Time(tb) => tb.max_time.0,
            Preconditions::V2(v2) => v2
                .time_bounds
                .as_ref()
                .map(|tb| tb.max_time.0)
                .with_context(|| "Challenge transaction has no time bounds (required by SEP-10)")?,
            Preconditions::None => {
                anyhow::bail!(
                    "Challenge transaction has no preconditions; time bounds required by SEP-10"
                );
            }
        };
        if max_time < now {
            anyhow::bail!(
                "Challenge transaction has expired (max_time {} < current time {})",
                max_time,
                now
            );
        }

        // Verify first operation is manage_data with key "<anchor> auth"
        if tx.operations.is_empty() {
            anyhow::bail!("Challenge transaction has no operations");
        }
        match &tx.operations[0].body {
            OperationBody::ManageData(md) => {
                let key = md.data_name.0.to_utf8_string_lossy();
                let expected = format!("{} auth", anchor);
                if key != expected {
                    anyhow::bail!(
                        "Challenge manage_data key mismatch: expected '{}', got '{}'",
                        expected,
                        key
                    );
                }
                match &md.data_value {
                    Some(dv) if dv.0.len() == 64 => {}
                    Some(dv) => {
                        anyhow::bail!("Challenge nonce must be 64 bytes, got {}", dv.0.len())
                    }
                    None => anyhow::bail!("Challenge manage_data operation has no data value"),
                }
            }
            _ => anyhow::bail!("First operation in challenge is not a manage_data operation"),
        }

        // Compute transaction signing hash
        let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
        let tx_body = tx
            .to_xdr(Limits::none())
            .context("Failed to XDR-encode transaction body for signing")?;
        let mut payload = Vec::with_capacity(36 + tx_body.len());
        payload.extend_from_slice(&network_id);
        payload.extend_from_slice(&[0u8, 0, 0, 2]); // ENVELOPE_TYPE_TX = 2
        payload.extend_from_slice(&tx_body);
        let hash: [u8; 32] = Sha256::digest(&payload).into();

        // Decrypt wallet secret key and sign
        let sk_str = wallet
            .secret_key
            .as_ref()
            .with_context(|| format!("Wallet '{}' has no secret key stored", wallet_name))?;
        let plain_sk = if sk_str.contains(':') {
            let pwd = crypto::prompt_password(
                &format!("Enter password for wallet '{}'", wallet_name),
                false,
            )?;
            crypto::decrypt_secret(&pwd, sk_str)
                .map_err(|_| anyhow::anyhow!("Incorrect password or unable to decrypt wallet"))?
        } else {
            sk_str.clone()
        };
        let decoded = StellarPrivateKey::from_string(&plain_sk)
            .context("Failed to parse wallet secret key")?;
        let signing_key = SigningKey::from_bytes(&decoded.0);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let dalek_sig = signing_key.sign(&hash);

        let hint = SignatureHint([pub_bytes[28], pub_bytes[29], pub_bytes[30], pub_bytes[31]]);
        let xdr_sig = XdrSignature(
            BytesM::try_from(dalek_sig.to_bytes().to_vec())
                .map_err(|_| anyhow::anyhow!("Failed to encode ed25519 signature as XDR bytes"))?,
        );
        let new_sig = DecoratedSignature {
            hint,
            signature: xdr_sig,
        };
        let existing: Vec<DecoratedSignature> = tx_v1.signatures.iter().cloned().collect();
        (new_sig, existing)
    };

    // Rebuild envelope with the added signature
    let mut envelope = envelope;
    let TransactionEnvelope::Tx(ref mut tx_v1) = envelope else {
        unreachable!()
    };
    let mut sigs = existing_sigs;
    sigs.push(new_sig);
    tx_v1.signatures = sigs
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature count exceeds envelope limit"))?;

    let xdr_bytes = envelope
        .to_xdr(Limits::none())
        .context("Failed to XDR-encode signed transaction")?;
    let signed_xdr = base64::engine::general_purpose::STANDARD.encode(&xdr_bytes);

    // Step 4: POST signed transaction to get JWT
    p::step(4, 5, "Submitting signed challenge...");
    let body = serde_json::to_string(&serde_json::json!({ "transaction": signed_xdr }))?;
    let token_resp = ureq::post(&web_auth_endpoint)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .with_context(|| format!("Failed to submit signed challenge to {}", web_auth_endpoint))?;
    let token_json: serde_json::Value = token_resp
        .into_json()
        .context("Failed to parse JWT response as JSON")?;
    let jwt = token_json["token"]
        .as_str()
        .context("JWT response missing 'token' field")?;

    // Step 5: Store JWT
    p::step(5, 5, "Storing JWT...");
    save_sep10_token(anchor, jwt)?;

    p::separator();
    p::success(&format!("Authenticated with anchor '{}'", anchor));
    p::kv("JWT stored for", anchor);
    Ok(())
}

// ── SEP-24 ───────────────────────────────────────────────────────────────────

fn sep24_deposit(anchor: &str, asset: &str, amount: f64, wallet_name: &str) -> Result<()> {
    p::header("SEP-24 Interactive Deposit");

    let cfg = config::load()?;
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == wallet_name)
        .with_context(|| format!("Wallet '{}' not found", wallet_name))?;
    let public_key = wallet.public_key.clone();

    p::info(&format!(
        "Deposit: {} {} via anchor '{}'",
        amount, asset, anchor
    ));
    p::kv("Wallet", wallet_name);
    p::kv("Public Key", &public_key);

    // Step 1: Ensure we have a SEP-10 JWT
    p::step(1, 4, "Getting SEP-10 authentication token...");
    let tokens = load_sep10_tokens()?;
    let jwt = if let Some(token) = tokens.get(anchor) {
        p::info("Using stored SEP-10 token");
        token.clone()
    } else {
        p::info("No stored token found — running SEP-10 auth first...");
        sep10_auth(anchor, wallet_name)?;
        let refreshed = load_sep10_tokens()?;
        refreshed
            .get(anchor)
            .cloned()
            .context("SEP-10 auth succeeded but token was not stored")?
    };

    // Step 2: Get TRANSFER_SERVER_SEP0024 from stellar.toml
    p::step(2, 4, "Fetching stellar.toml...");
    let toml = stellar_toml::fetch(anchor)
        .with_context(|| format!("Failed to fetch stellar.toml from '{}'", anchor))?;
    let transfer_server = toml.transfer_server_sep0024.with_context(|| {
        format!(
            "Anchor '{}' does not publish TRANSFER_SERVER_SEP0024 in stellar.toml",
            anchor
        )
    })?;
    p::kv("TRANSFER_SERVER", &transfer_server);

    // Step 3: POST /transactions/deposit/interactive
    p::step(3, 4, "Initiating interactive deposit...");
    let amount_str = format!("{}", amount);
    let deposit_resp = ureq::post(&format!(
        "{}/transactions/deposit/interactive",
        transfer_server.trim_end_matches('/')
    ))
    .set("Authorization", &format!("Bearer {}", jwt))
    .send_form(&[
        ("asset_code", asset),
        ("amount", &amount_str),
        ("account", &public_key),
    ])
    .with_context(|| {
        format!(
            "Failed to initiate deposit at {}/transactions/deposit/interactive",
            transfer_server
        )
    })?;

    let deposit_json: serde_json::Value = deposit_resp
        .into_json()
        .context("Failed to parse deposit response as JSON")?;

    let resp_type = deposit_json["type"].as_str().unwrap_or("");
    if resp_type != "interactive_customer_info_needed" {
        anyhow::bail!(
            "Unexpected response type '{}' from deposit endpoint; expected 'interactive_customer_info_needed'",
            resp_type
        );
    }

    let url = deposit_json["url"]
        .as_str()
        .context("Deposit response missing 'url' field")?;
    let tx_id = deposit_json["id"]
        .as_str()
        .context("Deposit response missing 'id' field")?;

    p::success("Interactive deposit session created");
    p::kv("Transaction ID", tx_id);
    p::kv("Deposit URL", url);

    // Step 4: Open browser and poll for completion
    p::step(4, 4, "Opening deposit URL in browser...");
    open_browser(url)?;
    println!();
    p::info("Complete the deposit in the browser, then this CLI will detect completion.");
    p::info("Polling every 5 seconds (timeout: 2 minutes)...");
    println!();

    poll_sep24_transaction(transfer_server.trim_end_matches('/'), tx_id, &jwt)?;

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn sep10_tokens_path() -> Result<PathBuf> {
    Ok(config::get_data_dir()?.join("sep10_tokens.json"))
}

fn load_sep10_tokens() -> Result<HashMap<String, String>> {
    let path = sep10_tokens_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(&path).context("Failed to read SEP-10 token store")?;
    serde_json::from_str(&content).context("Failed to parse SEP-10 token store as JSON")
}

fn save_sep10_token(anchor: &str, token: &str) -> Result<()> {
    let path = sep10_tokens_path()?;
    let mut tokens = load_sep10_tokens()?;
    tokens.insert(anchor.to_string(), token.to_string());
    let json = serde_json::to_string_pretty(&tokens)?;
    fs::write(&path, json).context("Failed to write SEP-10 token store")?;
    Ok(())
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .context("Failed to open browser with 'open'")?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("Failed to open browser with 'xdg-open'")?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()
            .context("Failed to open browser with 'start'")?;
    }
    Ok(())
}

fn poll_sep24_transaction(transfer_server: &str, tx_id: &str, jwt: &str) -> Result<()> {
    let poll_url = format!("{}/transaction?id={}", transfer_server, tx_id);
    for attempt in 1u32..=24 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let resp = match ureq::get(&poll_url)
            .set("Authorization", &format!("Bearer {}", jwt))
            .call()
        {
            Ok(r) => r,
            Err(e) => {
                p::warn(&format!("Poll attempt {} failed: {}", attempt, e));
                continue;
            }
        };
        let json: serde_json::Value = resp
            .into_json()
            .context("Failed to parse transaction poll response")?;
        let status = json["transaction"]["status"].as_str().unwrap_or("unknown");
        match status {
            "completed" => {
                p::separator();
                p::success("Deposit completed!");
                if let Some(stellar_tx_id) = json["transaction"]["stellar_transaction_id"].as_str()
                {
                    p::kv("Stellar Transaction ID", stellar_tx_id);
                }
                if let Some(amount) = json["transaction"]["amount_in"].as_str() {
                    p::kv("Amount In", amount);
                }
                if let Some(amount) = json["transaction"]["amount_out"].as_str() {
                    p::kv("Amount Out", amount);
                }
                return Ok(());
            }
            "error" | "failed" => {
                let msg = json["transaction"]["message"]
                    .as_str()
                    .unwrap_or("Unknown error");
                anyhow::bail!("Deposit failed: {}", msg);
            }
            _ => {
                p::info(&format!("[{}/24] Status: {} — waiting...", attempt, status));
            }
        }
    }
    p::warn("Timed out waiting for deposit completion. Check the anchor's website for the deposit status.");
    Ok(())
}
