use crate::sep10::{
    ChallengeValidationConfig, EncryptedTokenStore, Sep10Client, Sep10Doctor, Sep10Validator,
};

use crate::utils::{config, crypto, print as p, stellar_toml};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum SepCommands {
    /// SEP-10 Web Authentication suite (login, inspect, verify, list, revoke, doctor)
    #[command(name = "auth")]
    Auth(SepAuthArgs),

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

#[derive(Args, Debug)]
pub struct SepAuthArgs {
    /// Action subcommand (inspect, verify, list, revoke, doctor, login)
    #[command(subcommand)]
    pub action: Option<Sep10Subcommands>,

    /// Anchor domain (e.g. testanchor.stellar.org) - used when running direct auth
    #[arg(long)]
    pub anchor: Option<String>,

    /// Name of the local wallet to authenticate with - used when running direct auth
    #[arg(long)]
    pub wallet: Option<String>,

    /// Optional client domain for client attribution
    #[arg(long)]
    pub client_domain: Option<String>,

    /// Force re-authentication even if active token is cached
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand, Debug)]
pub enum Sep10Subcommands {
    /// Authenticate against an anchor and store encrypted session token
    Login {
        /// Anchor domain (e.g. testanchor.stellar.org)
        #[arg(long)]
        anchor: String,
        /// Name of the local wallet to authenticate with
        #[arg(long)]
        wallet: String,
        /// Optional client domain for attribution
        #[arg(long)]
        client_domain: Option<String>,
        /// Force re-authentication even if an active token is cached
        #[arg(long)]
        force: bool,
    },
    /// Inspect a challenge transaction XDR without signing or submitting
    Inspect {
        /// Challenge transaction envelope as base64 XDR
        #[arg(long)]
        challenge: String,
        /// Anchor server public key (G...)
        #[arg(long)]
        server_key: String,
        /// Client account public key (G...)
        #[arg(long)]
        client_account: String,
        /// Network passphrase
        #[arg(long, default_value = "Test SDF Network ; September 2015")]
        network: String,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },
    /// Verify a challenge transaction XDR against full validation rules
    Verify {
        /// Challenge transaction envelope as base64 XDR
        #[arg(long)]
        challenge: String,
        /// Anchor server public key (G...)
        #[arg(long)]
        server_key: String,
        /// Client account public key (G...)
        #[arg(long)]
        client_account: String,
        /// Expected home domain
        #[arg(long)]
        home_domain: Option<String>,
        /// Expected web auth domain
        #[arg(long)]
        web_auth_domain: Option<String>,
        /// Network passphrase
        #[arg(long, default_value = "Test SDF Network ; September 2015")]
        network: String,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },
    /// List active and cached SEP-10 sessions with expiration status
    List {
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },
    /// Revoke and delete stored sessions for an anchor
    Revoke {
        /// Anchor domain to revoke
        #[arg(long)]
        anchor: String,
        /// Optional specific account to revoke (if omitted, revokes all for anchor)
        #[arg(long)]
        account: Option<String>,
    },
    /// Run comprehensive diagnostics on an anchor's SEP-10 service and infrastructure
    Doctor {
        /// Anchor domain (e.g. testanchor.stellar.org)
        #[arg(long)]
        anchor: String,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn handle(cmd: SepCommands) -> Result<()> {
    match cmd {
        SepCommands::Auth(args) => handle_auth(args),
        SepCommands::Deposit {
            anchor,
            asset,
            amount,
            wallet,
        } => sep24_deposit(&anchor, &asset, amount, &wallet),
    }
}

fn handle_auth(args: SepAuthArgs) -> Result<()> {
    match args.action {
        Some(Sep10Subcommands::Login {
            anchor,
            wallet,
            client_domain,
            force,
        }) => sep10_auth(&anchor, &wallet, client_domain.as_deref(), force),

        Some(Sep10Subcommands::Inspect {
            challenge,
            server_key,
            client_account,
            network,
            json,
        }) => inspect_cmd(&challenge, &server_key, &client_account, &network, json),

        Some(Sep10Subcommands::Verify {
            challenge,
            server_key,
            client_account,
            home_domain,
            web_auth_domain,
            network,
            json,
        }) => verify_cmd(
            &challenge,
            &server_key,
            &client_account,
            home_domain.as_deref(),
            web_auth_domain.as_deref(),
            &network,
            json,
        ),

        Some(Sep10Subcommands::List { json }) => list_sessions_cmd(json),

        Some(Sep10Subcommands::Revoke { anchor, account }) => {
            revoke_sessions_cmd(&anchor, account.as_deref())
        }

        Some(Sep10Subcommands::Doctor { anchor, json }) => doctor_cmd(&anchor, json),

        None => {
            // Backward-compatible direct `starforge sep auth --anchor <anchor> --wallet <wallet>`
            let anchor = args.anchor.with_context(|| {
                "Missing required argument '--anchor'. Usage: starforge sep auth --anchor <anchor> --wallet <wallet>"
            })?;
            let wallet = args.wallet.with_context(|| {
                "Missing required argument '--wallet'. Usage: starforge sep auth --anchor <anchor> --wallet <wallet>"
            })?;
            sep10_auth(&anchor, &wallet, args.client_domain.as_deref(), args.force)
        }
    }
}

// ── SEP-10 Commands ─────────────────────────────────────────────────────────

fn sep10_auth(
    anchor: &str,
    wallet_name: &str,
    client_domain: Option<&str>,
    force: bool,
) -> Result<()> {
    p::header("SEP-10 Web Authentication");

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
    if let Some(cd) = client_domain {
        p::kv("Client Domain", cd);
    }

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

    let client = Sep10Client::new().map_err(|e| anyhow::anyhow!("{e}"))?;

    p::step(
        1,
        3,
        "Executing SEP-10 challenge authentication handshake...",
    );
    let session = client
        .authenticate(anchor, &public_key, &plain_sk, client_domain, force)
        .map_err(|e| anyhow::anyhow!("Authentication failed: {e}"))?;

    p::separator();
    p::success(&format!(
        "Authenticated successfully with anchor '{}'",
        anchor
    ));
    p::kv("Session Account", &session.account);
    p::kv(
        "Token Expiry",
        &format!("{}s remaining", session.seconds_until_expiry()),
    );
    p::kv(
        "Encrypted Session Store",
        "Saved to ~/.starforge/sep10_sessions.enc (mode 0600)",
    );
    p::kv("Redacted JWT", &session.redacted_jwt());

    // Also sync with legacy token store for backward compatibility
    let _ = save_sep10_token(anchor, &session.jwt);

    Ok(())
}

fn inspect_cmd(
    challenge: &str,
    server_key: &str,
    client_account: &str,
    network: &str,
    json_output: bool,
) -> Result<()> {
    let report = Sep10Client::inspect_challenge(challenge, server_key, client_account, network)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report.details)?);
    } else {
        p::header("SEP-10 Challenge Inspection");
        p::kv("Server Account", &report.details.server_account);
        p::kv("Client Account", &report.details.client_account);
        p::kv(
            "Sequence Number",
            &report.details.sequence_number.to_string(),
        );
        p::kv("Home Domain", &report.details.home_domain);
        if let Some(wad) = report.details.web_auth_domain.as_deref() {
            p::kv("Web Auth Domain", wad);
        }
        if let Some(cd) = report.details.client_domain.as_deref() {
            p::kv("Client Domain", cd);
        }

        p::kv(
            "Duration (seconds)",
            &report.details.duration_secs.to_string(),
        );
        p::kv(
            "Time to Expiry (seconds)",
            &report.details.time_to_expiry_secs.to_string(),
        );
        p::kv(
            "Server Signature Valid",
            &report.details.server_signature_valid.to_string(),
        );
    }
    Ok(())
}

fn verify_cmd(
    challenge: &str,
    server_key: &str,
    client_account: &str,
    home_domain: Option<&str>,
    web_auth_domain: Option<&str>,
    network: &str,
    json_output: bool,
) -> Result<()> {
    let config = ChallengeValidationConfig {
        expected_home_domain: home_domain.map(|s| s.to_string()),
        expected_web_auth_domain: web_auth_domain.map(|s| s.to_string()),
        network_passphrase: network.to_string(),
        require_web_auth_domain: web_auth_domain.is_some(),
        ..Default::default()
    };

    let result = Sep10Validator::validate(challenge, server_key, client_account, &config);

    match result {
        Ok(report) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                p::header("SEP-10 Challenge Verification Passed ✅");
                for check in &report.checks_passed {
                    println!("  {} {}", "✔".green(), check);
                }
                for warn in &report.warnings {
                    println!("  {} {}", "⚠".yellow(), warn);
                }
            }
            Ok(())
        }
        Err(e) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "is_valid": false,
                        "error": e.to_string()
                    })
                );
            } else {
                p::header("SEP-10 Challenge Verification Failed ❌");
                println!("  {} {}", "✖".red(), e);
            }
            anyhow::bail!("Challenge validation failed");
        }
    }
}

fn list_sessions_cmd(json_output: bool) -> Result<()> {
    let store = EncryptedTokenStore::default_store().map_err(|e| anyhow::anyhow!("{e}"))?;
    let sessions = store.list_sessions().map_err(|e| anyhow::anyhow!("{e}"))?;

    if json_output {
        let serialized: Vec<serde_json::Value> = sessions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "anchor_domain": s.anchor_domain,
                    "account": s.account,
                    "jwt_redacted": s.redacted_jwt(),
                    "is_expired": s.is_expired(),
                    "expires_at": s.expires_at,
                    "seconds_until_expiry": s.seconds_until_expiry(),
                    "client_domain": s.client_domain
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&serialized)?);
    } else {
        p::header("SEP-10 Cached Sessions");
        if sessions.is_empty() {
            p::info("No cached SEP-10 sessions found.");
            return Ok(());
        }

        for s in sessions {
            let status = if s.is_expired() {
                "EXPIRED".red().to_string()
            } else {
                format!("ACTIVE ({}s remaining)", s.seconds_until_expiry())
                    .green()
                    .to_string()
            };
            println!(
                "• Anchor: {} | Account: {}",
                s.anchor_domain.bold(),
                s.account
            );
            println!("  Status: {}", status);
            println!("  Token: {}", s.redacted_jwt().dimmed());
            println!();
        }
    }
    Ok(())
}

fn revoke_sessions_cmd(anchor: &str, account: Option<&str>) -> Result<()> {
    let store = EncryptedTokenStore::default_store().map_err(|e| anyhow::anyhow!("{e}"))?;
    p::header("SEP-10 Session Revocation");

    if let Some(acc) = account {
        let removed = store
            .revoke_session(anchor, acc)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if removed {
            p::success(&format!(
                "Revoked session for anchor '{}' and account '{}'",
                anchor, acc
            ));
        } else {
            p::warn(&format!(
                "No active session found for anchor '{}' and account '{}'",
                anchor, acc
            ));
        }
    } else {
        let count = store
            .revoke_anchor(anchor)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        p::success(&format!(
            "Revoked {} session(s) for anchor '{}'",
            count, anchor
        ));
    }

    // Also remove from legacy file
    let mut tokens = load_sep10_tokens().unwrap_or_default();
    if tokens.remove(anchor).is_some() {
        if let Ok(path) = sep10_tokens_path() {
            let _ = fs::write(&path, serde_json::to_string_pretty(&tokens)?);
        }
    }

    Ok(())
}

fn doctor_cmd(anchor: &str, json_output: bool) -> Result<()> {
    let report = Sep10Doctor::diagnose(anchor).map_err(|e| anyhow::anyhow!("{e}"))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        p::header(&format!("SEP-10 Anchor Diagnostics: {}", anchor));
        p::kv("stellar.toml URL", &report.toml_url);
        p::kv("stellar.toml Reachable", &report.toml_fetch_ok.to_string());
        if let Some(ep) = report.web_auth_endpoint.as_deref() {
            p::kv("WEB_AUTH_ENDPOINT", ep);
        }
        if let Some(sk) = report.signing_key.as_deref() {
            p::kv("SIGNING_KEY", sk);
        }

        p::kv("Latency", &format!("{} ms", report.measured_latency_ms));
        p::kv(
            "Clock Skew Estimate",
            &format!("{} s", report.estimated_clock_skew_secs),
        );

        if report.issues_found.is_empty() {
            p::separator();
            p::success("All SEP-10 infrastructure checks passed! Anchor is healthy.");
        } else {
            p::separator();
            p::warn("Issues identified with anchor:");
            for issue in &report.issues_found {
                println!("  {} {}", "•".yellow(), issue);
            }
        }
    }
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
    let store = EncryptedTokenStore::default_store().ok();
    let jwt_opt = store.and_then(|s| {
        s.get_session(anchor, &public_key)
            .ok()
            .flatten()
            .map(|st| st.jwt)
    });

    let jwt = if let Some(t) = jwt_opt {
        p::info("Using active encrypted SEP-10 token");
        t
    } else {
        let legacy_tokens = load_sep10_tokens()?;
        if let Some(token) = legacy_tokens.get(anchor) {
            p::info("Using stored legacy SEP-10 token");
            token.clone()
        } else {
            p::info("No stored token found — running SEP-10 auth first...");
            sep10_auth(anchor, wallet_name, None, false)?;
            let refreshed = load_sep10_tokens()?;
            refreshed
                .get(anchor)
                .cloned()
                .context("SEP-10 auth succeeded but token was not stored")?
        }
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
