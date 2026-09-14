//! RPC Traffic Recording, Redaction, and Deterministic Replay CLI commands
//!
//! Provides CLI subcommands to record live JSON-RPC traffic through a privacy-safe
//! proxy, sanitize recordings by scrubbing secrets and signatures, deterministically
//! replay captured sessions with fault injection, inspect session contents, and
//! verify cryptographic digests and security properties.

use crate::utils::print as p;
use crate::utils::rpc_recording::fault::{FaultRule, FaultSuite, FaultType};
use crate::utils::rpc_recording::proxy::{ProxyConfig, RecordingProxy};
use crate::utils::rpc_recording::redaction::{AccountRedactionStrategy, RedactionConfig, Redactor};
use crate::utils::rpc_recording::replay::{
    ReplayEngine, ReplayMode, ReplayNormalization, ReplayServer,
};
use crate::utils::rpc_recording::verifier::SessionVerifier;
use crate::utils::rpc_recording::{load_recording, sanitize_session, save_recording};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Subcommand, Debug, Clone)]
pub enum RpcCommands {
    /// Record live JSON-RPC traffic through a local proxy with on-the-fly privacy redaction
    Record(RecordArgs),
    /// Deterministically replay recorded RPC traffic as a mock server with fault injection
    Replay(ReplayArgs),
    /// Inspect recorded sessions, exchanges, latency profiles, and redaction metrics
    Inspect(InspectArgs),
    /// Re-sanitize an existing recording file with customized redaction rules
    Sanitize(SanitizeArgs),
    /// Verify recording schema, cryptographic digests, causal chains, and scan for secret leaks
    Verify(VerifyArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct RecordArgs {
    /// Local address to bind recording proxy to
    #[arg(long, default_value = "127.0.0.1:8545")]
    pub listen: String,

    /// Upstream RPC server URL to proxy requests to
    #[arg(long, default_value = "https://soroban-testnet.stellar.org")]
    pub upstream: String,

    /// Destination file path where recording session JSON will be written
    #[arg(long, short = 'o', default_value = "rpc-recording.json")]
    pub output: PathBuf,

    /// Network passphrase to document with session
    #[arg(long)]
    pub network_passphrase: Option<String>,

    /// Account ID redaction strategy (preserve, mask, pseudonymize)
    #[arg(long, default_value = "preserve")]
    pub account_strategy: AccountStrategyArg,

    /// Additional custom regular expression patterns to redact from traffic
    #[arg(long = "custom-pattern")]
    pub custom_patterns: Vec<String>,

    /// Additional JSON key names to treat as sensitive and redact
    #[arg(long = "custom-key")]
    pub custom_keys: Vec<String>,

    /// Network timeout in seconds for upstream requests
    #[arg(long, default_value = "15")]
    pub timeout_secs: u64,

    /// Maximum number of exchanges to record before terminating
    #[arg(long)]
    pub max_exchanges: Option<usize>,

    /// Maximum recording duration in seconds before terminating
    #[arg(long)]
    pub duration_secs: Option<u64>,
}

#[derive(Parser, Debug, Clone)]
pub struct ReplayArgs {
    /// Path to recording session file to replay
    #[arg(long, short = 'f')]
    pub file: PathBuf,

    /// Local address to bind the mock replay server to
    #[arg(long, default_value = "127.0.0.1:8545")]
    pub listen: String,

    /// Replay matching mode: 'unordered' (match by params) or 'causal' (strict sequence order)
    #[arg(long, default_value = "unordered")]
    pub mode: ReplayModeArg,

    /// Strict mode: return 404/RPC error immediately on any unmatched request
    #[arg(long)]
    pub strict: bool,

    /// Path to JSON configuration file specifying custom fault rules
    #[arg(long)]
    pub fault_config: Option<PathBuf>,

    /// Inject constant latency delay (milliseconds) across replayed responses
    #[arg(long)]
    pub fault_delay_ms: Option<u64>,

    /// Inject jitter (milliseconds) on top of latency delay
    #[arg(long)]
    pub fault_jitter_ms: Option<u64>,

    /// Percentage (0-100) of requests to fail with HTTP 429 Rate Limit
    #[arg(long)]
    pub fault_rate_limit_pct: Option<f64>,

    /// Simulate a specific JSON-RPC error code (e.g. -32601, -32000)
    #[arg(long)]
    pub fault_error_code: Option<i64>,

    /// Custom error message to accompany simulated RPC error
    #[arg(long, default_value = "Simulated fault error")]
    pub fault_error_message: String,

    /// Simulate network disconnects on requests matching this method name
    #[arg(long)]
    pub fault_disconnect_method: Option<String>,

    /// Maximum requests to serve before shutting down server
    #[arg(long)]
    pub max_requests: Option<usize>,
}

#[derive(Parser, Debug, Clone)]
pub struct InspectArgs {
    /// Path to recording session file
    #[arg(long, short = 'f')]
    pub file: PathBuf,

    /// Output full machine-readable JSON structure
    #[arg(long)]
    pub json: bool,

    /// Include full serialized request and response payloads in human output
    #[arg(long)]
    pub detailed: bool,

    /// Filter output to only include exchanges for the specified JSON-RPC method
    #[arg(long)]
    pub filter_method: Option<String>,

    /// Show audit log of all redactions applied to this session
    #[arg(long)]
    pub show_redactions: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct SanitizeArgs {
    /// Input recording file to sanitize
    #[arg(long, short = 'i')]
    pub input: PathBuf,

    /// Output recording file (or use --in-place to overwrite input)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Overwrite input file in-place
    #[arg(long)]
    pub in_place: bool,

    /// Account ID redaction strategy (preserve, mask, pseudonymize)
    #[arg(long, default_value = "mask")]
    pub account_strategy: AccountStrategyArg,

    /// Additional custom regular expression patterns to redact
    #[arg(long = "custom-pattern")]
    pub custom_patterns: Vec<String>,

    /// Additional JSON key names to treat as sensitive
    #[arg(long = "custom-key")]
    pub custom_keys: Vec<String>,

    /// Output sanitization metrics in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct VerifyArgs {
    /// Path to recording file to verify
    #[arg(long, short = 'f')]
    pub file: PathBuf,

    /// Perform deep scan for unredacted secret leaks (seeds, bearer tokens)
    #[arg(long, default_value = "true")]
    pub check_secrets: bool,

    /// Strict mode: fail with non-zero exit if any warning is reported
    #[arg(long)]
    pub strict: bool,

    /// Output machine-readable JSON verification report
    #[arg(long)]
    pub json: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStrategyArg {
    Preserve,
    Mask,
    Pseudonymize,
}

impl From<AccountStrategyArg> for AccountRedactionStrategy {
    fn from(arg: AccountStrategyArg) -> Self {
        match arg {
            AccountStrategyArg::Preserve => AccountRedactionStrategy::Preserve,
            AccountStrategyArg::Mask => AccountRedactionStrategy::Mask,
            AccountStrategyArg::Pseudonymize => AccountRedactionStrategy::Pseudonymize,
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayModeArg {
    Unordered,
    Causal,
}

impl From<ReplayModeArg> for ReplayMode {
    fn from(arg: ReplayModeArg) -> Self {
        match arg {
            ReplayModeArg::Unordered => ReplayMode::Unordered,
            ReplayModeArg::Causal => ReplayMode::Causal,
        }
    }
}

/// Helper to determine whether the command output should suppress banner
pub fn is_machine_readable(cmd: &RpcCommands) -> bool {
    match cmd {
        RpcCommands::Inspect(args) => args.json,
        RpcCommands::Sanitize(args) => args.json,
        RpcCommands::Verify(args) => args.json,
        _ => false,
    }
}

/// Central CLI dispatcher for starforge rpc commands
pub fn handle(cmd: RpcCommands) -> Result<()> {
    match cmd {
        RpcCommands::Record(args) => handle_record(args),
        RpcCommands::Replay(args) => handle_replay(args),
        RpcCommands::Inspect(args) => handle_inspect(args),
        RpcCommands::Sanitize(args) => handle_sanitize(args),
        RpcCommands::Verify(args) => handle_verify(args),
    }
}

// ----------------------------------------------------------------------------
// Command Handlers
// ----------------------------------------------------------------------------

fn handle_record(args: RecordArgs) -> Result<()> {
    p::header("StarForge RPC Traffic Recorder");
    println!("  {} Upstream:   {}", "•".cyan(), args.upstream.bold());
    println!(
        "  {} Local Proxy: http://{}",
        "•".cyan(),
        args.listen.bold()
    );
    println!(
        "  {} Output File: {}",
        "•".cyan(),
        args.output.display().to_string().bold()
    );
    println!(
        "  {} Account Mode: {:?}",
        "•".cyan(),
        AccountRedactionStrategy::from(args.account_strategy)
    );

    let mut redactor_cfg = RedactionConfig {
        account_strategy: args.account_strategy.into(),
        redact_file_paths: true,
        inspect_base64: true,
        sensitive_keys: HashSet::new(),
        custom_patterns: args.custom_patterns,
    };
    for key in args.custom_keys {
        redactor_cfg.sensitive_keys.insert(key.to_lowercase());
    }

    let redactor = Redactor::new(redactor_cfg)?;

    let proxy_cfg = ProxyConfig {
        listen_addr: args.listen.clone(),
        upstream_url: args.upstream.clone(),
        output_file: args.output.clone(),
        timeout_secs: args.timeout_secs,
        network_passphrase: args.network_passphrase,
    };

    let proxy = Arc::new(RecordingProxy::new(proxy_cfg, redactor));
    let proxy_clone = Arc::clone(&proxy);

    // Setup clean Ctrl-C handler
    let term_signal = Arc::new(AtomicBool::new(false));
    let term_signal_clone = Arc::clone(&term_signal);
    let _ = ctrlc::set_handler(move || {
        println!(
            "\n  {} Stopping recorder and finalizing session...",
            "ℹ".yellow()
        );
        term_signal_clone.store(true, Ordering::SeqCst);
        proxy_clone.stop();
    });

    println!(
        "\n  {} Recording in progress. Press Ctrl+C to finish.",
        "▶".green().bold()
    );

    let max_duration = args.duration_secs.map(Duration::from_secs);
    proxy.run(args.max_exchanges, max_duration)?;

    let session = proxy.current_session();
    p::success(&format!(
        "Recording saved to '{}' ({} exchanges captured, {} items redacted, digest: {})",
        args.output.display(),
        session.exchanges.len(),
        session.redaction_summary.total(),
        &session.session_digest[0..12.min(session.session_digest.len())]
    ));

    Ok(())
}

fn handle_replay(args: ReplayArgs) -> Result<()> {
    p::header("StarForge Deterministic RPC Replay");

    if !args.file.exists() {
        bail!("Recording file not found: {}", args.file.display());
    }

    let session = load_recording(&args.file).with_context(|| {
        format!(
            "Failed to load recording session from {}",
            args.file.display()
        )
    })?;

    println!(
        "  {} Session ID:   {}",
        "•".cyan(),
        session.session_id.dimmed()
    );
    println!(
        "  {} Exchanges:    {}",
        "•".cyan(),
        session.exchanges.len().to_string().bold()
    );
    println!(
        "  {} Upstream URL: {}",
        "•".cyan(),
        session.endpoint.upstream_url.dimmed()
    );
    println!("  {} Replay Mode:  {:?}", "•".cyan(), args.mode);
    println!(
        "  {} Mock Server:  http://{}",
        "•".cyan(),
        args.listen.bold()
    );

    let mut fault_suite = if let Some(ref config_path) = args.fault_config {
        let content = std::fs::read_to_string(config_path).with_context(|| {
            format!("Failed to read fault config from {}", config_path.display())
        })?;
        serde_json::from_str::<FaultSuite>(&content)
            .with_context(|| "Failed to parse fault configuration JSON")?
    } else {
        FaultSuite::new()
    };

    // Apply CLI fault flags
    if let Some(delay_ms) = args.fault_delay_ms {
        println!("  {} Fault Inject: Delay {}ms", "⚠".yellow(), delay_ms);
        fault_suite.add_rule(FaultRule::new(FaultType::Delay {
            delay_ms,
            jitter_ms: args.fault_jitter_ms,
        }));
    }

    if let Some(pct) = args.fault_rate_limit_pct {
        let prob = (pct / 100.0).clamp(0.0, 1.0);
        println!(
            "  {} Fault Inject: Rate Limit ({:.1}% probability)",
            "⚠".yellow(),
            pct
        );
        fault_suite.add_rule(
            FaultRule::new(FaultType::RateLimit {
                retry_after_secs: 5,
                message: Some("Rate limit exceeded in replay test".to_string()),
            })
            .with_probability(prob),
        );
    }

    if let Some(code) = args.fault_error_code {
        println!("  {} Fault Inject: RPC Error code {}", "⚠".yellow(), code);
        fault_suite.add_rule(FaultRule::new(FaultType::RpcError {
            code,
            message: args.fault_error_message.clone(),
            data: None,
        }));
    }

    if let Some(ref method) = args.fault_disconnect_method {
        println!(
            "  {} Fault Inject: Disconnect on method '{}'",
            "⚠".yellow(),
            method
        );
        fault_suite.add_rule(FaultRule::new(FaultType::Disconnect).with_method(method));
    }

    let normalization = ReplayNormalization::default();
    let engine = ReplayEngine::new(
        session,
        args.mode.into(),
        normalization,
        fault_suite,
        args.strict,
    );

    let server = Arc::new(ReplayServer::new(engine, &args.listen));
    let server_clone = Arc::clone(&server);

    let _ = ctrlc::set_handler(move || {
        println!("\n  {} Shutting down replay server...", "ℹ".yellow());
        server_clone.stop();
    });

    println!(
        "\n  {} Replay server listening on http://{}. Press Ctrl+C to terminate.",
        "▶".green().bold(),
        args.listen
    );

    server.run(args.max_requests)?;
    p::success("Replay session completed.");
    Ok(())
}

fn handle_inspect(args: InspectArgs) -> Result<()> {
    let session = load_recording(&args.file)
        .with_context(|| format!("Failed to read recording file {}", args.file.display()))?;

    if args.json {
        let output = if let Some(ref filter) = args.filter_method {
            let mut filtered = session.clone();
            filtered
                .exchanges
                .retain(|ex| ex.request.jsonrpc_method == *filter);
            serde_json::to_string_pretty(&filtered)?
        } else {
            serde_json::to_string_pretty(&session)?
        };
        println!("{}", output);
        return Ok(());
    }

    p::header("StarForge RPC Recording Inspector");
    println!("  {} File:             {}", "•".cyan(), args.file.display());
    println!(
        "  {} Session ID:       {}",
        "•".cyan(),
        session.session_id.bold()
    );
    println!(
        "  {} Schema Version:   {}",
        "•".cyan(),
        session.schema_version
    );
    println!("  {} Created:          {}", "•".cyan(), session.created_at);
    println!("  {} Updated:          {}", "•".cyan(), session.updated_at);
    println!(
        "  {} Upstream URL:     {}",
        "•".cyan(),
        session.endpoint.upstream_url.bold()
    );
    println!(
        "  {} Total Exchanges:  {}",
        "•".cyan(),
        session.exchanges.len().to_string().bold()
    );
    println!(
        "  {} Session Digest:   {}",
        "•".cyan(),
        session.session_digest.dimmed()
    );

    println!("\n  {}", "Redaction Summary:".bold());
    println!(
        "    Secrets Redacted:    {}",
        session.redaction_summary.secrets_redacted_count
    );
    println!(
        "    Signatures Redacted: {}",
        session.redaction_summary.signatures_redacted_count
    );
    println!(
        "    Paths Redacted:      {}",
        session.redaction_summary.paths_redacted_count
    );
    println!(
        "    Accounts Redacted:   {}",
        session.redaction_summary.accounts_redacted_count
    );
    println!(
        "    Custom Rules:        {}",
        session.redaction_summary.custom_rules_matched_count
    );

    println!("\n  {}", "Captured Exchanges:".bold());
    let mut shown = 0;
    for ex in &session.exchanges {
        if let Some(ref filter) = args.filter_method {
            if ex.request.jsonrpc_method != *filter {
                continue;
            }
        }
        shown += 1;

        let status_color = if ex.response.status_code == 200 && !ex.response.is_error {
            format!("{}", ex.response.status_code).green()
        } else {
            format!("{}", ex.response.status_code).red()
        };

        println!(
            "  [{:03}] {} {:<26} status: {}  duration: {}ms  digest: {}",
            ex.sequence_id,
            ex.request.method.yellow(),
            ex.request.jsonrpc_method.bold(),
            status_color,
            ex.timing.duration_ms,
            &ex.exchange_digest[0..10.min(ex.exchange_digest.len())].dimmed()
        );

        if args.detailed {
            println!(
                "        Request Params:  {}",
                serde_json::to_string(&ex.request.params)?
            );
            println!(
                "        Response Body:   {}",
                serde_json::to_string(&ex.response.body)?
            );
        }
    }

    if shown == 0 {
        println!("    (No exchanges matched filter)");
    }

    Ok(())
}

fn handle_sanitize(args: SanitizeArgs) -> Result<()> {
    if !args.input.exists() {
        bail!("Input recording file not found: {}", args.input.display());
    }

    let target_out = if args.in_place {
        args.input.clone()
    } else {
        args.output
            .ok_or_else(|| anyhow::anyhow!("Must provide either --output <FILE> or --in-place"))?
    };

    let session = load_recording(&args.input)?;
    let mut redactor_cfg = RedactionConfig {
        account_strategy: args.account_strategy.into(),
        redact_file_paths: true,
        inspect_base64: true,
        sensitive_keys: HashSet::new(),
        custom_patterns: args.custom_patterns,
    };
    for key in args.custom_keys {
        redactor_cfg.sensitive_keys.insert(key.to_lowercase());
    }

    let redactor = Redactor::new(redactor_cfg)?;
    let (sanitized_session, summary, events) = sanitize_session(session, &redactor);

    save_recording(&target_out, &sanitized_session)?;

    if args.json {
        let res = serde_json::json!({
            "target": target_out,
            "total_redactions": summary.total(),
            "summary": summary,
            "events_count": events.len(),
            "new_session_digest": sanitized_session.session_digest
        });
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        p::header("StarForge RPC Sanitizer");
        p::success(&format!(
            "Sanitized recording saved to '{}' ({} additional redactions applied)",
            target_out.display(),
            summary.total()
        ));
        println!(
            "  {} Secrets:     {}",
            "•".cyan(),
            summary.secrets_redacted_count
        );
        println!(
            "  {} Signatures:  {}",
            "•".cyan(),
            summary.signatures_redacted_count
        );
        println!(
            "  {} Paths:       {}",
            "•".cyan(),
            summary.paths_redacted_count
        );
        println!(
            "  {} Accounts:    {}",
            "•".cyan(),
            summary.accounts_redacted_count
        );
        println!(
            "  {} Custom:      {}",
            "•".cyan(),
            summary.custom_rules_matched_count
        );
    }

    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    let verifier = SessionVerifier::new();
    let report = verifier.verify_file(&args.file, args.check_secrets);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.is_valid || (args.strict && !report.warnings.is_empty()) {
            std::process::exit(1);
        }
        return Ok(());
    }

    p::header("StarForge RPC Recording Verifier");
    println!("  {} File:             {}", "•".cyan(), args.file.display());
    println!(
        "  {} Schema Version:   {}",
        "•".cyan(),
        report.metrics.schema_version
    );
    println!(
        "  {} Total Exchanges:  {}",
        "•".cyan(),
        report.metrics.total_exchanges
    );
    println!(
        "  {} Digests Verified: {}",
        "•".cyan(),
        if report.metrics.digests_verified {
            "PASS".green()
        } else {
            "FAIL".red()
        }
    );
    println!(
        "  {} Causal Chain:     {}",
        "•".cyan(),
        if report.metrics.causal_chain_intact {
            "PASS".green()
        } else {
            "FAIL".red()
        }
    );
    println!(
        "  {} File Security:    {}",
        "•".cyan(),
        if report.metrics.file_permissions_secure {
            "PASS (0600)".green()
        } else {
            "WARN".yellow()
        }
    );

    if !report.warnings.is_empty() {
        println!("\n  {}", "Warnings:".yellow().bold());
        for warn in &report.warnings {
            println!("    {} {}", "⚠".yellow(), warn);
        }
    }

    if !report.errors.is_empty() {
        println!("\n  {}", "Violations:".red().bold());
        for err in &report.errors {
            println!("    {} {}", "✗".red(), err);
        }
        p::error(&format!(
            "Verification failed with {} violation(s)",
            report.errors.len()
        ));
        std::process::exit(1);
    }

    if args.strict && !report.warnings.is_empty() {
        p::error("Verification failed in strict mode due to warnings");
        std::process::exit(1);
    }

    p::success("All verification and integrity checks passed!");
    Ok(())
}
