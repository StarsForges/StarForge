use crate::compatibility::audit::AuditFailureThreshold;
use crate::compatibility::cache::{write_private_json, CacheLookup};
use crate::compatibility::{
    AuditOptions, CapabilityCache, CapabilityMatrix, CompatibilityAuditor, CompatibilityEvaluator,
    CompatibilityExport, CompatibilityLevel, CompatibilityStatus, EndpointEvidence, EndpointProber,
    ProbeOptions, UreqTransport,
};
use crate::utils::{config, print as p};
use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Subcommand)]
pub enum CompatibilityCommands {
    /// Show compatibility using a protocol override or fresh cached endpoint evidence
    Status(StatusArgs),
    /// Probe Horizon and Soroban RPC capabilities with bounded requests
    Probe(ProbeArgs),
    /// Print the versioned protocol, XDR, RPC method, and feature matrix
    Matrix(MatrixArgs),
    /// Audit a project, artifacts, fixtures, plugins, and endpoint evidence
    Audit(AuditArgs),
    /// Export a stable versioned JSON evidence bundle
    Export(ExportArgs),
}

#[derive(Args)]
pub struct StatusArgs {
    /// Configured network name (defaults to the active network)
    #[arg(long)]
    pub network: Option<String>,
    /// Evaluate a protocol version without endpoint evidence
    #[arg(long, conflicts_with = "network")]
    pub protocol_version: Option<u32>,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Maximum cache age in seconds
    #[arg(long, default_value_t = 300)]
    pub cache_ttl_seconds: u64,
    /// Write the report to a private file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct ProbeArgs {
    /// Configured network name (defaults to the active network)
    #[arg(long)]
    pub network: Option<String>,
    /// Soroban RPC URL override; credentials and paths are redacted from output
    #[arg(long)]
    pub rpc_url: Option<String>,
    /// Horizon URL override used to verify network identity consistency
    #[arg(long)]
    pub horizon_url: Option<String>,
    /// Per-request connect, read, and write timeout in milliseconds
    #[arg(long, default_value_t = 3000, value_parser = clap::value_parser!(u64).range(100..=60000))]
    pub timeout_ms: u64,
    /// Maximum cache age in seconds
    #[arg(long, default_value_t = 300)]
    pub cache_ttl_seconds: u64,
    /// Ignore fresh cached evidence and contact the endpoint
    #[arg(long)]
    pub refresh: bool,
    /// Do not read or persist capability evidence
    #[arg(long)]
    pub no_cache: bool,
    /// Skip optional RPC method checks
    #[arg(long)]
    pub core_only: bool,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Write the report to a private file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct MatrixArgs {
    /// Limit protocol rows to one version; unknown versions remain unverified
    #[arg(long)]
    pub protocol_version: Option<u32>,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Write the matrix to a private file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct AuditArgs {
    /// Project or workspace root to inspect
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    /// Configured network whose cached evidence should be included
    #[arg(long)]
    pub network: Option<String>,
    /// Contact configured endpoints before auditing (off by default for deterministic CI)
    #[arg(long)]
    pub probe_endpoints: bool,
    /// Per-request timeout when --probe-endpoints is used
    #[arg(long, default_value_t = 3000, value_parser = clap::value_parser!(u64).range(100..=60000))]
    pub timeout_ms: u64,
    /// Maximum accepted endpoint cache age in seconds
    #[arg(long, default_value_t = 300)]
    pub cache_ttl_seconds: u64,
    /// Maximum number of project files to inspect
    #[arg(long, default_value_t = 10000)]
    pub max_files: usize,
    /// Fail threshold for CI gating
    #[arg(long, default_value = "never", value_parser = ["never", "incompatible", "degraded"])]
    pub fail_on: String,
    /// Output format
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Write the audit report to a private file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Configured network whose fresh cached evidence should be exported
    #[arg(long)]
    pub network: Option<String>,
    /// Protocol override when endpoint evidence is unavailable
    #[arg(long)]
    pub protocol_version: Option<u32>,
    /// Include a project upgrade-readiness audit
    #[arg(long)]
    pub audit_path: Option<PathBuf>,
    /// Maximum accepted endpoint cache age in seconds
    #[arg(long, default_value_t = 300)]
    pub cache_ttl_seconds: u64,
    /// Private JSON destination; stdout is used when omitted
    #[arg(long)]
    pub output: Option<PathBuf>,
}

pub fn is_machine_readable(command: &CompatibilityCommands) -> bool {
    match command {
        CompatibilityCommands::Status(args) => args.format == "json",
        CompatibilityCommands::Probe(args) => args.format == "json",
        CompatibilityCommands::Matrix(args) => args.format == "json",
        CompatibilityCommands::Audit(args) => args.format == "json",
        CompatibilityCommands::Export(_) => true,
    }
}

pub fn handle(command: CompatibilityCommands) -> Result<()> {
    match command {
        CompatibilityCommands::Status(args) => handle_status(args),
        CompatibilityCommands::Probe(args) => handle_probe(args),
        CompatibilityCommands::Matrix(args) => handle_matrix(args),
        CompatibilityCommands::Audit(args) => handle_audit(args),
        CompatibilityCommands::Export(args) => handle_export(args),
    }
}

fn handle_status(args: StatusArgs) -> Result<()> {
    let matrix = CapabilityMatrix::builtin();
    matrix.validate().map_err(anyhow::Error::msg)?;
    let evaluator = CompatibilityEvaluator::new(&matrix);
    let status = if let Some(protocol) = args.protocol_version {
        evaluator.evaluate_protocol(Some(protocol))
    } else {
        let resolved = resolve_network(args.network.as_deref())?;
        let cache = capability_cache(args.cache_ttl_seconds);
        match cache.get_fresh(&resolved.rpc_url, Utc::now())? {
            Some(evidence) => evaluator.evaluate_endpoint(evidence, Utc::now()),
            None => evaluator.evaluate_protocol(None),
        }
    };
    emit_status(&status, &args.format, args.output.as_deref())
}

fn handle_probe(args: ProbeArgs) -> Result<()> {
    let resolved = resolve_probe_endpoints(
        args.network.as_deref(),
        args.rpc_url.clone(),
        args.horizon_url.clone(),
    )?;
    let cache = capability_cache(args.cache_ttl_seconds);
    let now = Utc::now();
    let (evidence, source) = if !args.no_cache && !args.refresh {
        match cache.lookup(&resolved.rpc_url, now)? {
            Some(CacheLookup {
                evidence,
                fresh: true,
                ..
            }) => (evidence, "cache"),
            _ => (probe_endpoint(&resolved, &args)?, "network"),
        }
    } else {
        (probe_endpoint(&resolved, &args)?, "network")
    };
    if !args.no_cache && source == "network" {
        cache.store(evidence.clone(), now)?;
    }
    let status =
        CompatibilityEvaluator::new(&CapabilityMatrix::builtin()).evaluate_endpoint(evidence, now);
    if args.format == "json" {
        let value = serde_json::json!({
            "schema_version": crate::compatibility::COMPATIBILITY_SCHEMA_VERSION,
            "source": source,
            "status": status
        });
        emit_json(&value, args.output.as_deref())
    } else {
        if let Some(path) = args.output.as_deref() {
            write_private_json(path, &status)?;
            p::success(&format!("Compatibility probe saved to {}", path.display()));
            return Ok(());
        }
        p::header("Compatibility Probe");
        p::kv("Evidence source", source);
        render_status(&status);
        Ok(())
    }
}

fn handle_matrix(args: MatrixArgs) -> Result<()> {
    let mut matrix = CapabilityMatrix::builtin();
    matrix.validate().map_err(anyhow::Error::msg)?;
    if let Some(protocol) = args.protocol_version {
        matrix
            .protocols
            .retain(|entry| entry.protocol_version == protocol);
    }
    if args.format == "json" {
        emit_json(&matrix, args.output.as_deref())
    } else if let Some(path) = args.output.as_deref() {
        write_private_json(path, &matrix)?;
        p::success(&format!("Compatibility matrix saved to {}", path.display()));
        Ok(())
    } else {
        p::header("Stellar / Soroban Compatibility Matrix");
        p::kv("Schema", &matrix.schema_version.to_string());
        p::kv("Matrix evidence", &matrix.matrix_version);
        p::kv(
            "XDR",
            &format!(
                "{} {} (protocol {}–{})",
                matrix.xdr.crate_name,
                matrix.xdr.crate_version,
                matrix.xdr.protocol.minimum,
                matrix.xdr.protocol.maximum
            ),
        );
        println!("\n  Protocols");
        if matrix.protocols.is_empty() {
            p::warn("Requested protocol is not evidence-backed and is not considered safe.");
        }
        for protocol in matrix.protocols {
            println!(
                "    {:>3}  {:<12} XDR={} host-generation={}",
                protocol.protocol_version,
                protocol.status,
                protocol.xdr_supported,
                protocol.host_function_generation
            );
        }
        println!("\n  RPC methods");
        for method in matrix.rpc_methods {
            let requirement = if method.required_for_core {
                "core"
            } else if method.required_for_probe {
                "probe"
            } else {
                "optional"
            };
            println!(
                "    {:<24} {:<8} {}",
                method.method, requirement, method.description
            );
        }
        println!("\n  Features");
        for feature in matrix.features {
            println!(
                "    {:<24} protocol {}–{} required=[{}]",
                feature.feature,
                feature.protocol.minimum,
                feature.protocol.maximum,
                feature
                    .required_methods
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(())
    }
}

fn handle_audit(args: AuditArgs) -> Result<()> {
    let matrix = CapabilityMatrix::builtin();
    let endpoint = audit_endpoint_evidence(&args)?;
    let mut options = AuditOptions::new(&args.path);
    options.max_files = args.max_files;
    options.endpoint = endpoint;
    let report = CompatibilityAuditor::new(matrix).audit(options)?;
    if args.format == "json" {
        emit_json(&report, args.output.as_deref())?;
    } else if let Some(path) = args.output.as_deref() {
        write_private_json(path, &report)?;
        p::success(&format!("Compatibility audit saved to {}", path.display()));
    } else {
        render_audit(&report);
    }
    let threshold = match args.fail_on.as_str() {
        "incompatible" => AuditFailureThreshold::Incompatible,
        "degraded" => AuditFailureThreshold::Degraded,
        _ => AuditFailureThreshold::Never,
    };
    if report.should_fail(threshold) {
        anyhow::bail!(
            "Compatibility audit gate failed at threshold '{}' with status {}",
            args.fail_on,
            report.level
        );
    }
    Ok(())
}

fn handle_export(args: ExportArgs) -> Result<()> {
    let matrix = CapabilityMatrix::builtin();
    let endpoint = resolve_network(args.network.as_deref())
        .ok()
        .and_then(|resolved| {
            capability_cache(args.cache_ttl_seconds)
                .get_fresh(&resolved.rpc_url, Utc::now())
                .ok()
                .flatten()
        });
    let evaluator = CompatibilityEvaluator::new(&matrix);
    let status = match endpoint.clone() {
        Some(evidence) => evaluator.evaluate_endpoint(evidence, Utc::now()),
        None => evaluator.evaluate_protocol(args.protocol_version),
    };
    let audit = match args.audit_path {
        Some(path) => {
            let mut options = AuditOptions::new(path);
            options.endpoint = endpoint;
            Some(CompatibilityAuditor::new(matrix.clone()).audit(options)?)
        }
        None => None,
    };
    let export = CompatibilityExport {
        schema_version: crate::compatibility::COMPATIBILITY_SCHEMA_VERSION,
        exported_at: Utc::now(),
        matrix,
        status,
        audit,
    };
    emit_json(&export, args.output.as_deref())?;
    if let Some(path) = args.output {
        p::success(&format!(
            "Compatibility evidence exported to {}",
            path.display()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ResolvedEndpoints {
    rpc_url: String,
    horizon_url: Option<String>,
}

fn resolve_network(network: Option<&str>) -> Result<ResolvedEndpoints> {
    let cfg = config::load()?;
    let name = network.unwrap_or(&cfg.network);
    let configured = config::get_network_config(&cfg, name)
        .with_context(|| format!("Failed to resolve compatibility network '{name}'"))?;
    let rpc_url = configured.soroban_rpc_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Network '{}' has no Soroban RPC URL; configure soroban_rpc_url or pass --rpc-url to compatibility probe",
            name
        )
    })?;
    Ok(ResolvedEndpoints {
        rpc_url,
        horizon_url: Some(configured.horizon_url),
    })
}

fn resolve_probe_endpoints(
    network: Option<&str>,
    rpc_override: Option<String>,
    horizon_override: Option<String>,
) -> Result<ResolvedEndpoints> {
    if let Some(rpc_url) = rpc_override {
        return Ok(ResolvedEndpoints {
            rpc_url,
            horizon_url: horizon_override,
        });
    }
    let mut resolved = resolve_network(network)?;
    if horizon_override.is_some() {
        resolved.horizon_url = horizon_override;
    }
    Ok(resolved)
}

fn capability_cache(ttl_seconds: u64) -> CapabilityCache {
    CapabilityCache::new(
        config::config_dir().join("compatibility"),
        Duration::from_secs(ttl_seconds),
    )
}

fn probe_endpoint(resolved: &ResolvedEndpoints, args: &ProbeArgs) -> Result<EndpointEvidence> {
    let transport = UreqTransport::new(Duration::from_millis(args.timeout_ms));
    let prober = EndpointProber::new(
        transport,
        CapabilityMatrix::builtin(),
        ProbeOptions {
            probe_optional_methods: !args.core_only,
            include_horizon: resolved.horizon_url.is_some(),
        },
    );
    prober
        .probe(&resolved.rpc_url, resolved.horizon_url.as_deref())
        .map_err(|error| {
            anyhow::anyhow!(
                "Endpoint compatibility probe did not produce valid evidence: {}",
                error
            )
        })
}

fn audit_endpoint_evidence(args: &AuditArgs) -> Result<Option<EndpointEvidence>> {
    let resolved = match resolve_network(args.network.as_deref()) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let cache = capability_cache(args.cache_ttl_seconds);
    if args.probe_endpoints {
        let transport = UreqTransport::new(Duration::from_millis(args.timeout_ms));
        let evidence = EndpointProber::new(
            transport,
            CapabilityMatrix::builtin(),
            ProbeOptions::default(),
        )
        .probe(&resolved.rpc_url, resolved.horizon_url.as_deref())?;
        cache.store(evidence.clone(), Utc::now())?;
        return Ok(Some(evidence));
    }
    cache.get_fresh(&resolved.rpc_url, Utc::now())
}

fn emit_status(status: &CompatibilityStatus, format: &str, output: Option<&Path>) -> Result<()> {
    if format == "json" {
        emit_json(status, output)
    } else if let Some(path) = output {
        write_private_json(path, status)?;
        p::success(&format!("Compatibility status saved to {}", path.display()));
        Ok(())
    } else {
        render_status(status);
        Ok(())
    }
}

fn emit_json<T: serde::Serialize>(value: &T, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        write_private_json(path, value)
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
        Ok(())
    }
}

fn render_status(status: &CompatibilityStatus) {
    p::header("Compatibility Status");
    p::kv("Status", &status.level.to_string());
    p::kv("Matrix", &status.matrix_version);
    p::kv(
        "Protocol",
        &status
            .protocol_version
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into()),
    );
    if let Some(endpoint) = &status.endpoint {
        p::kv("Endpoint", &endpoint.display_endpoint);
        p::kv("Evidence time", &endpoint.observed_at.to_rfc3339());
        p::kv(
            "Latest ledger",
            &endpoint
                .latest_ledger
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into()),
        );
        p::kv(
            "Retention",
            &endpoint
                .retention_window
                .map(|value| format!("{value} ledgers"))
                .unwrap_or_else(|| "unknown".into()),
        );
    }
    println!("\n  Feature gates");
    for feature in &status.features {
        println!("    {:<28} {}", feature.feature, feature.level);
    }
    if !status.findings.is_empty() {
        println!("\n  Diagnostics");
        for finding in &status.findings {
            println!(
                "    [{}] {}: {}",
                finding.severity, finding.code, finding.summary
            );
            println!("      Action: {}", finding.action);
        }
    }
}

fn render_audit(report: &crate::compatibility::audit::AuditReport) {
    p::header("Upgrade Readiness Audit");
    p::kv("Status", &report.level.to_string());
    p::kv("Root", &report.root);
    p::kv("Files scanned", &report.inventory.files_scanned.to_string());
    p::kv(
        "WASM artifacts",
        &report.inventory.wasm_artifacts.to_string(),
    );
    p::kv(
        "Transaction fixtures",
        &report.inventory.transaction_fixtures.to_string(),
    );
    p::kv(
        "Plugin manifests",
        &report.inventory.plugin_manifests.to_string(),
    );
    p::kv(
        "Findings",
        &format!(
            "{} errors, {} warnings",
            report.error_count(),
            report.warning_count()
        ),
    );
    for finding in &report.findings {
        println!("\n  [{}] {}", finding.severity, finding.summary);
        println!("    Code:   {}", finding.code);
        println!("    Action: {}", finding.action);
    }
}

pub fn gate_feature(feature: &str, evidence: &EndpointEvidence) -> Result<()> {
    let matrix = CapabilityMatrix::builtin();
    let decision = CompatibilityEvaluator::new(&matrix)
        .gate_named_feature(feature, Some(evidence))
        .map_err(|finding| anyhow::anyhow!("{}: {}", finding.summary, finding.action))?;
    if decision.level == CompatibilityLevel::Incompatible {
        anyhow::bail!(
            "Command requires compatibility feature '{}': {} Missing RPC methods: {}",
            feature,
            decision.action,
            decision
                .missing_required_methods
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

pub fn gate_configured_feature(feature: &str, network: &str) -> Result<()> {
    let cfg = config::load()?;
    let configured = match config::get_network_config(&cfg, network) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let Some(endpoint) = configured.soroban_rpc_url else {
        return Ok(());
    };
    let cache = capability_cache(300);
    if let Some(evidence) = cache.get_fresh(&endpoint, Utc::now())? {
        gate_feature(feature, &evidence)?;
    }
    Ok(())
}
