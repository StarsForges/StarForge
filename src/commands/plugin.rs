use crate::plugins::interface::CORE_VERSION;
use crate::plugins::manifest;
use crate::plugins::registry::{self, RegisteredCommand, TrustLevel, UninstallOptions};
use crate::plugins::{PluginLoadError, PluginManager};
use crate::utils::print as p;
use anyhow::{Context, Result};
use clap::Subcommand;
use std::path::Path;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum PluginCommands {
    /// Register a plugin shared library for StarForge to load
    ///
    /// Example: starforge plugin install starforge-defi --path ./libstarforge_defi.so
    Install {
        /// Plugin name (used as the command name)
        name: String,
        /// Path to the plugin shared library (.so/.dylib/.dll)
        #[arg(long)]
        path: Option<PathBuf>,
        /// Source URL or identifier for trust classification
        #[arg(long)]
        source: Option<String>,
        /// Install even if the plugin source is untrusted (requires explicit confirmation)
        #[arg(long)]
        force: bool,
    },
    /// List installed plugins from the local registry
    List,
    /// Load installed plugins and show those successfully loaded
    Load,
    /// Remove a plugin from the registry
    ///
    /// Example: starforge plugin uninstall starforge-defi
    Uninstall {
        /// Plugin name to remove
        name: String,
        /// Also delete the plugin library file from disk (only under ~/.starforge/plugins/)
        #[arg(long)]
        purge: bool,
        /// Skip confirmation for destructive removal
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Verify trust and compatibility of installed plugins
    Verify {
        /// Plugin name to verify (verifies all plugins if omitted)
        name: Option<String>,
        /// Run the full audit checks, including manifest validation
        #[arg(long)]
        deep: bool,
        /// Attempt to load each plugin as an optional runtime self-check
        #[arg(long)]
        runtime_check: bool,
    },
    /// Audit installed plugins for filesystem, trust, manifest, compatibility, and runtime issues
    Audit {
        /// Plugin name to audit (audits all plugins if omitted)
        name: Option<String>,
        /// Attempt to load each plugin as an optional runtime self-check
        #[arg(long)]
        runtime_check: bool,
    },
    /// Update installed plugins to their latest versions
    ///
    /// Checks each plugin's source URL, validates compatibility with the running
    /// CLI, and replaces the local library if a newer copy is available.
    /// Configuration and trust settings are preserved.
    ///
    /// Example: starforge plugin update
    ///          starforge plugin update starforge-defi
    Update {
        /// Plugin name to update (updates all plugins if omitted)
        name: Option<String>,
        /// Skip confirmation prompt
        #[arg(long, default_value = "false")]
        yes: bool,
    },
    /// List commands registered by installed plugins
    Commands {
        /// Show commands for a specific plugin only
        name: Option<String>,
    },
}

pub fn handle(cmd: PluginCommands) -> Result<()> {
    match cmd {
        PluginCommands::Install {
            name,
            path,
            source,
            force,
        } => install(name, path, source, force),
        PluginCommands::List => list(),
        PluginCommands::Load => load(),
        PluginCommands::Uninstall { name, purge, yes } => uninstall(name, purge, yes),
        PluginCommands::Verify {
            name,
            deep,
            runtime_check,
        } => verify(name, deep, runtime_check),
        PluginCommands::Audit {
            name,
            runtime_check,
        } => audit(name, runtime_check),
        PluginCommands::Update { name, yes } => update(name, yes),
        PluginCommands::Commands { name } => commands(name),
    }
}

fn install(name: String, path: Option<PathBuf>, source: Option<String>, force: bool) -> Result<()> {
    let lib_path = registry::resolve_plugin_library_path(&name, path)?;
    let source_str = source.as_deref().unwrap_or("");
    let config = crate::utils::config::load().unwrap_or_default();
    let trust = registry::classify_source(source_str);

    // Warn the user about untrusted sources and require --force to proceed.
    if trust == TrustLevel::Unknown && !source_str.is_empty() && !force {
        p::header("Plugin Install — Trust Warning");
        p::warn(&format!(
            "Plugin source '{}' is not in the trusted sources list.",
            source_str
        ));
        p::info("Trusted sources:");
        for src in &config.plugin_trust.trusted_sources {
            p::info(&format!("  • {}", src));
        }
        p::info("");
        p::info("To install anyway: starforge plugin install <name> --source <url> --force");
        p::info("To install from a local path (always trusted): starforge plugin install <name> --path <lib>");
        anyhow::bail!("Refusing to install plugin from untrusted source without --force");
    }

    let plugin_manifest = manifest::require_compatible_manifest(&lib_path, &name)?;

    // Command discovery is best-effort: install records the manifest/path, while
    // audit/load report runtime library failures with richer diagnostics.
    let discovered_commands: Vec<RegisteredCommand> = match discover_commands_from_library(
        lib_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Plugin path is not valid UTF-8"))?,
    ) {
        Ok(commands) => commands,
        Err(error) => {
            p::warn(&format!(
                "Plugin registered without command discovery: {}",
                error
            ));
            Vec::new()
        }
    };

    registry::install_plugin(
        &name,
        &lib_path,
        source_str,
        &plugin_manifest.starforge_version,
        &plugin_manifest.version,
        discovered_commands.clone(),
    )?;

    p::header("Plugin Install");
    p::success("Plugin registered");
    p::kv_accent("Name", &name);
    p::kv("Library", &lib_path.display().to_string());
    p::kv("Plugin version", &plugin_manifest.version);
    p::kv(
        "StarForge compatibility",
        &plugin_manifest.starforge_version,
    );
    p::kv("Trust", trust.label());
    if !source_str.is_empty() {
        p::kv("Source", source_str);
    }
    if !discovered_commands.is_empty() {
        p::info("Registered commands:");
        for cmd in &discovered_commands {
            p::info(&format!("  • {}  — {}", cmd.name, cmd.description));
        }
    }
    p::info("Load plugins with: starforge plugin load");
    Ok(())
}

fn list() -> Result<()> {
    p::header("Installed Plugins");
    let reg = registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        p::info("No plugins installed. Use: starforge plugin install <name> --path <lib>");
        return Ok(());
    }

    p::kv("StarForge core version", CORE_VERSION);
    p::separator();
    for (i, pl) in reg.plugins.iter().enumerate() {
        println!("  {:>2}. {}", i + 1, pl.name);
        p::kv("Path", &pl.path);
        p::kv("Trust", pl.trust.label());
        if !pl.source.is_empty() {
            p::kv("Source", &pl.source);
        }
        if !pl.starforge_version.is_empty() {
            p::kv("StarForge", &pl.starforge_version);
        }
        if i < reg.plugins.len() - 1 {
            println!();
        }
    }
    p::separator();
    Ok(())
}

fn load() -> Result<()> {
    p::header("Plugin Loader");

    let reg = registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        p::info("No plugins installed. Use: starforge plugin install <name> --path <lib>");
        return Ok(());
    }

    let _config = crate::utils::config::load().unwrap_or_default();

    // Warn about any unknown-trust plugins before loading.
    for pl in reg.plugins.iter().filter(|p| {
        registry::classify_source(&p.source) == TrustLevel::Unknown && !p.source.is_empty()
    }) {
        p::warn(&format!(
            "Plugin '{}' is from an unknown/untrusted source: {}",
            pl.name, pl.source
        ));
    }

    let mut pm = PluginManager::new();
    let mut failed: Vec<(String, PluginLoadError)> = Vec::new();

    for pl in &reg.plugins {
        match unsafe { pm.load_plugin_diagnosed(&pl.path) } {
            Ok(()) => {}
            Err(e) => failed.push((pl.name.clone(), e)),
        }
    }

    // ── Report failures with structured diagnostics ──────────────────────────
    if !failed.is_empty() {
        p::warn(&format!("{} plugin(s) failed to load:", failed.len()));
        for (name, err) in &failed {
            println!();
            p::error(&format!("[{}] {}", err.category(), name));
            for line in err.diagnostic().lines() {
                println!("  {}", line);
            }
        }
        println!();
    }

    let loaded = pm.list_plugins();
    if loaded.is_empty() && failed.is_empty() {
        p::warn("No plugins loaded.");
        return Ok(());
    }

    if !loaded.is_empty() {
        p::kv("StarForge core version", CORE_VERSION);
        p::separator();
        for (name, desc, built_for) in loaded {
            p::kv_accent(name, desc);
            p::kv("Built for StarForge", built_for);
        }
        p::separator();
    }

    if !failed.is_empty() {
        anyhow::bail!(
            "{} plugin(s) failed to load. See diagnostics above.",
            failed.len()
        );
    }

    Ok(())
}

fn uninstall(name: String, purge: bool, yes: bool) -> Result<()> {
    let reg = registry::load_registry().unwrap_or_default();
    let plugin = reg.plugins.iter().find(|p| p.name == name).ok_or_else(|| {
        anyhow::anyhow!(
            "Plugin '{}' is not installed. Run `starforge plugin list` to see installed plugins.",
            name
        )
    })?;

    let lib_path = PathBuf::from(&plugin.path);
    let lib_exists = lib_path.exists();

    p::header("Plugin Uninstall");
    p::kv_accent("Plugin", &name);
    p::kv("Library", &plugin.path);

    if lib_exists {
        p::warn(
            "If this plugin is loaded in another StarForge session, close that session before purging files.",
        );
    } else {
        p::warn("Plugin library file is already missing on disk.");
    }

    if purge && !yes {
        p::warn("This will permanently delete the plugin library file.");
        p::info("Proceed with: starforge plugin uninstall <name> --purge --yes");
        anyhow::bail!("Refusing destructive uninstall without --yes");
    }

    // Best-effort: load plugin to run on_unload before registry removal
    if lib_exists {
        let mut pm = PluginManager::new();
        if let Err(e) = unsafe { pm.load_plugin(&lib_path) } {
            p::warn(&format!(
                "Could not load plugin for clean shutdown: {}. Proceeding with uninstall.",
                e
            ));
        } else {
            p::info("Plugin unloaded cleanly.");
        }
    }

    let opts = UninstallOptions {
        purge_files: purge,
        assume_yes: yes,
    };
    let report = registry::uninstall_plugin(&name, &opts)?;

    p::success(&format!("Plugin '{}' removed from registry", name));
    if report.files_removed {
        p::success("Plugin library file deleted.");
    } else if !purge {
        p::info("Library file kept on disk. Use --purge --yes to delete it.");
    }
    if report.library_was_missing && !report.files_removed {
        p::info("No library file was present to remove.");
    }

    Ok(())
}

fn update(name: Option<String>, yes: bool) -> Result<()> {
    p::header("Plugin Update");

    let reg = registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        p::info("No plugins installed. Use: starforge plugin install <name> --path <lib>");
        return Ok(());
    }

    let _config = crate::utils::config::load().unwrap_or_default();

    let to_update: Vec<_> = match &name {
        Some(n) => {
            let found: Vec<_> = reg.plugins.iter().filter(|p| &p.name == n).collect();
            if found.is_empty() {
                anyhow::bail!(
                    "Plugin '{}' is not installed. Run `starforge plugin list`.",
                    n
                );
            }
            found
        }
        None => reg.plugins.iter().collect(),
    };

    p::kv("Plugins to check", &to_update.len().to_string());
    p::kv("StarForge core version", CORE_VERSION);
    p::separator();

    let mut updated = 0u32;
    let mut skipped = 0u32;
    let mut failed = 0u32;

    for pl in &to_update {
        println!("  Checking: {}", pl.name);

        // Verify the library still exists at its registered path.
        let lib_exists = std::path::Path::new(&pl.path).exists();
        if !lib_exists {
            p::warn(&format!(
                "  '{}' library missing at {}. Re-install with: starforge plugin install {} --path <lib>",
                pl.name, pl.path, pl.name
            ));
            failed += 1;
            println!();
            continue;
        }

        // Only plugins with a non-empty, trusted source URL can be fetched remotely.
        if pl.source.is_empty() {
            p::info(&format!(
                "  '{}' was installed from a local path — no remote source to fetch from.",
                pl.name
            ));
            p::kv("  Path", &pl.path);
            skipped += 1;
            println!();
            continue;
        }

        let trust = registry::classify_source(&pl.source);
        if trust == TrustLevel::Unknown && !yes {
            p::warn(&format!(
                "  '{}' source '{}' is not trusted. Use --yes to force update from unknown sources.",
                pl.name, pl.source
            ));
            skipped += 1;
            println!();
            continue;
        }

        // For trusted/confirmed sources, re-install the plugin library.
        // This re-uses the existing path — the user is responsible for
        // placing an updated .so/.dylib at the same location, or the source
        // URL must be a direct download endpoint.
        //
        // For crates.io sources we attempt to download via `cargo install`.
        if pl.source.starts_with("https://crates.io/crates/") {
            let crate_name = pl
                .source
                .trim_start_matches("https://crates.io/crates/")
                .split('/')
                .next()
                .unwrap_or(&pl.name);

            p::info(&format!("  Attempting `cargo install {}` ...", crate_name));
            let status = std::process::Command::new("cargo")
                .args(["install", crate_name, "--force"])
                .status();

            match status {
                Ok(s) if s.success() => {
                    registry::install_plugin(
                        &pl.name,
                        std::path::Path::new(&pl.path),
                        &pl.source,
                        &pl.starforge_version,
                        &pl.plugin_version,
                        pl.commands.clone(),
                    )?;
                    p::success(&format!("  '{}' updated via cargo install", pl.name));
                    updated += 1;
                }
                Ok(s) => {
                    p::warn(&format!(
                        "  cargo install exited with status {}. Plugin not updated.",
                        s
                    ));
                    failed += 1;
                }
                Err(e) => {
                    p::warn(&format!(
                        "  Failed to run cargo: {}. Is Cargo installed?",
                        e
                    ));
                    failed += 1;
                }
            }
        } else {
            // For GitHub and other sources, check if the library file on disk
            // has been updated since install and refresh the registry timestamp.
            let metadata = std::fs::metadata(&pl.path);
            match metadata {
                Ok(m) => {
                    let modified = m
                        .modified()
                        .ok()
                        .and_then(|t| {
                            t.duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .map(|d| d.as_secs())
                        })
                        .unwrap_or(0);

                    let installed_epoch = 0u64;

                    if modified > installed_epoch {
                        // Library on disk is newer — refresh the registry entry.
                        let cmds = discover_commands_from_library(&pl.path)
                            .unwrap_or_else(|_| pl.commands.clone());
                        registry::install_plugin(
                            &pl.name,
                            std::path::Path::new(&pl.path),
                            &pl.source,
                            &pl.starforge_version,
                            &pl.plugin_version,
                            cmds,
                        )?;
                        p::success(&format!(
                            "  '{}' library on disk is newer — registry refreshed.",
                            pl.name
                        ));
                        updated += 1;
                    } else {
                        p::info(&format!(
                            "  '{}' is already up to date. Source: {}",
                            pl.name, pl.source
                        ));
                        p::info(
                            "  To update manually: replace the library at the registered path,",
                        );
                        p::info(&format!("  then run: starforge plugin update {}", pl.name));
                        skipped += 1;
                    }
                }
                Err(e) => {
                    p::warn(&format!("  Could not read library metadata: {}", e));
                    failed += 1;
                }
            }
        }

        println!();
    }

    p::separator();
    p::kv("Updated", &updated.to_string());
    p::kv("Skipped (already current / local)", &skipped.to_string());
    p::kv("Failed", &failed.to_string());

    if failed > 0 {
        anyhow::bail!("{} plugin(s) failed to update. See warnings above.", failed);
    }

    Ok(())
}

fn verify(name: Option<String>, deep: bool, runtime_check: bool) -> Result<()> {
    if deep || runtime_check {
        return run_audit(name, runtime_check);
    }

    p::header("Plugin Verification");

    let reg = registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        p::info("No plugins installed.");
        return Ok(());
    }

    let to_check: Vec<_> = match &name {
        Some(n) => {
            let found: Vec<_> = reg.plugins.iter().filter(|p| &p.name == n).collect();
            if found.is_empty() {
                anyhow::bail!("Plugin '{}' is not installed.", n);
            }
            found
        }
        None => reg.plugins.iter().collect(),
    };

    let _config = crate::utils::config::load().unwrap_or_default();
    let mut all_ok = true;

    for pl in &to_check {
        let lib_exists = std::path::Path::new(&pl.path).exists();

        let current_trust = registry::classify_source(&pl.source);
        let trust_ok = match current_trust {
            TrustLevel::Local | TrustLevel::Trusted => true,
            TrustLevel::Unknown => false,
        };

        let compat_ok = if pl.starforge_version.is_empty() {
            true
        } else {
            crate::plugins::interface::is_core_version_compatible(&pl.starforge_version)
        };

        let status = if lib_exists && trust_ok && compat_ok {
            "✓ OK"
        } else if !lib_exists {
            all_ok = false;
            "✗ library missing"
        } else if !compat_ok {
            all_ok = false;
            "✗ incompatible"
        } else {
            all_ok = false;
            "⚠ untrusted source"
        };

        println!(
            "  {:<24} [{}]  trust={}",
            pl.name,
            status,
            current_trust.label()
        );
        if !pl.starforge_version.is_empty() {
            p::kv("StarForge", &pl.starforge_version);
        }
        if !pl.source.is_empty() {
            p::kv("Source", &pl.source);
        }
        if !lib_exists {
            p::warn(&format!("Library not found at: {}", pl.path));
            p::info("Re-install with: starforge plugin install <name> --path <lib>");
        }
        if current_trust == TrustLevel::Unknown && !pl.source.is_empty() {
            p::warn("Source is not in the trusted sources list.");
            p::info("Check your CLI config for trusted sources.");
        }
        if !compat_ok && !pl.starforge_version.is_empty() {
            p::warn(&format!(
                "Plugin targets StarForge {} but running {}",
                pl.starforge_version, CORE_VERSION
            ));
            p::info("Reinstall a compatible build or upgrade StarForge.");
        }
    }

    if all_ok {
        p::success("All checked plugins passed verification.");
    }

    Ok(())
}

fn audit(name: Option<String>, runtime_check: bool) -> Result<()> {
    run_audit(name, runtime_check)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditSeverity {
    Pass,
    Warn,
    Fail,
}

impl AuditSeverity {
    fn label(self) -> &'static str {
        match self {
            AuditSeverity::Pass => "pass",
            AuditSeverity::Warn => "warn",
            AuditSeverity::Fail => "fail",
        }
    }
}

#[derive(Debug)]
struct AuditCheck {
    name: &'static str,
    severity: AuditSeverity,
    message: String,
}

#[derive(Debug)]
struct AuditReport {
    plugin_name: String,
    checks: Vec<AuditCheck>,
}

impl AuditReport {
    fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.severity == AuditSeverity::Fail)
    }

    fn has_warnings(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.severity == AuditSeverity::Warn)
    }
}

fn run_audit(name: Option<String>, runtime_check: bool) -> Result<()> {
    p::header("Plugin Audit");

    let reg = registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        p::info("No plugins installed.");
        return Ok(());
    }

    let to_check: Vec<_> = match &name {
        Some(n) => {
            let found: Vec<_> = reg.plugins.iter().filter(|p| &p.name == n).collect();
            if found.is_empty() {
                anyhow::bail!(
                    "Plugin '{}' is not installed. Run `starforge plugin list`.",
                    n
                );
            }
            found
        }
        None => reg.plugins.iter().collect(),
    };

    p::kv("StarForge core version", CORE_VERSION);
    p::kv(
        "Runtime self-check",
        if runtime_check { "enabled" } else { "disabled" },
    );
    p::separator();

    let mut failed = 0usize;
    let mut warned = 0usize;

    for plugin in to_check {
        let report = audit_plugin(plugin, runtime_check);
        if report.has_failures() {
            failed += 1;
        }
        if report.has_warnings() {
            warned += 1;
        }
        print_audit_report(&report);
    }

    p::separator();
    p::kv("Plugins failed", &failed.to_string());
    p::kv("Plugins with warnings", &warned.to_string());

    if failed > 0 {
        anyhow::bail!("{} plugin(s) failed audit checks.", failed);
    }

    p::success("All audited plugins passed required checks.");
    Ok(())
}

fn audit_plugin(plugin: &registry::InstalledPlugin, runtime_check: bool) -> AuditReport {
    let mut checks = Vec::new();
    let library_path = Path::new(&plugin.path);

    if library_path.exists() {
        checks.push(AuditCheck {
            name: "file",
            severity: AuditSeverity::Pass,
            message: format!("Library exists at {}", plugin.path),
        });
    } else {
        checks.push(AuditCheck {
            name: "file",
            severity: AuditSeverity::Fail,
            message: format!("Library missing at {}", plugin.path),
        });
        return AuditReport {
            plugin_name: plugin.name.clone(),
            checks,
        };
    }

    let classified = registry::classify_source(&plugin.source);
    if classified == plugin.trust {
        checks.push(AuditCheck {
            name: "trust",
            severity: match plugin.trust {
                TrustLevel::Unknown => AuditSeverity::Warn,
                TrustLevel::Local | TrustLevel::Trusted => AuditSeverity::Pass,
            },
            message: format!("Trust level is {}", plugin.trust.label()),
        });
    } else {
        checks.push(AuditCheck {
            name: "trust",
            severity: AuditSeverity::Fail,
            message: format!(
                "Registry trust is {}, but source now classifies as {}",
                plugin.trust.label(),
                classified.label()
            ),
        });
    }

    if plugin.starforge_version.is_empty() {
        checks.push(AuditCheck {
            name: "compatibility",
            severity: AuditSeverity::Fail,
            message: "Registry is missing StarForge compatibility metadata".to_string(),
        });
    } else if crate::plugins::interface::is_core_version_compatible(&plugin.starforge_version) {
        checks.push(AuditCheck {
            name: "compatibility",
            severity: AuditSeverity::Pass,
            message: format!("Compatible with StarForge {}", plugin.starforge_version),
        });
    } else {
        checks.push(AuditCheck {
            name: "compatibility",
            severity: AuditSeverity::Fail,
            message: format!(
                "Plugin targets StarForge {}, running {}",
                plugin.starforge_version, CORE_VERSION
            ),
        });
    }

    match manifest::load_manifest_for_library(library_path) {
        Ok(Some(plugin_manifest)) => {
            if plugin_manifest.name != plugin.name {
                checks.push(AuditCheck {
                    name: "manifest",
                    severity: AuditSeverity::Fail,
                    message: format!(
                        "Manifest name '{}' does not match registry name '{}'",
                        plugin_manifest.name, plugin.name
                    ),
                });
            }

            if plugin_manifest.version != plugin.plugin_version {
                checks.push(AuditCheck {
                    name: "manifest",
                    severity: AuditSeverity::Warn,
                    message: format!(
                        "Manifest version {} differs from registry version {}",
                        plugin_manifest.version, plugin.plugin_version
                    ),
                });
            }

            match plugin_manifest.validate() {
                Ok(()) => checks.push(AuditCheck {
                    name: "manifest",
                    severity: AuditSeverity::Pass,
                    message: "Manifest is valid".to_string(),
                }),
                Err(err) => checks.push(AuditCheck {
                    name: "manifest",
                    severity: AuditSeverity::Fail,
                    message: err.to_string(),
                }),
            }
        }
        Ok(None) => checks.push(AuditCheck {
            name: "manifest",
            severity: AuditSeverity::Fail,
            message: format!("Missing {}", manifest::MANIFEST_FILENAME),
        }),
        Err(err) => checks.push(AuditCheck {
            name: "manifest",
            severity: AuditSeverity::Fail,
            message: err.to_string(),
        }),
    }

    if runtime_check {
        let mut manager = PluginManager::new();
        match unsafe { manager.load_plugin(library_path) } {
            Ok(()) => checks.push(AuditCheck {
                name: "runtime",
                severity: AuditSeverity::Pass,
                message: "Plugin loaded successfully".to_string(),
            }),
            Err(err) => checks.push(AuditCheck {
                name: "runtime",
                severity: AuditSeverity::Fail,
                message: err.to_string(),
            }),
        }
    }

    AuditReport {
        plugin_name: plugin.name.clone(),
        checks,
    }
}

fn print_audit_report(report: &AuditReport) {
    p::kv_accent("Plugin", &report.plugin_name);
    for check in &report.checks {
        let marker = match check.severity {
            AuditSeverity::Pass => "✓",
            AuditSeverity::Warn => "⚠",
            AuditSeverity::Fail => "✗",
        };
        println!(
            "  {} {:<13} {:<4} {}",
            marker,
            check.name,
            check.severity.label(),
            check.message
        );
    }
    println!();
}

fn discover_commands_from_library(path: &str) -> Result<Vec<RegisteredCommand>> {
    let mut pm = PluginManager::new();
    unsafe {
        pm.load_plugin(path)
            .with_context(|| format!("Failed to load plugin from {}", path))?;
    }
    Ok(pm
        .list_commands()
        .into_iter()
        .map(|c| RegisteredCommand {
            name: c.name,
            description: c.description,
        })
        .collect())
}

fn commands(name: Option<String>) -> Result<()> {
    p::header("Plugin Commands");

    let reg = registry::load_registry().unwrap_or_default();
    if reg.plugins.is_empty() {
        p::info("No plugins installed. Use: starforge plugin install <name> --path <lib>");
        return Ok(());
    }

    let plugins: Vec<_> = match &name {
        Some(n) => {
            let found: Vec<_> = reg.plugins.iter().filter(|p| &p.name == n).collect();
            if found.is_empty() {
                anyhow::bail!(
                    "Plugin '{}' is not installed. Run `starforge plugin list`.",
                    n
                );
            }
            found
        }
        None => reg.plugins.iter().collect(),
    };

    let mut any = false;
    for pl in &plugins {
        if pl.commands.is_empty() {
            continue;
        }
        any = true;
        p::kv_accent("Plugin", &pl.name);
        for cmd in &pl.commands {
            println!("  starforge {}  — {}", cmd.name, cmd.description);
        }
        println!();
    }

    if !any {
        p::info("No commands registered. Re-install plugins to discover their commands.");
        p::info("  starforge plugin install <name> --path <lib>");
    }

    Ok(())
}
