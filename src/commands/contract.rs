use crate::utils::{bindings, config, crypto, print as p, soroban};
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ContractCommands {
    /// Invoke a deployed Soroban contract function
    Invoke(InvokeArgs),
    /// Inspect a deployed Soroban contract instance
    Inspect(InspectArgs),
    /// Upload a WASM binary to the Stellar network (upload-only step)
    ///
    /// See: https://developers.stellar.org/docs/build/smart-contracts/getting-started/deploy-increment-contract
    Upload(UploadArgs),
    /// Generate typed client bindings from embedded WASM metadata
    GenerateBindings(GenerateBindingsArgs),
}

#[derive(Args)]
pub struct InvokeArgs {
    /// Contract ID to invoke
    pub contract_id: String,
    /// Function name to call
    pub function: String,
    /// Function arguments (use multiple --arg flags)
    #[arg(long = "arg", action = clap::ArgAction::Append)]
    pub args: Vec<String>,
    /// Argument types (use multiple --type flags, must match --arg count)
    #[arg(long = "type", action = clap::ArgAction::Append)]
    pub types: Vec<String>,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Wallet name to use for signing (required with --submit)
    #[arg(long)]
    pub wallet: Option<String>,
    /// Submit the transaction after simulation
    #[arg(long, default_value = "false")]
    pub submit: bool,
    /// Fee multiplier for transaction submission and fee bumping
    #[arg(long, default_value = "1.0")]
    pub fee_multiplier: f64,
    /// Wallet name that sponsors fees via a fee-bump envelope when submission needs it
    #[arg(long)]
    pub fee_payer: Option<String>,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Contract ID to inspect
    pub contract_id: String,
    /// Network to use; defaults to the global config network
    #[arg(long, value_parser = ["testnet", "mainnet"])]
    pub network: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct UploadArgs {
    /// Path to the compiled WASM file
    #[arg(long)]
    pub wasm: String,
    /// Network to use
    #[arg(long, default_value = "testnet", value_parser = ["testnet", "mainnet"])]
    pub network: String,
    /// Wallet name to use for signing
    #[arg(long)]
    pub wallet: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BindingLang {
    Rust,
    Ts,
}

#[derive(Args)]
pub struct GenerateBindingsArgs {
    /// Path to the compiled WASM file
    pub wasm_file: PathBuf,
    /// Binding target language
    #[arg(long, value_enum)]
    pub lang: BindingLang,
}

pub fn handle(cmd: ContractCommands) -> Result<()> {
    match cmd {
        ContractCommands::Invoke(args) => handle_invoke(args),
        ContractCommands::Inspect(args) => handle_inspect(args),
        ContractCommands::Upload(args) => handle_upload(args),
        ContractCommands::GenerateBindings(args) => handle_generate_bindings(args),
    }
}

fn handle_generate_bindings(args: GenerateBindingsArgs) -> Result<()> {
    config::validate_file_path(&args.wasm_file, Some("wasm"))?;

    let lang = match args.lang {
        BindingLang::Rust => bindings::BindingLanguage::Rust,
        BindingLang::Ts => bindings::BindingLanguage::TypeScript,
    };
    let generated = bindings::generate_bindings(&args.wasm_file, lang)?;
    println!("{}", generated);
    Ok(())
}

fn handle_inspect(args: InspectArgs) -> Result<()> {
    config::validate_contract_id(&args.contract_id)?;
    if let Some(ref net) = args.network {
        config::validate_network(net)?;
    }
    let network = resolve_network(args.network)?;

    p::header("Inspect Soroban Contract");
    p::separator();
    p::kv("Contract ID", &args.contract_id);
    p::kv("Network", &network);
    p::separator();

    println!();
    p::step(1, 1, "Querying contract instance from Soroban RPC…");
    let inspect = soroban::inspect_contract(&args.contract_id, &network)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&inspect)?);
        return Ok(());
    }

    println!();
    p::kv_accent("Contract ID", &inspect.contract_id);
    p::kv("Executable", &inspect.executable);
    p::kv(
        "WASM Hash",
        inspect
            .wasm_hash
            .as_deref()
            .unwrap_or("n/a (stellar asset contract)"),
    );
    p::kv("Storage Durability", &inspect.storage_durability);
    p::kv("Ledger Sequence", &inspect.latest_ledger.to_string());

    if let Some(last_modified) = inspect.last_modified_ledger_seq {
        p::kv("Last Modified", &last_modified.to_string());
    }

    if let Some(live_until) = inspect.live_until_ledger_seq {
        p::kv("Live Until", &live_until.to_string());
    }

    p::kv(
        "Instance Storage",
        &format!(
            "{} entr{}",
            inspect.instance_storage.len(),
            if inspect.instance_storage.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ),
    );
    p::separator();

    if inspect.instance_storage.is_empty() {
        p::info("No instance storage entries found.");
    } else {
        p::info("Instance storage:");
        for (index, entry) in inspect.instance_storage.iter().enumerate() {
            p::kv(&format!("  Key {}", index + 1), &entry.key);
            p::kv(&format!("  Val {}", index + 1), &entry.value);
        }
    }

    p::separator();
    Ok(())
}

fn handle_invoke(args: InvokeArgs) -> Result<()> {
    p::header("Invoke Soroban Contract");

    config::validate_contract_id(&args.contract_id)?;
    config::validate_network(&args.network)?;

    // Validate arguments and types match
    if args.args.len() != args.types.len() && !args.types.is_empty() {
        anyhow::bail!(
            "Argument count mismatch: {} args but {} types specified",
            args.args.len(),
            args.types.len()
        );
    }

    // Default to string type if no types specified
    let arg_types = if args.types.is_empty() {
        vec!["string".to_string(); args.args.len()]
    } else {
        args.types.clone()
    };

    p::separator();
    p::kv("Contract ID", &args.contract_id);
    p::kv("Function", &args.function);
    p::kv("Network", &args.network);

    if !args.args.is_empty() {
        p::kv("Arguments", &format!("{} args", args.args.len()));
        for (i, (arg, arg_type)) in args.args.iter().zip(arg_types.iter()).enumerate() {
            p::kv(
                &format!("  Arg {}", i + 1),
                &format!("{} ({})", arg, arg_type),
            );
        }
    } else {
        p::kv("Arguments", "none");
    }

    if args.network == "mainnet" {
        p::warn("You are invoking on MAINNET. This may cost real XLM if submitted.");
    }

    // Load and optionally decrypt wallet for submission
    let mut fee_payer_wallet: Option<crate::utils::config::WalletEntry> = None;
    let submit_wallet: Option<crate::utils::config::WalletEntry> = if args.submit {
        let cfg = config::load()?;
        let mut w = if let Some(ref wallet_name) = args.wallet {
            cfg.wallets
                .iter()
                .find(|w| &w.name == wallet_name)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Wallet '{}' not found. Run `starforge wallet list`",
                        wallet_name
                    )
                })?
                .clone()
        } else if !cfg.wallets.is_empty() {
            p::info(&format!(
                "No --wallet specified. Using: {}",
                cfg.wallets[0].name.cyan()
            ));
            cfg.wallets[0].clone()
        } else {
            anyhow::bail!(
                "No wallets found for submission. Create one first:\n  starforge wallet create deployer --fund"
            );
        };
        p::kv("Wallet", &w.name);
        if let Some(ref fee_payer_name) = args.fee_payer {
            let sponsor = cfg
                .wallets
                .iter()
                .find(|w| &w.name == fee_payer_name)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Fee payer wallet '{}' not found. Run `starforge wallet list`",
                        fee_payer_name
                    )
                })?
                .clone();
            p::kv("Fee Payer", &sponsor.name);
            fee_payer_wallet = Some(sponsor);
        }
        if let Some(sk) = &w.secret_key.clone() {
            if sk.contains(':') {
                let pwd = crypto::prompt_password(
                    &format!("Enter password to decrypt wallet '{}'", w.name),
                    false,
                )?;
                w.secret_key = Some(crypto::decrypt_secret(&pwd, sk)?);
            }
        }
        Some(w)
    } else {
        None
    };

    p::separator();

    let archival_report = match soroban::inspect_contract_archival(&args.contract_id, &args.network)
    {
        Ok(report) => {
            print_archival_preflight(&report);
            Some(report)
        }
        Err(error) => {
            p::warn(&format!("Archival preflight unavailable: {}", error));
            None
        }
    };

    if let (Some(report), Some(wallet)) = (archival_report.as_ref(), submit_wallet.as_ref()) {
        if report.needs_restore() {
            let restore_keys = report.restore_key_xdrs();
            match soroban::simulate_restore_footprint(&restore_keys, &args.network, wallet) {
                Ok(simulation) => {
                    p::warn("Archived ledger entries must be restored before submission.");
                    p::kv("Restore Fee", &format!("{} stroops", simulation.fee));
                }
                Err(error) => {
                    p::warn(&format!(
                        "Restore footprint simulation unavailable: {}",
                        error
                    ));
                }
            }
        }
    }

    // Step 1 (+ optional Step 2): delegate to shared invoke_contract()
    println!();
    p::step(
        1,
        if args.submit { 2 } else { 1 },
        "Simulating contract invocation…",
    );

    let outcome = soroban::invoke_contract(
        &args.contract_id,
        &args.function,
        &args.args,
        &arg_types,
        &args.network,
        submit_wallet.as_ref(),
        args.fee_multiplier,
        fee_payer_wallet.as_ref(),
    )?;

    let simulation_result = outcome.simulation;
    p::kv_accent("Simulation", "✓ Success");
    p::kv("Return Value", &simulation_result.return_value);
    p::kv("Fee (stroops)", &simulation_result.fee.to_string());
    p::kv(
        "Fee (XLM)",
        &format!("{:.7}", simulation_result.fee as f64 / 10_000_000.0),
    );

    if !simulation_result.events.is_empty() {
        p::kv(
            "Events",
            &format!("{} emitted", simulation_result.events.len()),
        );
        for (i, event) in simulation_result.events.iter().enumerate() {
            p::kv(&format!("  Event {}", i + 1), event);
        }
    }

    if let Some(ref footprint) = simulation_result.footprint {
        print_footprint_summary(footprint);
    }

    if let Some(tx_result) = outcome.transaction {
        println!();
        p::step(2, 2, "Submitting transaction…");
        p::kv_accent("Transaction", "✓ Submitted");
        p::kv("TX Hash", &tx_result.hash);
        p::kv("Return Value", &tx_result.return_value);
    } else if !args.submit {
        println!();
        p::info("Simulation complete. Add --submit to execute the transaction.");
    }

    p::separator();
    Ok(())
}

fn print_archival_preflight(report: &soroban::ArchivalPreflightReport) {
    if report.all_entries_live() {
        p::success("Archival preflight: target ledger entries are live");
        return;
    }

    p::warn("Archival preflight detected ledger lifecycle risk:");
    for entry in &report.entries {
        p::kv(
            &format!("  {}", entry.label),
            &format!("{:?} - {}", entry.status, entry.guidance),
        );
    }
}

fn print_footprint_summary(footprint: &soroban::StorageFootprintSummary) {
    println!();
    p::info("Storage footprint:");
    p::kv("  Read-only keys", &footprint.read_only.len().to_string());
    p::kv("  Read-write keys", &footprint.read_write.len().to_string());
    p::kv("  Total keys", &footprint.total_keys().to_string());

    for key in footprint
        .read_only
        .iter()
        .chain(footprint.read_write.iter())
    {
        let access = match key.access {
            soroban::FootprintAccess::ReadOnly => "read-only",
            soroban::FootprintAccess::ReadWrite => "read-write",
        };
        p::kv(
            &format!("  {}", access),
            &format!("{} ({} bytes)", key.key, key.size_hint_bytes),
        );
    }
}

fn handle_upload(args: UploadArgs) -> Result<()> {
    config::validate_network(&args.network)?;

    p::header("Upload WASM to Stellar Network");
    p::separator();
    p::kv("WASM", &args.wasm);
    p::kv("Network", &args.network);

    if args.network == "mainnet" {
        p::warn("You are uploading on MAINNET. This will cost real XLM.");
    }

    let cfg = config::load()?;
    let wallet = if let Some(ref name) = args.wallet {
        cfg.wallets
            .iter()
            .find(|w| &w.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!("Wallet '{}' not found. Run `starforge wallet list`", name)
            })?
            .clone()
    } else if !cfg.wallets.is_empty() {
        p::info(&format!(
            "No --wallet specified. Using: {}",
            cfg.wallets[0].name.cyan()
        ));
        cfg.wallets[0].clone()
    } else {
        anyhow::bail!(
            "No wallets found. Create one first:\n  starforge wallet create deployer --fund"
        );
    };

    p::kv("Wallet", &wallet.name);
    p::separator();

    println!();
    p::step(1, 1, "Uploading WASM binary…");

    let wasm_hash = soroban::upload_wasm(&args.wasm, &args.network, &wallet)?;

    println!();
    p::kv_accent("WASM Hash", &wasm_hash);
    p::success("WASM uploaded successfully.");
    println!();
    p::info("Next step — create the contract instance:");
    p::info(&format!(
        "  stellar contract deploy --wasm-hash {} --network {} --source {}",
        wasm_hash, args.network, wallet.name
    ));
    println!();
    Ok(())
}

fn resolve_network(network_override: Option<String>) -> Result<String> {
    let network = network_override.unwrap_or(config::load()?.network);
    match network.as_str() {
        "testnet" | "mainnet" => Ok(network),
        _ => anyhow::bail!(
            "Unsupported network '{}'. Use 'testnet' or 'mainnet'.",
            network
        ),
    }
}
