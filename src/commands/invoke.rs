use crate::utils::{config, confirmation, print as p, soroban};
use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct InvokeArgs {
    /// Contract ID to invoke
    #[arg(long)]
    contract_id: String,

    /// Function name to call
    #[arg(long)]
    function: String,

    /// Function arguments (comma-separated)
    #[arg(long)]
    args: Option<String>,

    /// Argument types (comma-separated: string, symbol, int, bool, address)
    #[arg(long)]
    arg_types: Option<String>,

    /// Wallet to use for signing
    #[arg(long)]
    wallet: String,

    /// Network to use (overrides config)
    #[arg(long)]
    network: Option<String>,

    /// Simulate only (don't submit transaction)
    #[arg(long)]
    simulate: bool,

    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    yes: bool,
}

#[allow(dead_code)]
pub fn handle(args: InvokeArgs) -> Result<()> {
    let cfg = config::load()?;
    let network = args.network.as_ref().unwrap_or(&cfg.network);

    // Validate contract ID
    config::validate_contract_id(&args.contract_id)?;

    // Find wallet
    let wallet = cfg
        .wallets
        .iter()
        .find(|w| w.name == args.wallet)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", args.wallet))?;

    // Parse arguments
    let arg_list = parse_args(&args.args)?;
    let arg_type_list = parse_arg_types(&args.arg_types)?;

    if arg_list.len() != arg_type_list.len() {
        anyhow::bail!(
            "Argument count mismatch: {} args but {} types",
            arg_list.len(),
            arg_type_list.len()
        );
    }

    p::header(&format!(
        "Invoking contract function: {}::{}",
        args.contract_id, args.function
    ));
    p::separator();
    p::kv("Contract ID", &args.contract_id);
    p::kv("Function", &args.function);
    p::kv("Network", network);
    p::kv("Wallet", &args.wallet);

    if !arg_list.is_empty() {
        println!();
        p::info("Arguments:");
        for (i, (arg, arg_type)) in arg_list.iter().zip(arg_type_list.iter()).enumerate() {
            p::kv(&format!("  [{}] {}", i, arg_type), arg);
        }
    }

    println!();

    let submit_wallet = if args.simulate { None } else { Some(wallet) };

    p::step(
        1,
        if args.simulate { 1 } else { 2 },
        "Simulating transaction...",
    );

    let outcome = soroban::invoke_contract(
        &args.contract_id,
        &args.function,
        &arg_list,
        &arg_type_list,
        network,
        submit_wallet.map(|w| w as &crate::utils::config::WalletEntry),
    )?;

    println!();
    p::success("Simulation successful!");
    p::separator();
    p::kv_accent("Return Value", &outcome.simulation.return_value);
    p::kv(
        "Estimated Fee",
        &format!("{} stroops", outcome.simulation.fee),
    );

    if !outcome.simulation.events.is_empty() {
        println!();
        p::info(&format!("Events ({})", outcome.simulation.events.len()));
        for (i, event) in outcome.simulation.events.iter().enumerate() {
            p::kv(&format!("  [{}]", i), event);
        }
    }

    // Add confirmation before actual submission
    if !args.simulate {
        let risk_level = if *network == "mainnet" {
            confirmation::RiskLevel::High
        } else {
            confirmation::RiskLevel::Medium
        };

        let mut summary = confirmation::OperationSummary::new(
            "Invoke Contract Function".to_string(),
            network.clone(),
            risk_level,
        )
        .add("Contract ID", &args.contract_id)
        .add("Function", &args.function)
        .add("Wallet", &args.wallet)
        .add(
            "Estimated Fee",
            format!("{} stroops", outcome.simulation.fee),
        )
        .add("Return Value", &outcome.simulation.return_value);

        // Add arguments to summary if present
        if !arg_list.is_empty() {
            for (i, (arg, arg_type)) in arg_list.iter().zip(arg_type_list.iter()).enumerate() {
                summary = summary.add(format!("Arg [{}] {}", i, arg_type), arg);
            }
        }

        let confirm_config = confirmation::ConfirmationConfig {
            risk_level,
            network: network.clone(),
            skip_confirm: args.yes,
            dry_run: false,
            prompt: Some("Submit this transaction?".to_string()),
            require_type_confirmation: *network == "mainnet",
        };

        if !confirmation::confirm_operation(&summary, &confirm_config)? {
            p::info("Transaction submission cancelled.");
            return Ok(());
        }
    }

    if let Some(tx) = outcome.transaction {
        p::step(2, 2, "Submitting to network...");
        println!();
        p::success("Transaction submitted successfully!");
        p::separator();
        p::kv_accent("Transaction Hash", &tx.hash);
        p::kv_accent("Return Value", &tx.return_value);
        println!();
        p::info(&format!(
            "View on Stellar Expert: https://stellar.expert/explorer/{}/tx/{}",
            network, tx.hash
        ));
    }

    Ok(())
}

fn parse_args(args: &Option<String>) -> Result<Vec<String>> {
    match args {
        Some(s) if !s.is_empty() => Ok(s.split(',').map(|a| a.trim().to_string()).collect()),
        _ => Ok(Vec::new()),
    }
}

fn parse_arg_types(arg_types: &Option<String>) -> Result<Vec<String>> {
    match arg_types {
        Some(s) if !s.is_empty() => {
            let types: Vec<String> = s.split(',').map(|t| t.trim().to_string()).collect();
            for t in &types {
                if !matches!(t.as_str(), "string" | "symbol" | "int" | "bool" | "address") {
                    anyhow::bail!(
                        "Invalid argument type '{}'. Supported: string, symbol, int, bool, address",
                        t
                    );
                }
            }
            Ok(types)
        }
        _ => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args() {
        assert_eq!(parse_args(&None).unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_args(&Some("".to_string())).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_args(&Some("arg1,arg2,arg3".to_string())).unwrap(),
            vec!["arg1", "arg2", "arg3"]
        );
        assert_eq!(
            parse_args(&Some("arg1, arg2 , arg3".to_string())).unwrap(),
            vec!["arg1", "arg2", "arg3"]
        );
    }

    #[test]
    fn test_parse_arg_types() {
        assert_eq!(parse_arg_types(&None).unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_arg_types(&Some("string,int,bool".to_string())).unwrap(),
            vec!["string", "int", "bool"]
        );
        assert!(parse_arg_types(&Some("invalid_type".to_string())).is_err());
    }
}
