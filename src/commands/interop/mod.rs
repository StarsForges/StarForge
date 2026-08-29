//! Stellar CLI interoperability commands.

pub mod output;
pub mod stellar;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum InteropCommands {
    /// Bidirectional configuration sync with the official Stellar CLI
    #[command(subcommand)]
    Stellar(stellar::StellarInteropCommands),
}

pub fn handle(cmd: InteropCommands) -> Result<()> {
    match cmd {
        InteropCommands::Stellar(cmd) => stellar::handle(cmd),
    }
}

pub fn is_machine_readable(cmd: &InteropCommands) -> bool {
    match cmd {
        InteropCommands::Stellar(inner) => stellar::is_machine_readable(inner),
    }
}
