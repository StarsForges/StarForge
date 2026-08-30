use clap::{Args, Subcommand};
use anyhow::Result;
use colored::*;

use super::core::{GovernanceEngine, ProposalStatus, ApprovalAttestation};
use super::manifest::{ProposalManifest, GovernanceOperation};

#[derive(Subcommand, Debug, Clone)]
pub enum GovernanceCommands {
    Create(CreateArgs),
    Validate(ValidateArgs),
    Approve(ApproveArgs),
    Status(StatusArgs),
    Execute(ExecuteArgs),
    Cancel(CancelArgs),
    Audit(AuditArgs),
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(long)] pub title: String,
    #[arg(long)] pub description: String,
    #[arg(long)] pub action: String,
}

#[derive(Args, Debug, Clone)]
pub struct ValidateArgs { #[arg(long)] pub id: String, }

#[derive(Args, Debug, Clone)]
pub struct ApproveArgs { 
    #[arg(long)] pub id: String,
    #[arg(long)] pub signer: String,
    #[arg(long)] pub weight: u32,
}

#[derive(Args, Debug, Clone)]
pub struct StatusArgs { #[arg(long)] pub id: String, }

#[derive(Args, Debug, Clone)]
pub struct ExecuteArgs { #[arg(long)] pub id: String, }

#[derive(Args, Debug, Clone)]
pub struct CancelArgs {
    #[arg(long)] pub id: String,
    #[arg(long)] pub reason: String,
}

#[derive(Args, Debug, Clone)]
pub struct AuditArgs { #[arg(long)] pub id: Option<String>, }

pub fn handle(cmd: GovernanceCommands) -> Result<()> {
    let mut engine = GovernanceEngine::new(".starforge/governance")?;
    match cmd {
        GovernanceCommands::Create(args) => {
            let id = engine.create_proposal(&args.title, &args.description, "author_cli", vec![], Default::default(), Default::default(), None, vec![], vec![])?;
            println!("Created proposal: {}", id);
        },
        GovernanceCommands::Validate(args) => {
            engine.validate_proposal(&args.id)?;
            println!("Proposal valid");
        },
        GovernanceCommands::Approve(args) => {
            let att = ApprovalAttestation {
                proposal_id: args.id.clone(),
                signer: args.signer,
                signature: "sig".to_string(),
                weight: args.weight,
                timestamp: chrono::Utc::now(),
            };
            engine.submit_approval(att)?;
            println!("Proposal approved");
        },
        GovernanceCommands::Status(args) => {
            let status = engine.get_status(&args.id)?;
            println!("Status: {:?}", status);
        },
        GovernanceCommands::Execute(args) => {
            engine.execute_proposal(&args.id)?;
            println!("Executed proposal");
        },
        GovernanceCommands::Cancel(args) => {
            engine.cancel_proposal(&args.id, &args.reason)?;
            println!("Canceled proposal");
        },
        GovernanceCommands::Audit(args) => {
            let audit = engine.audit(args.id.as_deref())?;
            println!("{}", audit);
        }
    }
    Ok(())
}
