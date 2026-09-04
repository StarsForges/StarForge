use super::manifest::{ExecutionCondition, GovernanceOperation, ProposalManifest};
use anyhow::{bail, Result};
use regex::Regex;

pub struct ProposalValidator;

impl ProposalValidator {
    pub fn validate(manifest: &ProposalManifest) -> Result<()> {
        Self::validate_basics(manifest)?;
        Self::validate_thresholds(&manifest.thresholds)?;
        Self::validate_timing(manifest)?;
        Self::validate_operations(&manifest.operations)?;
        Self::validate_conditions(&manifest.execution_conditions)?;
        Self::validate_metadata(&manifest.metadata)?;
        Ok(())
    }

    fn validate_basics(manifest: &ProposalManifest) -> Result<()> {
        if manifest.version == 0 || manifest.version > 2 {
            bail!("Invalid version {}", manifest.version);
        }
        if manifest.id.is_empty() {
            bail!("Invalid empty ID");
        }
        if manifest.title.is_empty() || manifest.title.len() > 200 {
            bail!("Title must be between 1 and 200 characters");
        }
        if manifest.author.is_empty() {
            bail!("Author cannot be empty");
        }
        Ok(())
    }

    fn validate_thresholds(thresholds: &super::manifest::ApprovalThresholds) -> Result<()> {
        if thresholds.required_weight == 0 {
            bail!("Required weight must be > 0");
        }
        if thresholds.quorum_percentage == 0 || thresholds.quorum_percentage > 100 {
            bail!("Quorum percentage must be between 1 and 100");
        }
        if let Some(veto) = thresholds.veto_threshold {
            if veto == 0 {
                bail!("Veto threshold must be > 0");
            }
        }
        Ok(())
    }

    fn validate_timing(manifest: &ProposalManifest) -> Result<()> {
        if manifest.voting_window.end_time <= manifest.voting_window.start_time {
            bail!("Voting window end time must be after start time");
        }
        if let Some(tl) = &manifest.timelock {
            if tl.delay_seconds == 0 {
                bail!("Timelock delay must be > 0");
            }
            if let Some(max_delay) = tl.max_delay_seconds {
                if max_delay < tl.delay_seconds {
                    bail!("Max delay cannot be less than standard delay");
                }
            }
        }
        Ok(())
    }

    fn validate_operations(operations: &[GovernanceOperation]) -> Result<()> {
        if operations.is_empty() {
            bail!("No operations provided");
        }
        if operations.len() > 100 {
            bail!("Maximum 100 operations allowed per proposal");
        }

        let account_regex = Regex::new(r"^G[A-Z2-7]{55}$").unwrap();
        let contract_regex = Regex::new(r"^C[A-Z2-7]{55}$").unwrap();

        for op in operations {
            match op {
                GovernanceOperation::Transfer { amount, to, .. } => {
                    if *amount == 0 {
                        bail!("Transfer amount must be > 0");
                    }
                    if !account_regex.is_match(to) {
                        bail!("Invalid account ID format");
                    }
                }
                GovernanceOperation::ChangeThresholds { low, med, high } => {
                    if low > med || med > high {
                        bail!("Invalid threshold ordering (low <= med <= high)");
                    }
                }
                GovernanceOperation::Payment {
                    amount,
                    destination,
                    ..
                } => {
                    if *amount == 0 {
                        bail!("Payment amount must be > 0");
                    }
                    if !account_regex.is_match(destination) {
                        bail!("Invalid account ID format for destination");
                    }
                }
                GovernanceOperation::SetOptions {
                    signer,
                    weight,
                    master_weight,
                } => {
                    if let Some(w) = weight {
                        if *w > 255 {
                            bail!("Signer weight cannot exceed 255");
                        }
                    }
                    if let Some(m) = master_weight {
                        if *m > 255 {
                            bail!("Master weight cannot exceed 255");
                        }
                    }
                    if let Some(s) = signer {
                        if !account_regex.is_match(s) {
                            bail!("Invalid signer account ID format");
                        }
                    }
                }
                GovernanceOperation::CreateAccount {
                    destination,
                    starting_balance,
                } => {
                    if *starting_balance == 0 {
                        bail!("Starting balance must be > 0");
                    }
                    if !account_regex.is_match(destination) {
                        bail!("Invalid destination account ID format");
                    }
                }
                GovernanceOperation::InvokeContract { contract_id, .. } => {
                    if !contract_regex.is_match(contract_id) {
                        bail!("Invalid contract ID format");
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn validate_conditions(conditions: &[ExecutionCondition]) -> Result<()> {
        for cond in conditions {
            match cond {
                ExecutionCondition::NetworkFeeBelow { max_fee } => {
                    if *max_fee == 0 {
                        bail!("Max fee must be greater than 0");
                    }
                }
                ExecutionCondition::SignerWeightAbove { min_weight } => {
                    if *min_weight == 0 {
                        bail!("Min weight must be greater than 0");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_metadata(metadata: &std::collections::HashMap<String, String>) -> Result<()> {
        for (k, v) in metadata {
            if k.len() > 100 {
                bail!("Metadata key too long");
            }
            if v.len() > 1000 {
                bail!("Metadata value too long");
            }
        }
        Ok(())
    }
}
