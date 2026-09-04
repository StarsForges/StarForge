use super::manifest::ProposalManifest;
use super::core::{ProposalStatus, ApprovalAttestation, SignerInfo};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct StateSnapshot {
    pub version: u32,
    pub proposals: HashMap<String, ProposalManifest>,
    pub statuses: HashMap<String, ProposalStatus>,
    pub approvals: HashMap<String, Vec<ApprovalAttestation>>,
    pub signers: HashMap<String, SignerInfo>,
    pub superseded_by: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct StorageMetadata {
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub network: String,
    pub storage_version: u32,
}

pub struct GovernanceStorage {
    data_dir: PathBuf,
}

impl GovernanceStorage {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
        }
    }

    pub fn save_state(&self, snapshot: &StateSnapshot) -> Result<()> {
        if !self.data_dir.exists() {
            fs::create_dir_all(&self.data_dir).context("Failed to create data directory")?;
        }
        
        let file_path = self.data_dir.join("governance_state.json");
        let json = serde_json::to_string_pretty(snapshot).context("Failed to serialize state")?;
        
        fs::write(&file_path, json).context("Failed to write state file")?;
        
        // Also save a backup
        let backup_path = self.data_dir.join("governance_state.backup.json");
        fs::copy(&file_path, &backup_path).context("Failed to create backup")?;
        
        // Write metadata
        let metadata = StorageMetadata {
            last_updated: chrono::Utc::now(),
            network: "testnet".to_string(), // placeholder
            storage_version: 1,
        };
        let meta_path = self.data_dir.join("metadata.json");
        let meta_json = serde_json::to_string_pretty(&metadata).unwrap();
        fs::write(meta_path, meta_json)?;

        Ok(())
    }

    pub fn load_state(&self) -> Result<StateSnapshot> {
        let file_path = self.data_dir.join("governance_state.json");
        
        if !file_path.exists() {
            return Ok(StateSnapshot {
                version: 1,
                proposals: HashMap::new(),
                statuses: HashMap::new(),
                approvals: HashMap::new(),
                signers: HashMap::new(),
                superseded_by: HashMap::new(),
            });
        }
        
        let json = fs::read_to_string(&file_path).context("Failed to read state file")?;
        let snapshot: StateSnapshot = serde_json::from_str(&json).context("Failed to deserialize state")?;
        
        Ok(snapshot)
    }

    pub fn save_proposal_receipt(&self, proposal_id: &str, receipt: &str) -> Result<()> {
        let receipts_dir = self.data_dir.join("receipts");
        if !receipts_dir.exists() {
            fs::create_dir_all(&receipts_dir).context("Failed to create receipts directory")?;
        }
        let file_path = receipts_dir.join(format!("{}.txt", proposal_id));
        fs::write(&file_path, receipt).context("Failed to write receipt")?;
        Ok(())
    }

    pub fn get_proposal_receipt(&self, proposal_id: &str) -> Result<String> {
        let receipts_dir = self.data_dir.join("receipts");
        let file_path = receipts_dir.join(format!("{}.txt", proposal_id));
        if !file_path.exists() {
            bail!("Receipt not found for proposal {}", proposal_id);
        }
        let content = fs::read_to_string(&file_path)?;
        Ok(content)
    }

    pub fn clear_all_data(&self) -> Result<()> {
        if self.data_dir.exists() {
            fs::remove_dir_all(&self.data_dir).context("Failed to clear data directory")?;
        }
        Ok(())
    }
    
    pub fn get_storage_size(&self) -> Result<u64> {
        let mut total = 0;
        if !self.data_dir.exists() {
            return Ok(0);
        }
        for entry in fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() {
                total += meta.len();
            }
        }
        Ok(total)
    }
    
    pub fn list_receipts(&self) -> Result<Vec<String>> {
        let receipts_dir = self.data_dir.join("receipts");
        if !receipts_dir.exists() {
            return Ok(vec![]);
        }
        
        let mut receipts = Vec::new();
        for entry in fs::read_dir(receipts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("txt") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    receipts.push(stem.to_string());
                }
            }
        }
        Ok(receipts)
    }

    pub fn get_metadata(&self) -> Result<StorageMetadata> {
        let meta_path = self.data_dir.join("metadata.json");
        if !meta_path.exists() {
            bail!("Metadata not found");
        }
        let content = fs::read_to_string(meta_path)?;
        let meta: StorageMetadata = serde_json::from_str(&content)?;
        Ok(meta)
    }
}
