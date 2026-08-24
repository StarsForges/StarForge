use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const INDEX_SCHEMA_VERSION: u16 = 1;
pub const RESPONSE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectIndex {
    pub schema_version: u16,
    pub generated_at: String,
    pub project_name: String,
    pub entries: Vec<ContextEntry>,
    pub summary: IndexSummary,
}

impl ProjectIndex {
    pub fn compatible(&self) -> bool {
        self.schema_version <= INDEX_SCHEMA_VERSION && self.schema_version > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextEntry {
    /// Slash-separated path relative to the project root. Absolute paths are
    /// deliberately never persisted or sent to a provider.
    pub path: String,
    pub kind: ContextKind,
    pub size_bytes: u64,
    pub digest: String,
    pub excerpt: String,
    pub redactions: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    CargoManifest,
    ContractSource,
    ContractMetadata,
    Template,
    Configuration,
    Test,
    DeploymentHistory,
}

impl ContextKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CargoManifest => "cargo manifest",
            Self::ContractSource => "contract source",
            Self::ContractMetadata => "contract metadata",
            Self::Template => "template",
            Self::Configuration => "configuration",
            Self::Test => "test",
            Self::DeploymentHistory => "deployment history",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexSummary {
    pub files_indexed: usize,
    pub bytes_indexed: u64,
    pub redactions: usize,
    pub skipped_files: usize,
    pub truncated_files: usize,
    pub by_kind: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyReport {
    pub redaction_enabled: bool,
    pub excluded_path_count: usize,
    pub redactions_applied: usize,
    pub absolute_paths_shared: bool,
    pub provider_contacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Online,
    Offline,
    Fallback,
    Preview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantResponse {
    pub schema_version: u16,
    pub workflow: Workflow,
    pub mode: ResponseMode,
    pub summary: String,
    pub guidance: Vec<GuidanceItem>,
    pub sources: Vec<SourceReference>,
    pub privacy: PrivacyReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_preview: Option<PromptPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuidanceItem {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Suggestion,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Suggestion => "suggestion",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceReference {
    pub path: String,
    pub kind: ContextKind,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptPreview {
    pub system: String,
    pub user: String,
    pub estimated_input_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderReport {
    pub name: String,
    pub model: String,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Workflow {
    Explain,
    Diagnose,
    Suggest,
    Scaffold,
    Review,
}

impl Workflow {
    pub fn name(self) -> &'static str {
        match self {
            Self::Explain => "explain",
            Self::Diagnose => "diagnose",
            Self::Suggest => "suggest",
            Self::Scaffold => "scaffold",
            Self::Review => "review",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowRequest {
    pub workflow: Workflow,
    pub query: String,
    pub focus: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IndexOptions {
    pub root: PathBuf,
    pub excluded_paths: Vec<String>,
    pub redact: bool,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantConfig {
    pub schema_version: u16,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default = "default_redact")]
    pub redact: bool,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: usize,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        Self {
            schema_version: INDEX_SCHEMA_VERSION,
            excluded_paths: Vec::new(),
            redact: true,
            max_file_bytes: default_max_file_bytes(),
            max_total_bytes: default_max_total_bytes(),
        }
    }
}

fn default_redact() -> bool {
    true
}

fn default_max_file_bytes() -> usize {
    32 * 1024
}

fn default_max_total_bytes() -> usize {
    256 * 1024
}
