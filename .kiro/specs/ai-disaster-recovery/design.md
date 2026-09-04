# Design Document: AI Disaster Recovery

## Overview

The `ai-disaster-recovery` subsystem adds a `starforge ai recovery` command group to StarForge. It lets Soroban developers inventory contract artifacts, define backup policies, create encrypted+versioned backup archives, verify archive integrity, simulate restores, and generate AI-assisted recovery reports — all with a mandatory deterministic offline fallback.

The feature follows exactly the same structural conventions as the existing `anomaly` and `impact` subsystems: a `src/commands/ai/recovery/` module directory, domain types in `model.rs`, persistence helpers isolated in submodules, an AI client in `ai_client.rs`, and all persistent state under `~/.starforge/data/recovery/`.

---

## Architecture

```
starforge ai recovery <subcommand>
        │
        ▼
src/commands/ai/recovery/
├── mod.rs           — clap enum, top-level handle(), route dispatch
├── model.rs         — Artifact, BackupPolicy, RecoveryPlan, RecoveryReport, …
├── inventory.rs     — filesystem scan → Vec<Artifact>
├── scorer.rs        — Offline_Fallback risk scoring; RiskFactor accumulation
├── backup.rs        — archive write, integrity digest, retention enforcement
├── verify.rs        — digest recomputation and archive validation
├── restore_sim.rs   — dry-run restore validation without filesystem writes
├── report.rs        — RecoveryReport assembly (plan + verify + AI narrative)
├── ai_client.rs     — OpenAI narrative request with prompt redaction
├── persistence.rs   — load/save helpers, atomic write, schema migration
└── migrations.rs    — schema version constants and forward migration fns
```

The module is wired into the existing `AiCommands` enum in `src/commands/ai/mod.rs` as a new variant `Recovery(recovery::RecoveryArgs)`, mirroring how `Impact` and `SecurityTraining` are added today.

### Data Flow

```
plan:     inventory.rs → scorer.rs → ai_client.rs (optional) → persistence.rs → stdout/file
backup:   inventory.rs → backup.rs (encrypt, digest, write, prune) → persistence.rs
verify:   backup_store → verify.rs (decrypt, digest check) → stdout/file
restore-dry-run: backup_store → restore_sim.rs (validate, no writes) → stdout/file
report:   persistence.rs (load plan + verify result) → scorer.rs → ai_client.rs → report.rs → stdout/file
```

---

## Components and Interfaces

### `mod.rs` — CLI Surface

```rust
#[derive(Subcommand)]
pub enum RecoveryCommands {
    Plan {
        #[arg(long)] init_policy: bool,
        #[arg(long)] network: Option<String>,
        #[arg(long, default_value = "human", value_parser = ["human","json"])] format: String,
        #[arg(long)] output: Option<PathBuf>,
        #[arg(long)] deterministic: bool,
        #[arg(long, default_value = "gpt-4")] model: String,
        #[arg(long, value_parser = ["low","medium","high","critical"])] fail_on: Option<String>,
    },
    Backup {
        #[arg(long)] network: Option<String>,
        #[arg(long)] dry_run: bool,
        #[arg(long, default_value = "human", value_parser = ["human","json"])] format: String,
        #[arg(long)] yes: bool,
    },
    Verify {
        #[arg(long)] archive: Option<PathBuf>,
        #[arg(long)] network: Option<String>,
        #[arg(long)] fail_on_any: bool,
        #[arg(long, default_value = "human", value_parser = ["human","json"])] format: String,
    },
    RestoreDryRun {
        #[arg(long)] archive: Option<PathBuf>,
        #[arg(long)] network: Option<String>,
        #[arg(long, default_value = "human", value_parser = ["human","json"])] format: String,
        #[arg(long)] fail_on_warning: bool,
    },
    Report {
        #[arg(long)] network: Option<String>,
        #[arg(long, default_value = "markdown", value_parser = ["markdown","json"])] format: String,
        #[arg(long)] output: Option<PathBuf>,
        #[arg(long)] deterministic: bool,
        #[arg(long, default_value = "gpt-4")] model: String,
    },
}
```

### `inventory.rs`

```rust
pub fn scan(project_root: &Path, starforge_home: &Path) -> Result<Vec<Artifact>>
```

Walks `project_root` recursively for `*.wasm` and `*.deploy.json` files, then loads any matching manifest from `starforge_home/data/recovery/manifests/`. Sets `ArtifactStatus` by comparing SHA-256 of the discovered WASM against the hash stored in the manifest. Calls `redact_text` on all discovered paths before storing them.

### `scorer.rs`

```rust
pub fn score_offline(artifacts: &[Artifact], policy: &BackupPolicy, last_backup_ts: Option<DateTime<Utc>>) -> (u8, RiskLevel, Vec<RiskFactor>)
```

Accumulates point contributions as defined by requirement 5.4, clamps to [0, 100], derives `RiskLevel`.

### `backup.rs`

```rust
pub fn run_backup(artifacts: &[Artifact], policy: &BackupPolicy, store: &Path, dry_run: bool) -> Result<BackupResult>
pub fn enforce_retention(store: &Path, retain: usize) -> Result<()>
```

`run_backup` writes to a `.tmp` file first, computes digest, renames to final path (atomic write pattern). On any error, deletes `.tmp` before propagating. `enforce_retention` lists `*.tar.gz` files sorted by creation time, deletes oldest until count ≤ `retain`.

### `verify.rs`

```rust
pub fn verify_all(store: &Path, passphrase: Option<&str>) -> Result<Vec<VerifyResult>>
pub fn verify_one(archive: &Path, passphrase: Option<&str>) -> Result<VerifyResult>
```

Reads sidecar `.sha256`, decrypts if needed, recomputes SHA-256 of archive bytes, compares. Returns `VerifyStatus::Ok`, `Corrupted { expected, actual }`, or `Unverifiable`.

### `restore_sim.rs`

```rust
pub fn simulate(archive: &Path, passphrase: Option<&str>) -> Result<SimulationResult>
```

Reads and decrypts archive, iterates every artifact entry, validates integrity digest + required manifest fields + absent secrets. Collects all failures rather than short-circuiting. Emits no filesystem writes.

### `report.rs`

```rust
pub fn build(plan: &RecoveryPlan, verify: Option<&[VerifyResult]>, ai_narrative: Option<&str>) -> RecoveryReport
```

Sorts remediation steps by risk point contribution descending, applies `redact_text` to all string fields before returning.

### `ai_client.rs`

```rust
pub async fn request_narrative(client: &Client<OpenAIConfig>, plan: &RecoveryPlan, model: &str) -> Result<String>
pub async fn request_remediation(client: &Client<OpenAIConfig>, report: &RecoveryReport, model: &str) -> Result<String>
```

Builds a prompt from redacted plan/report data (no raw paths or keys), calls `execute_chat` from `commands::ai` (which handles telemetry), redacts the response before returning.

### `persistence.rs`

```rust
pub fn load_policy(home: &Path) -> Result<Option<BackupPolicy>>
pub fn save_policy(home: &Path, policy: &BackupPolicy) -> Result<()>
pub fn load_plan(home: &Path) -> Result<Option<RecoveryPlan>>
pub fn save_plan(home: &Path, plan: &RecoveryPlan) -> Result<PathBuf>
pub fn load_verify_results(home: &Path) -> Result<Option<Vec<VerifyResult>>>
pub fn save_verify_results(home: &Path, results: &[VerifyResult]) -> Result<()>
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()>
fn set_permissions_600(path: &Path) -> Result<()>
```

`atomic_write` writes to `path.with_extension("tmp")`, sets permissions to 0600, then renames. On rename failure deletes the `.tmp`.

### `migrations.rs`

```rust
pub const CURRENT_POLICY_VERSION: u8 = 1;
pub const CURRENT_PLAN_VERSION: u8 = 1;
pub const CURRENT_REPORT_VERSION: u8 = 1;

pub fn migrate_policy(raw: serde_json::Value) -> Result<BackupPolicy>
pub fn migrate_plan(raw: serde_json::Value) -> Result<RecoveryPlan>
```

Reads `schema_version` from the JSON value; returns error if higher than current; applies migration fns in sequence if lower.

---

## Data Models

```rust
// model.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The kind of item that was found during artifact inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    WasmBinary,
    DeployManifest,
    ContractId,
    KeyReference,
}

/// Whether the artifact was found, found but hash-mismatched, or absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactStatus {
    Present,
    Stale,
    Missing,
}

/// One recoverable item discovered during inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,               // uuid v4
    pub kind: ArtifactKind,
    pub path: String,             // redacted via Secret_Redactor
    pub status: ArtifactStatus,
    pub sha256: Option<String>,   // hex digest of current bytes
    pub expected_sha256: Option<String>, // digest from manifest, if any
    pub size_bytes: u64,
    pub last_modified: DateTime<Utc>,
}

/// The encryption mode for backup archives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode { Aes256Gcm, None }

/// The integrity hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntegrityAlgorithm { Sha256, Blake3 }

/// User-editable backup configuration persisted to policy.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub schema_version: u8,       // must equal migrations::CURRENT_POLICY_VERSION
    pub cadence_hours: u32,       // 1..=8760
    pub retention_count: u32,     // 1..=365
    pub encryption: EncryptionMode,
    pub integrity: IntegrityAlgorithm,
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            cadence_hours: 24,
            retention_count: 7,
            encryption: EncryptionMode::Aes256Gcm,
            integrity: IntegrityAlgorithm::Sha256,
        }
    }
}

/// One contributing factor to the overall risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub description: String,
    pub points: u8,
}

/// Risk band derived from the numeric score.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel { Low, Medium, High, Critical }

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=29  => RiskLevel::Low,
            30..=59 => RiskLevel::Medium,
            60..=84 => RiskLevel::High,
            _       => RiskLevel::Critical,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low      => "low",
            RiskLevel::Medium   => "medium",
            RiskLevel::High     => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// The machine-readable output of `starforge ai recovery plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub network: String,
    pub artifacts: Vec<Artifact>,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub ai_narrative: Option<String>,
}

/// Per-archive result from `starforge ai recovery verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub archive_path: String,
    pub status: VerifyStatus,
    pub expected_digest: Option<String>,
    pub actual_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyStatus { Ok, Corrupted, Unverifiable }

/// Per-artifact validation result from `restore-dry-run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactValidation {
    pub artifact_id: String,
    pub passed: bool,
    pub issues: Vec<String>,
}

/// Output of `restore-dry-run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub archive_path: String,
    pub artifact_count: usize,
    pub validation_results: Vec<ArtifactValidation>,
    pub simulation_passed: bool,
    pub simulated_restore_duration_ms: u64,
}

/// Result of `starforge ai recovery backup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupResult {
    pub archive_path: String,
    pub artifact_count: usize,
    pub size_bytes: u64,
    pub integrity_digest: String,
    pub timestamp: DateTime<Utc>,
}

/// Output of `starforge ai recovery report`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub plan: RecoveryPlan,
    pub verify_summary: Option<Vec<VerifyResult>>,
    pub recommendations: Vec<Recommendation>,
    pub ai_narrative: Option<String>,
}

/// A single recommended remediation step, sortable by risk contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: u8,             // risk points this recommendation addresses
    pub description: String,
    pub action: String,
}
```

---

## Persistence Layout

```
~/.starforge/data/recovery/          (mode 0700)
├── policy.json                      (mode 0600) — BackupPolicy
├── plan.json                        (mode 0600) — most recent RecoveryPlan
├── verify_results.json              (mode 0600) — most recent Vec<VerifyResult>
├── report_history/                  (mode 0700)
│   └── YYYY-MM-DDTHH-MM-SS.json    (mode 0600) — historical RecoveryReports
└── backups/                         (mode 0700)
    ├── YYYY-MM-DDTHH-MM-SS.tar.gz   (mode 0600) — encrypted archive
    └── YYYY-MM-DDTHH-MM-SS.tar.gz.sha256 (mode 0600) — integrity sidecar
```

All filenames use UTC ISO-8601 with colons replaced by dashes to avoid filesystem issues. Collision resolution appends `.N` (e.g. `…T12-00-00.1.tar.gz`).

---

## Encryption and Integrity

### Encryption (AES-256-GCM)

- **Key derivation**: Argon2id with a random 16-byte salt stored in a `key_params.json` sidecar alongside the archive. The passphrase is sourced from `STARFORGE_RECOVERY_PASSPHRASE` env var or prompted interactively via `dialoguer`. The derived key and salt are **never logged**.
- **Nonce**: 12-byte random nonce prepended to the ciphertext within the archive.
- **Dependencies**: `aes-gcm = "0.10.3"` and `argon2 = "0.5.3"` (already in `Cargo.toml`).

### Integrity

- SHA-256 of the raw (post-encryption) archive bytes is written to `<archive>.sha256` as a lowercase hex string.
- During `verify`, the archive is read, decrypted, and the hash recomputed before comparison.
- The atomic write pattern ensures the sidecar is only present when the archive write is complete.

---

## AI Provider Integration and Offline Fallback

### Integration Pattern

Mirrors `impact/ai_client.rs`:
1. Build a sanitized prompt from `RecoveryPlan` / `RecoveryReport` — no raw paths, no keys, no contract IDs (all stripped via `redact_text`).
2. Call `commands::ai::execute_chat()` (handles telemetry uniformly).
3. Redact the response with `redact_text` before storing or displaying.
4. AI narrative is stored in `plan.ai_narrative` / `report.ai_narrative` as `Option<String>`.

### Offline Fallback

`scorer::score_offline` is always called. AI narrative is appended after the deterministic output only when the API key is available and `--deterministic` is not set. Any AI provider failure logs a warning via `notifications::warn` and proceeds with the offline result — no error is returned to the caller.

| Condition | Risk Points |
|---|---|
| Missing WASM binary | +30 |
| Missing Manifest | +25 |
| Stale digest mismatch | +20 |
| Unencrypted key reference in artifact path | +15 |
| No backup in last `cadence_hours` | +10 |

Score is clamped to [0, 100]. `RiskLevel::from_score` maps the value to a band.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Artifact inventory completeness

*For any* project directory containing N artifact files (WASM binaries, deploy manifests, key references), the `scan` function should return exactly N entries, one per discovered artifact, each with a `status` field of `present`, `stale`, or `missing`.

**Validates: Requirements 1.1, 1.2**

### Property 2: Stale digest detection

*For any* WASM binary file whose SHA-256 digest differs from the digest recorded in its associated manifest, the corresponding `Artifact` entry returned by `scan` should have `status == ArtifactStatus::Stale` and include both the expected and actual digest values.

**Validates: Requirements 1.3**

### Property 3: Secret redaction universality

*For any* string containing a Stellar secret key (`S...` 56-char), a mnemonic phrase, a hex-encoded 32-byte value, or a bearer token, applying `redact_text` should produce a string that does not contain the original secret pattern, regardless of where in the output or persisted document it appears.

**Validates: Requirements 1.7, 5.7, 7.6, 11.1, 11.4, 11.5**

### Property 4: Schema version presence

*For any* persisted JSON document written by the Recovery_Engine (BackupPolicy, RecoveryPlan, RecoveryReport, VerifyResult array), deserializing it back and checking the `schema_version` field should return the current supported version integer.

**Validates: Requirements 1.4, 7.3, 9.2**

### Property 5: Backup → verify round-trip

*For any* non-empty set of artifacts and any BackupPolicy with `encryption: aes-256-gcm` or `none`, running `backup` followed immediately by `verify` on the resulting archive should return `VerifyStatus::Ok` for that archive.

**Validates: Requirements 3.2, 4.1, 4.3, 4.7, 10.5**

### Property 6: Policy field range validation

*For any* `retention_count` value outside [1, 365] or any `cadence_hours` value outside [1, 8760], the policy validator should return an error; for any value within the valid range, validation should succeed.

**Validates: Requirements 2.6, 2.7**

### Property 7: Backup retention enforcement

*For any* BackupPolicy with `retention_count = N` and any sequence of M > N backup runs, the backup store should contain exactly N archive files after the final run, consisting of the N most recent archives.

**Validates: Requirements 3.4**

### Property 8: Risk score bounded invariant

*For any* combination of artifact statuses and backup freshness, the `score_offline` function should return a `risk_score` in the closed interval [0, 100] and a `risk_level` consistent with `RiskLevel::from_score(risk_score)`.

**Validates: Requirements 5.1, 5.4, 5.5**

### Property 9: Risk score additivity

*For any* artifact set, the `risk_score` should equal the sum of the `points` values in `risk_factors`, clamped to 100. Each `RiskFactor` in the list should correspond to exactly one of the five defined heuristic conditions from requirement 5.4.

**Validates: Requirements 5.4, 5.5**

### Property 10: Dry-run writes no files

*For any* invocation of `restore-dry-run` or `backup --dry-run`, the set of files in the backup store directory after the command should be identical to the set before the command.

**Validates: Requirements 3.5, 6.1**

### Property 11: Restore simulation reports all failures

*For any* archive containing K artifacts that fail validation, `simulate` should return a `SimulationResult` with exactly K entries in `validation_results` where `passed == false`; the function should not short-circuit on the first failure.

**Validates: Requirements 6.3, 6.4**

### Property 12: No archive collision overwrite

*For any* two backup runs that would produce the same filename (e.g. sub-second runs in tests), the backup store should contain two distinct files; no existing archive should be overwritten.

**Validates: Requirements 9.6**

### Property 13: Schema migration round-trip

*For any* persisted document with a `schema_version` lower than the current version, applying the forward migration chain and re-serializing should produce a document that deserializes cleanly to the current type with no field loss.

**Validates: Requirements 9.4**

### Property 14: No key material in output

*For any* backup, verify, plan, or report operation, the combined stdout, stderr, and persisted file content should not contain any string that matches the AES key format (32-byte hex), the Argon2 salt format, or the derived key material format.

**Validates: Requirements 11.3**

### Property 15: Corrupted archive detection

*For any* valid archive that has one or more bytes flipped or truncated after writing, `verify_one` should return `VerifyStatus::Corrupted` with the expected and actual digest values populated.

**Validates: Requirements 4.3**

---

## Error Handling

All public functions return `anyhow::Result<T>`. Error context is attached with `.with_context(|| ...)` at each layer boundary, preserving the full error chain to the CLI surface. The top-level `handle()` in `mod.rs` maps errors to a non-zero exit code and prints to stderr. Secrets are never included in error messages — `redact_text` is applied to any user-visible error string that might contain a path or key.

| Error scenario | Behavior |
|---|---|
| Policy schema_version mismatch | Actionable error naming old/new version, suggests `starforge upgrade` |
| AI provider unavailable | Warning to stderr, continues with offline fallback |
| Encrypted archive with wrong passphrase | `VerifyStatus::Corrupted` (decryption failure treated as corruption) |
| Backup interrupted (I/O error) | `.tmp` file deleted, original error returned |
| Archive filename collision | Appends `.N` suffix, retries up to 100 times before failing |
| Missing sidecar `.sha256` | `VerifyStatus::Unverifiable` |
| Unknown network name | Error naming the network, lists valid options from config |

---

## Testing Strategy

### Unit Tests (in module source files)

- `scorer.rs`: Each of the five heuristic risk conditions in isolation; boundary values (score 0, 100, clamp).
- `model.rs`: `RiskLevel::from_score` boundaries; `BackupPolicy::default` field values; serialization round-trip for all document types.
- `inventory.rs`: WASM-present, WASM-stale (mismatched hash), manifest-missing, key-reference-in-path.
- `backup.rs`: retention enforcement with various archive counts; atomic write temp-file cleanup.
- `verify.rs`: ok path, corrupted (byte flip), missing sidecar, decryption failure.
- `migrations.rs`: forward migration from v0 → v1 for each document type; rejection of future version.

### Integration Tests (`tests/recovery_*.rs`)

All integration tests use `tempfile::TempDir` for isolation. No writes to `~/.starforge/`. No outbound network calls (AI calls mocked via fixture responses).

- `backup_verify_roundtrip`: Run backup on a fixture artifact set, then verify — expect all `Ok`.
- `corrupted_archive_detection`: Backup, then truncate the archive, then verify — expect `Corrupted`.
- `missing_sidecar`: Backup, delete `.sha256` sidecar, verify — expect `Unverifiable`.
- `interrupted_backup_cleanup`: Simulate I/O error during write, confirm no `.tmp` file remains.
- `restore_dry_run_pass`: Backup a valid fixture set, dry-run restore — expect `simulation_passed: true`.
- `restore_dry_run_fail`: Corrupt an artifact inside a valid archive, dry-run restore — expect failures reported, `simulation_passed: false`, all failures present (not just first).
- `cli_json_format_stability`: Run `plan --format json` via `std::process::Command`, parse output, confirm required fields present and `schema_version == 1`.
- `retention_enforcement`: Run N+1 backups, confirm only N files remain.
- `no_archive_overwrite`: Two rapid backups at same timestamp in tests, confirm two distinct files.

### Property-Based Tests

Use the [`proptest`](https://crates.io/crates/proptest) crate (add to `[dev-dependencies]`). Minimum 100 runs per property.

Each test references its design property via a comment in the format:
`// Feature: ai-disaster-recovery, Property N: <property_text>`

- **Property 1** — Generate random directory trees with 0–20 artifact files; confirm scan returns exactly the right count with valid statuses.
- **Property 3** — Generate random strings with injected Stellar secrets, hex keys, and bearer tokens; confirm `redact_text` removes all of them.
- **Property 4** — Generate random `BackupPolicy`, `RecoveryPlan`, and `RecoveryReport` values; serialize to JSON; confirm `schema_version` field is present and correct.
- **Property 5** — Generate random artifact sets + policies; run backup then verify; confirm `VerifyStatus::Ok`.
- **Property 6** — Generate integers in `i64` range; test `validate_policy` rejects outside [1,365] for `retention_count` and [1,8760] for `cadence_hours`.
- **Property 7** — Generate random `retention_count` N (1–20) and M backups (N+1 to N+10); confirm exactly N files remain.
- **Property 8** — Generate random artifact status combinations; confirm `score_offline` returns `risk_score` in [0,100] and `risk_level == RiskLevel::from_score(risk_score)`.
- **Property 9** — Confirm `risk_score == min(sum(risk_factors[i].points), 100)` for all generated inputs.
- **Property 11** — Generate archives with random counts of corrupted artifacts; confirm `validation_results` length matches the injected failure count.
- **Property 13** — Generate v0-format JSON for each document type; apply migration; confirm all current fields are present in the result.
- **Property 15** — Generate valid archives, flip 1–N random bytes, call `verify_one`; confirm `Corrupted` is returned with both digests populated.

### Fixtures (`tests/fixtures/recovery/`)

| File | Purpose |
|---|---|
| `valid_plan.json` | A valid `RecoveryPlan` with `schema_version: 1`, two artifacts |
| `valid_policy.json` | A valid `BackupPolicy` with default values |
| `corrupted_archive.tar.gz` | A truncated (last 128 bytes removed) backup archive |
| `missing_sidecar_archive.tar.gz` | A valid archive with no `.sha256` sidecar |
| `ai_narrative_response.json` | A mock OpenAI response for use in integration tests |
