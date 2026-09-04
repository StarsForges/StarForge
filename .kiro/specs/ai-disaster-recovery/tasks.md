# Implementation Plan: AI Disaster Recovery

## Overview

Implement the `starforge ai recovery` command group as a new module at
`src/commands/ai/recovery/`, following the same structural conventions as the
`anomaly` and `impact` subsystems. Work proceeds from data models → persistence
→ core engine modules → CLI wiring → tests, so each task compiles and is
exercisable before the next begins.

---

## Tasks

- [x] 1. Scaffold module directory and core data models
  - Create `src/commands/ai/recovery/` directory
  - Create `src/commands/ai/recovery/mod.rs` with empty module declarations (`pub mod model; pub mod inventory; pub mod scorer; pub mod backup; pub mod verify; pub mod restore_sim; pub mod report; pub mod ai_client; pub mod persistence; pub mod migrations;`) and a placeholder `pub async fn handle()` that returns `Ok(())`
  - Create `src/commands/ai/recovery/model.rs` with all types from the design: `ArtifactKind`, `ArtifactStatus`, `Artifact`, `EncryptionMode`, `IntegrityAlgorithm`, `BackupPolicy` (with `Default`), `RiskFactor`, `RiskLevel` (with `from_score` and `as_str`), `RecoveryPlan`, `VerifyResult`, `VerifyStatus`, `ArtifactValidation`, `SimulationResult`, `BackupResult`, `RecoveryReport`, `Recommendation`
  - Add `proptest` to `[dev-dependencies]` in `Cargo.toml`
  - _Requirements: 1.4, 2.2, 5.5, 7.3, 9.2_

  - [ ]* 1.1 Write unit tests for model types
    - Test `RiskLevel::from_score` at all four band boundaries (0, 29, 30, 59, 60, 84, 85, 100)
    - Test `BackupPolicy::default` field values match requirement 2.2
    - Test JSON round-trip serialization for `BackupPolicy`, `RecoveryPlan`, `VerifyResult`, `RecoveryReport`
    - _Requirements: 2.2, 5.5, 9.2_

- [x] 2. Implement schema migrations module
  - Create `src/commands/ai/recovery/migrations.rs`
  - Define `CURRENT_POLICY_VERSION: u8 = 1`, `CURRENT_PLAN_VERSION: u8 = 1`, `CURRENT_REPORT_VERSION: u8 = 1`
  - Implement `migrate_policy(raw: serde_json::Value) -> Result<BackupPolicy>`: read `schema_version`, return error if higher than current, apply forward migrations (v0→v1 identity for now) if lower, deserialize
  - Implement `migrate_plan(raw: serde_json::Value) -> Result<RecoveryPlan>` with the same pattern
  - Implement `migrate_report(raw: serde_json::Value) -> Result<RecoveryReport>` with the same pattern
  - _Requirements: 9.2, 9.3, 9.4_

  - [ ]* 2.1 Write unit tests for migrations
    - Test that a document with `schema_version` higher than current returns an error naming the unsupported version
    - Test that a document with `schema_version` equal to current deserializes cleanly
    - Test that a document with `schema_version` lower than current (v0 fixture) migrates without field loss
    - _Requirements: 9.3, 9.4_

- [x] 3. Implement persistence helpers
  - Create `src/commands/ai/recovery/persistence.rs`
  - Implement `fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()>`: write to `path` + `.tmp` extension, set permissions 0600 (Unix only, log debug notice on non-Unix), rename to final path; delete `.tmp` on rename failure
  - Implement `fn set_permissions_600(path: &Path) -> Result<()>` and `fn ensure_dir_700(path: &Path) -> Result<()>`
  - Implement `fn never_overwrite(dir: &Path, base_name: &str) -> PathBuf`: if `base_name` exists in `dir`, append `.1`, `.2`, … up to 100 before returning (satisfies requirement 9.6)
  - Implement `load_policy`, `save_policy`, `load_plan`, `save_plan`, `load_verify_results`, `save_verify_results` — each using `atomic_write`, `migrations::migrate_*`, and `schema_version` field stamping
  - Create `~/.starforge/data/recovery/` directory tree on first use (mode 0700)
  - _Requirements: 9.1, 9.2, 9.5, 9.6_

  - [ ]* 3.1 Write unit tests for persistence helpers
    - Test `atomic_write` produces final file and removes `.tmp` on success
    - Test `atomic_write` removes `.tmp` when a simulated rename failure occurs
    - Test `never_overwrite` returns a suffixed path when the base name exists, and an unsuffixed path when it does not
    - All tests use `tempfile::TempDir` for isolation
    - _Requirements: 9.5, 9.6_

- [x] 4. Implement backup policy validation
  - Add `pub fn validate_policy(policy: &BackupPolicy) -> Result<()>` to `model.rs` (or a dedicated `validation.rs` re-exported from `model`)
  - Reject `retention_count` outside [1, 365] with error naming the allowed range
  - Reject `cadence_hours` outside [1, 8760] with error naming the allowed range
  - Emit a warning (via `notifications::warn`) when `encryption == EncryptionMode::None`
  - _Requirements: 2.4, 2.5, 2.6, 2.7_

  - [ ]* 4.1 Write property test for policy field range validation
    - **Property 6: Policy field range validation**
    - **Validates: Requirements 2.6, 2.7**
    - Generate integers across the full i64 range; assert `validate_policy` returns `Err` when `retention_count` outside [1,365] or `cadence_hours` outside [1,8760], and `Ok` within valid ranges

- [x] 5. Implement artifact inventory scanner
  - Create `src/commands/ai/recovery/inventory.rs`
  - Implement `pub fn scan(project_root: &Path, starforge_home: &Path) -> Result<Vec<Artifact>>`
  - Walk `project_root` recursively for `*.wasm` and `*.deploy.json` files using `std::fs::read_dir` (no extra dependencies needed)
  - Load matching manifest from `starforge_home/data/recovery/manifests/<stem>.json` if present
  - Compute SHA-256 of discovered WASM bytes using the `sha2` crate (already in `Cargo.toml`)
  - Set `ArtifactStatus::Present` when digest matches manifest, `Stale` when it differs (include both digests in the artifact), `Missing` when no WASM file found but a manifest references it
  - Apply `redact_text` to all path strings before storing in `Artifact.path`
  - Detect key references (`S...` 56-char Stellar keys, mnemonic-pattern substrings) in artifact paths; set `ArtifactKind::KeyReference` and note in `RiskFactor` later
  - _Requirements: 1.1, 1.2, 1.3, 1.7_

  - [ ]* 5.1 Write unit tests for inventory scanner
    - Test: directory with one WASM whose digest matches manifest → `ArtifactStatus::Present`
    - Test: WASM digest differs from manifest → `ArtifactStatus::Stale`, both digests present
    - Test: manifest references WASM that is absent → `ArtifactStatus::Missing`
    - Test: path containing a Stellar secret key is redacted in the returned `Artifact.path`
    - All tests use `tempfile::TempDir`
    - _Requirements: 1.1, 1.2, 1.3, 1.7_

  - [ ]* 5.2 Write property test for artifact inventory completeness
    - **Property 1: Artifact inventory completeness**
    - **Validates: Requirements 1.1, 1.2**
    - Generate random directory trees with 0–20 artifact files; assert `scan` returns exactly the right count with each status value drawn from the valid set

- [x] 6. Implement offline risk scorer
  - Create `src/commands/ai/recovery/scorer.rs`
  - Implement `pub fn score_offline(artifacts: &[Artifact], policy: &BackupPolicy, last_backup_ts: Option<DateTime<Utc>>) -> (u8, RiskLevel, Vec<RiskFactor>)`
  - Accumulate contributions: missing WASM binary (+30), missing Manifest (+25), stale digest mismatch (+20), unencrypted key reference in artifact path (+15), no backup in last `cadence_hours` (+10)
  - Clamp total to [0, 100]; derive `RiskLevel` via `RiskLevel::from_score`
  - Return `(score, level, risk_factors)` — each contributing condition becomes one `RiskFactor`
  - _Requirements: 5.1, 5.4, 5.5_

  - [ ]* 6.1 Write unit tests for risk scorer
    - Test each of the five heuristic conditions in isolation (single condition, other factors absent)
    - Test score clamp: artifact set that would exceed 100 points is clamped to 100
    - Test boundary values: score 0 → `RiskLevel::Low`, 29 → Low, 30 → Medium, 59 → Medium, 60 → High, 84 → High, 85 → Critical
    - _Requirements: 5.1, 5.4, 5.5_

  - [ ]* 6.2 Write property tests for risk scorer
    - **Property 8: Risk score bounded invariant**
    - **Validates: Requirements 5.1, 5.4, 5.5**
    - Generate random artifact status combinations; assert `score_offline` returns `risk_score` in [0, 100] and `risk_level == RiskLevel::from_score(risk_score)`

    - **Property 9: Risk score additivity**
    - **Validates: Requirements 5.4, 5.5**
    - Assert `risk_score == min(sum of risk_factors[i].points, 100)` for all generated inputs, and each `RiskFactor.description` matches one of the five defined conditions

- [x] 7. Implement encryption helpers
  - Add a private `encryption` submodule inside `backup.rs` (or a shared `crypto.rs` re-exported from `backup` and `verify`)
  - Implement `pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<(Vec<u8>, Vec<u8>)>` returning `(ciphertext_with_nonce, argon2_salt)` — use AES-256-GCM with a random 12-byte nonce prepended to ciphertext; derive key via Argon2id with a random 16-byte salt; never log key, salt, or nonce
  - Implement `pub fn decrypt(ciphertext: &[u8], passphrase: &str, salt: &[u8]) -> Result<Vec<u8>>`
  - Implement `fn passphrase_from_env_or_prompt() -> Result<String>` — reads `STARFORGE_RECOVERY_PASSPHRASE` env var, falls back to `dialoguer::Password`
  - _Requirements: 2.4, 4.7, 11.3_

  - [ ]* 7.1 Write unit tests for encryption round-trip
    - Test that `encrypt` followed by `decrypt` with the same passphrase returns the original plaintext
    - Test that `decrypt` with a wrong passphrase returns an error (treated as corruption)
    - Test that the nonce and salt differ across two calls to `encrypt` (randomness)
    - _Requirements: 2.4, 4.7_

- [x] 8. Implement backup execution
  - Create `src/commands/ai/recovery/backup.rs`
  - Implement `pub fn run_backup(artifacts: &[Artifact], policy: &BackupPolicy, store: &Path, passphrase: &str, dry_run: bool) -> Result<BackupResult>`
  - When `dry_run`: log all files that would be archived and expected archive path to stdout, return early with a zeroed `BackupResult`
  - When not dry_run: collect artifact bytes, build in-memory tar.gz, encrypt if `policy.encryption == Aes256Gcm`, write to `.tmp` via `persistence::atomic_write`, compute SHA-256 of the final archive bytes, write `.sha256` sidecar via `atomic_write`, write `key_params.json` sidecar with the Argon2 salt (not the key itself)
  - Use `persistence::never_overwrite` to resolve filename collisions
  - On any I/O error, delete the `.tmp` file and sidecar before propagating
  - Call `enforce_retention` after successful write
  - Record telemetry event via `crate::utils::ai_telemetry` with `artifact_count`, `size_bytes`, `duration_ms`, `success`
  - Implement `pub fn enforce_retention(store: &Path, retain: usize) -> Result<()>`: list `*.tar.gz` sorted by creation time, delete oldest until count ≤ `retain`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [ ]* 8.1 Write unit tests for backup execution
    - Test dry-run produces no files in the store directory
    - Test successful backup writes archive + `.sha256` sidecar
    - Test retention enforcement: run N+1 backups with `retention_count = N`, confirm exactly N archives remain (oldest deleted)
    - Test interrupted-backup cleanup: simulate I/O error, confirm no `.tmp` remains
    - All tests use `tempfile::TempDir`
    - _Requirements: 3.3, 3.4, 3.5_

  - [ ]* 8.2 Write property test for backup retention enforcement
    - **Property 7: Backup retention enforcement**
    - **Validates: Requirements 3.4**
    - Generate random `retention_count` N in [1, 20] and M in [N+1, N+10] backup runs; assert exactly N files remain after the final run

  - [ ]* 8.3 Write property test for no archive collision overwrite
    - **Property 12: No archive collision overwrite**
    - **Validates: Requirements 9.6**
    - Simulate two rapid backups that would produce the same filename; assert the backup store contains two distinct files and no file is overwritten

- [-] 9. Implement backup integrity verifier
  - Create `src/commands/ai/recovery/verify.rs`
  - Implement `pub fn verify_one(archive: &Path, passphrase: Option<&str>) -> Result<VerifyResult>`
  - Read the `.sha256` sidecar; if absent return `VerifyStatus::Unverifiable`
  - Read `key_params.json` sidecar for Argon2 salt; decrypt archive if encrypted; if decryption fails return `VerifyStatus::Corrupted`
  - Recompute SHA-256 of the raw (post-encryption) archive bytes; compare against sidecar; return `VerifyStatus::Ok` or `Corrupted { expected, actual }`
  - Implement `pub fn verify_all(store: &Path, passphrase: Option<&str>) -> Result<Vec<VerifyResult>>` calling `verify_one` for each `*.tar.gz` in the store
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.7_

  - [ ]* 9.1 Write unit tests for verifier
    - Test: valid archive → `VerifyStatus::Ok`
    - Test: byte-flipped archive → `VerifyStatus::Corrupted` with both digests populated
    - Test: missing `.sha256` sidecar → `VerifyStatus::Unverifiable`
    - Test: archive decryption failure (wrong passphrase) → `VerifyStatus::Corrupted`
    - All tests use `tempfile::TempDir`
    - _Requirements: 4.3, 4.4, 4.7_

  - [ ]* 9.2 Write property test for corrupted archive detection
    - **Property 15: Corrupted archive detection**
    - **Validates: Requirements 4.3**
    - Generate valid archives, flip 1–N random bytes, call `verify_one`; assert `Corrupted` is returned with both digest values populated

- [ ] 10. Checkpoint — core engine complete
  - Ensure all unit tests pass: `cargo test --lib`
  - Confirm `model.rs`, `migrations.rs`, `persistence.rs`, `inventory.rs`, `scorer.rs`, `backup.rs`, `verify.rs` compile without warnings
  - Ask the user if any questions arise before proceeding to the restore simulation, report, and AI client.

- [x] 11. Implement restore dry-run simulation
  - Create `src/commands/ai/recovery/restore_sim.rs`
  - Implement `pub fn simulate(archive: &Path, passphrase: Option<&str>) -> Result<SimulationResult>`
  - Read and decrypt the archive; iterate every artifact entry
  - For each artifact, validate: (a) integrity digest of artifact bytes, (b) presence of required Manifest fields (`contract_id`, `wasm_hash`, `network`, `deploy_timestamp`), (c) absence of clear-text secret values (Stellar `S...` keys, mnemonics, hex-encoded 32-byte values) using `redact_text` + pattern check
  - Collect ALL failures into `validation_results` — do NOT short-circuit on first failure
  - Produce `simulation_passed: true` only when all validations pass
  - Emit no filesystem writes
  - Estimate `simulated_restore_duration_ms` based on total artifact bytes (heuristic: 1 ms per 10 KB, minimum 1 ms)
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [ ]* 11.1 Write unit tests for restore simulation
    - Test: valid archive → `simulation_passed: true`, zero failures
    - Test: archive with one artifact missing a required Manifest field → `simulation_passed: false`, failure reported for that artifact
    - Test: archive with K corrupted artifacts → exactly K entries with `passed: false`
    - Confirm no files written to any directory during simulation
    - All tests use `tempfile::TempDir`
    - _Requirements: 6.3, 6.4_

  - [ ]* 11.2 Write property test for restore simulation completeness
    - **Property 11: Restore simulation reports all failures**
    - **Validates: Requirements 6.3, 6.4**
    - Generate archives with random counts K of corrupted artifacts; assert `validation_results` contains exactly K entries with `passed == false`

- [x] 12. Implement recovery report builder
  - Create `src/commands/ai/recovery/report.rs`
  - Implement `pub fn build(plan: &RecoveryPlan, verify: Option<&[VerifyResult]>, ai_narrative: Option<&str>) -> RecoveryReport`
  - Sort `recommendations` by `priority` descending (risk point contribution)
  - Derive `Recommendation` entries from `plan.risk_factors` — each factor becomes one recommendation with an actionable `action` string
  - Apply `redact_text` to all string fields (`ai_narrative`, recommendation descriptions, paths) before storing in `RecoveryReport`
  - Add `fn to_markdown(report: &RecoveryReport) -> String` and `fn to_json(report: &RecoveryReport) -> Result<String>`
  - _Requirements: 7.1, 7.2, 7.3, 7.6_

  - [ ]* 12.1 Write unit tests for report builder
    - Test recommendations are sorted by priority descending
    - Test `ai_narrative` containing a secret key is redacted in the returned report
    - Test `to_json` output contains `schema_version: 1`
    - _Requirements: 7.3, 7.6_

- [x] 13. Implement AI client for recovery narratives
  - Create `src/commands/ai/recovery/ai_client.rs`
  - Implement `pub async fn request_narrative(client: &Client<OpenAIConfig>, plan: &RecoveryPlan, model: &str) -> Result<String>`
  - Implement `pub async fn request_remediation(client: &Client<OpenAIConfig>, report: &RecoveryReport, model: &str) -> Result<String>`
  - Build prompts from redacted data only: strip all filesystem paths outside project root, all key values, all contract IDs via `redact_text` before including in the prompt
  - Use `commands::ai::execute_chat` for all API calls (uniform telemetry)
  - Redact the response with `redact_text` before returning
  - _Requirements: 5.2, 5.3, 7.5, 11.4, 11.5_

  - [ ]* 13.1 Write property test for secret redaction universality
    - **Property 3: Secret redaction universality**
    - **Validates: Requirements 1.7, 5.7, 7.6, 11.1, 11.4, 11.5**
    - Generate random strings with injected Stellar secrets (`S...` 56-char), hex-encoded 32-byte values, and bearer tokens; apply `redact_text`; assert no injected secret pattern survives in the output

- [x] 14. Implement CLI surface and command routing
  - Add full `RecoveryCommands` clap enum to `src/commands/ai/recovery/mod.rs` with all five subcommands (`Plan`, `Backup`, `Verify`, `RestoreDryRun`, `Report`) and their flags as defined in the design
  - Add `Recovery { #[command(subcommand)] cmd: recovery::RecoveryCommands }` variant to `AiCommands` enum in `src/commands/ai/mod.rs`
  - Wire `AiCommands::Recovery { cmd }` in `handle()` in `src/commands/ai/mod.rs` to call `recovery::handle(cmd).await`
  - Add `pub mod recovery;` to `src/commands/ai/mod.rs`
  - Implement `pub async fn handle(cmd: RecoveryCommands) -> Result<()>` in `recovery/mod.rs`, routing each variant to its handler function
  - Each handler maps errors to stderr + non-zero exit via `anyhow::Context`; secrets never appear in error messages (`redact_text` applied)
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

- [x] 15. Implement `plan` subcommand handler
  - Implement `async fn cmd_plan(...)` inside `recovery/mod.rs`
  - When `--init-policy` and no policy exists: write default `BackupPolicy` via `persistence::save_policy`
  - Load policy (or use default); validate via `model::validate_policy`
  - Run `inventory::scan`; run `scorer::score_offline`
  - If API key available and not `--deterministic`: call `ai_client::request_narrative`; on failure log warning and continue
  - Apply `--fail-on <level>` exit-code logic
  - When `--format json`: write only the `RecoveryPlan` JSON to stdout, progress lines to stderr
  - When `--output <path>`: write plan to file, print confirmation to stdout
  - Save plan via `persistence::save_plan`
  - _Requirements: 1.1–1.7, 5.1–5.7, 8.7_

  - [ ]* 15.1 Write property test for schema version presence
    - **Property 4: Schema version presence in all persisted documents**
    - **Validates: Requirements 1.4, 7.3, 9.2**
    - Generate random `BackupPolicy`, `RecoveryPlan`, and `RecoveryReport` values; serialize to JSON; assert `schema_version` field is present and equals the current supported version

- [x] 16. Implement `backup` subcommand handler
  - Implement `async fn cmd_backup(...)` inside `recovery/mod.rs`
  - Load policy; validate it; resolve passphrase via `encryption::passphrase_from_env_or_prompt`
  - When not `--yes` and operation is destructive (encryption = none or retention pruning will delete files): prompt for confirmation via `dialoguer`
  - Run `backup::run_backup`; on success emit JSON or human-readable summary per `--format`
  - _Requirements: 3.1–3.7, 8.6_

  - [ ]* 16.1 Write property test for backup → verify round-trip
    - **Property 5: Backup → verify round-trip**
    - **Validates: Requirements 3.2, 4.1, 4.3, 4.7, 10.5**
    - Generate random artifact sets and policies (`encryption: aes-256-gcm` or `none`); run `backup` then `verify`; assert `VerifyStatus::Ok` for the resulting archive

  - [ ]* 16.2 Write property test for dry-run writes no files
    - **Property 10: Dry-run writes no files**
    - **Validates: Requirements 3.5, 6.1**
    - For any invocation of `backup --dry-run`, assert the set of files in the backup store after the command is identical to the set before

- [x] 17. Implement `verify` subcommand handler
  - Implement `fn cmd_verify(...)` inside `recovery/mod.rs`
  - Resolve passphrase; call `verify::verify_all` or `verify::verify_one` depending on `--archive`
  - Save results via `persistence::save_verify_results`
  - Apply `--fail-on-any` exit-code logic
  - Emit JSON array or human-readable table per `--format`
  - _Requirements: 4.1–4.7_

- [x] 18. Implement `restore-dry-run` subcommand handler
  - Implement `fn cmd_restore_dry_run(...)` inside `recovery/mod.rs`
  - Select most recent valid archive from Backup_Store when no `--archive` specified
  - Resolve passphrase; call `restore_sim::simulate`
  - Apply `--fail-on-warning` logic: treat validation warnings as failures
  - Emit JSON object or human-readable summary per `--format`
  - Exit non-zero when `simulation_passed == false`
  - _Requirements: 6.1–6.7_

- [x] 19. Implement `report` subcommand handler and telemetry
  - Implement `async fn cmd_report(...)` inside `recovery/mod.rs`
  - Load most recent `RecoveryPlan` and `VerifyResult` list from persistence
  - If API key available and not `--deterministic`: call `ai_client::request_remediation`; on failure continue
  - Call `report::build`; render via `report::to_markdown` or `report::to_json` per `--format`
  - Apply `--output` path write; print confirmation to stdout
  - Record telemetry event with `risk_level`, `artifact_count`, `recommendation_count`, `ai_used`
  - Apply `redact_text` to all report content before persistence or display
  - _Requirements: 7.1–7.7_

- [x] 20. Create test fixtures
  - Create `tests/fixtures/recovery/` directory
  - Write `tests/fixtures/recovery/valid_plan.json` — a valid `RecoveryPlan` with `schema_version: 1` and two artifacts (one `Present`, one `Stale`)
  - Write `tests/fixtures/recovery/valid_policy.json` — default `BackupPolicy` values with `schema_version: 1`
  - Write `tests/fixtures/recovery/ai_narrative_response.json` — mock OpenAI chat completion response with a recovery narrative
  - Create `tests/fixtures/recovery/corrupted_archive.tar.gz` — a small valid tar.gz with the last 128 bytes removed (truncated)
  - Create `tests/fixtures/recovery/missing_sidecar_archive.tar.gz` — a valid tar.gz archive with no accompanying `.sha256` sidecar file
  - _Requirements: 10.6_

- [x] 21. Write integration tests
  - Create `tests/recovery_integration.rs`
  - `backup_verify_roundtrip`: backup a fixture artifact set, then verify — expect all `VerifyStatus::Ok`
  - `corrupted_archive_detection`: backup, truncate the archive file, verify — expect `VerifyStatus::Corrupted`
  - `missing_sidecar`: backup, delete `.sha256` sidecar, verify — expect `VerifyStatus::Unverifiable`
  - `interrupted_backup_cleanup`: simulate I/O error during archive write, confirm no `.tmp` file remains in the store
  - `restore_dry_run_pass`: backup a valid fixture artifact set, run restore-dry-run — expect `simulation_passed: true`
  - `restore_dry_run_fail`: corrupt one artifact inside a valid archive, run restore-dry-run — expect `simulation_passed: false` and all failures present (not just first)
  - `cli_json_format_stability`: invoke `plan --format json` via a direct handler call with a temp dir, parse output, confirm required fields present and `schema_version == 1`
  - `retention_enforcement_integration`: run N+1 backups with `retention_count = N`, confirm only N archives remain
  - `no_archive_overwrite_integration`: two rapid backups with the same timestamp string, confirm two distinct files exist
  - All tests use `tempfile::TempDir`; no outbound network calls (AI paths mocked via fixture `ai_narrative_response.json`)
  - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [ ]* 21.1 Write property test for backup/verify with all valid policy configurations
    - **Property 5 (extended): Backup → verify for all valid policy configurations**
    - **Validates: Requirements 10.5**
    - For any valid `BackupPolicy` (generated by proptest), backup then verify returns `ok` status for every archive written in that session

  - [ ]* 21.2 Write property test for schema migration round-trip
    - **Property 13: Schema migration round-trip**
    - **Validates: Requirements 9.4**
    - Generate v0-format JSON for each document type; apply migration chain; assert all current fields are present with no loss

- [x] 22. Final checkpoint — full build and test suite
  - Run `cargo build` to confirm the entire crate compiles cleanly
  - Run `cargo test` to confirm all unit and integration tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Checkpoints (tasks 10 and 22) ensure incremental validation
- Property tests use `proptest` (added to `[dev-dependencies]` in task 1)
- All integration tests are isolated with `tempfile::TempDir` and make no network calls
- The AI client (`ai_client.rs`) is always optional; every code path has a deterministic offline fallback
