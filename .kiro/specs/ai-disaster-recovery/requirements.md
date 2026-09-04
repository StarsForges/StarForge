# Requirements Document

## Introduction

This feature adds an AI-assisted disaster recovery and backup orchestration subsystem to StarForge. It enables Soroban/Stellar developers to plan, execute, verify, and simulate restores of contract artifacts, deployment manifests, keys, and ledger state — with AI-powered risk scoring and deterministic offline fallback heuristics. The system surfaces via `starforge ai recovery` subcommands: `plan`, `backup`, `verify`, `restore-dry-run`, and `report`.

The subsystem integrates with StarForge's existing module boundaries (`src/commands/ai/`, `src/utils/`), config/telemetry patterns, secret redaction, and JSON-versioned persistence, so it behaves consistently with existing features like the anomaly detector and context-aware assistant.

---

## Glossary

- **Recovery_Engine**: The subsystem responsible for inventorying artifacts, scoring risk, executing backup policies, and generating recovery plans.
- **Artifact**: A recoverable item associated with a deployed Soroban contract: compiled WASM binary, deployment manifest, contract ID, ledger metadata, or key reference.
- **Backup_Store**: The local or remote directory where versioned, encrypted backup archives are written.
- **Backup_Policy**: A versioned, user-editable configuration object specifying backup cadence, retention count, encryption mode, integrity verification method, and restore-point objective (RPO).
- **Recovery_Plan**: A machine-readable document (JSON) listing all discovered artifacts, their health status, missing items, risk scores, and recommended remediation steps.
- **Risk_Score**: A numeric value (0–100) representing the assessed recovery readiness of a deployment. Higher means higher risk / lower readiness.
- **Restore_Simulation**: A dry-run pass that validates backup archives without writing any files, confirming that a restore would succeed.
- **AI_Provider**: An external LLM API (OpenAI-compatible) used for narrative risk scoring and remediation suggestions. Always optional; offline fallback is mandatory.
- **Offline_Fallback**: Deterministic heuristic logic that produces risk scores and recommendations without calling any external provider.
- **Manifest**: A JSON document recording the contract ID, WASM hash, deploy timestamp, network, deployer key reference, and any known ledger anchors.
- **Integrity_Digest**: A SHA-256 or BLAKE3 hash of a backup archive, stored alongside it and verified on every read.
- **Secret_Redactor**: The existing StarForge utility that strips keys, mnemonics, and sensitive paths from output before display or persistence.
- **Schema_Version**: An integer field present in every persisted JSON document. Incremented on breaking structural changes; read at load time to gate compatibility.

---

## Requirements

### Requirement 1: Artifact Inventory

**User Story:** As a Soroban developer, I want StarForge to enumerate all deployable and recoverable artifacts in my project, so that I know exactly what needs to be protected before a recovery event.

#### Acceptance Criteria

1. WHEN `starforge ai recovery plan` is invoked, THE Recovery_Engine SHALL scan the current project directory and `~/.starforge/` for WASM binaries, deployment manifests, contract IDs, and key references.
2. WHEN the scan completes, THE Recovery_Engine SHALL emit a Recovery_Plan containing one entry per discovered Artifact, each with a `status` field set to `present`, `stale`, or `missing`.
3. IF a WASM binary's SHA-256 digest does not match the digest recorded in its corresponding Manifest, THEN THE Recovery_Engine SHALL set that Artifact's `status` to `stale` and include the expected and actual digests in the plan entry.
4. THE Recovery_Plan SHALL be serialized as valid JSON with a top-level `schema_version` integer field set to `1`.
5. WHEN `--format json` is passed, THE Recovery_Engine SHALL write only the JSON document to stdout; human-readable progress lines SHALL be written to stderr only.
6. WHEN `--output <path>` is passed, THE Recovery_Engine SHALL write the Recovery_Plan to the specified file and print a confirmation line to stdout.
7. IF a scanned path contains a secret key or mnemonic pattern, THEN THE Secret_Redactor SHALL redact that value before the path or content appears in any output or persisted document.

---

### Requirement 2: Backup Policy Definition

**User Story:** As a Soroban developer, I want to define a backup policy so that StarForge knows how often to back up, how many copies to retain, and what level of encryption and integrity checking to apply.

#### Acceptance Criteria

1. THE Recovery_Engine SHALL read backup policy from `~/.starforge/data/recovery/policy.json` when present.
2. WHEN `starforge ai recovery plan --init-policy` is invoked and no policy file exists, THE Recovery_Engine SHALL write a default Backup_Policy to `~/.starforge/data/recovery/policy.json` with `schema_version: 1`, `cadence_hours: 24`, `retention_count: 7`, `encryption: "aes-256-gcm"`, and `integrity: "sha256"`.
3. THE Backup_Policy file SHALL use a `schema_version` integer field; WHEN the file's `schema_version` differs from the current supported version, THE Recovery_Engine SHALL emit an actionable error describing the mismatch and the migration path.
4. WHERE the `encryption` field is set to `"aes-256-gcm"`, THE Recovery_Engine SHALL encrypt each backup archive using AES-256-GCM with an Argon2-derived key before writing it to the Backup_Store.
5. WHERE the `encryption` field is set to `"none"`, THE Recovery_Engine SHALL write unencrypted archives and emit a warning that the backup contains sensitive deployment metadata.
6. THE Backup_Policy SHALL accept a `retention_count` integer between 1 and 365 inclusive; IF the parsed value is outside this range, THEN THE Recovery_Engine SHALL return a validation error with the allowed range.
7. THE Backup_Policy SHALL accept a `cadence_hours` integer between 1 and 8760 inclusive; IF the parsed value is outside this range, THEN THE Recovery_Engine SHALL return a validation error with the allowed range.

---

### Requirement 3: Backup Execution

**User Story:** As a Soroban developer, I want to run `starforge ai recovery backup` to create a durable, versioned archive of my contract artifacts, so that I can recover them if they are lost or corrupted.

#### Acceptance Criteria

1. WHEN `starforge ai recovery backup` is invoked, THE Recovery_Engine SHALL collect all Artifacts identified in the most recent Recovery_Plan (or run a fresh scan if no plan exists) and write them to a timestamped archive in the Backup_Store directory (`~/.starforge/data/recovery/backups/`).
2. THE Recovery_Engine SHALL compute an Integrity_Digest over the completed archive and write it to a sidecar file named `<archive-name>.sha256` in the same directory.
3. IF the archive write is interrupted (process killed, disk full, I/O error), THEN THE Recovery_Engine SHALL delete the incomplete archive and its sidecar file before exiting, leaving no partial artifacts in the Backup_Store.
4. AFTER a successful backup, THE Recovery_Engine SHALL enforce the `retention_count` from the active Backup_Policy by deleting the oldest archives beyond the retention limit, oldest-first by creation timestamp.
5. WHEN `--dry-run` is passed, THE Recovery_Engine SHALL log all files that would be archived and the expected archive path without writing any data to disk.
6. WHEN `--format json` is passed, THE Recovery_Engine SHALL emit a JSON object containing `archive_path`, `artifact_count`, `size_bytes`, `integrity_digest`, and `timestamp` fields to stdout.
7. THE Recovery_Engine SHALL record each backup execution as a telemetry event using the existing StarForge AI telemetry pathway, capturing `artifact_count`, `size_bytes`, `duration_ms`, and `success` boolean.

---

### Requirement 4: Backup Integrity Verification

**User Story:** As a Soroban developer, I want to verify that my backups are intact and can be restored, so that I don't discover corruption only during an actual recovery.

#### Acceptance Criteria

1. WHEN `starforge ai recovery verify` is invoked, THE Recovery_Engine SHALL locate all archives in the Backup_Store and verify each one by recomputing its Integrity_Digest and comparing it against the stored sidecar value.
2. WHEN `starforge ai recovery verify --archive <path>` is invoked, THE Recovery_Engine SHALL verify only the specified archive file.
3. IF an archive's recomputed Integrity_Digest does not match the stored sidecar value, THEN THE Recovery_Engine SHALL report that archive as `corrupted` and include both the expected and actual digest values in the output.
4. IF a sidecar file is absent for an archive, THEN THE Recovery_Engine SHALL report that archive as `unverifiable` and treat it as a failed verification for exit-code purposes.
5. WHEN `--fail-on-any` is passed and at least one archive fails verification, THE Recovery_Engine SHALL exit with a non-zero exit code.
6. WHEN `--format json` is passed, THE Recovery_Engine SHALL emit a JSON array where each element contains `archive_path`, `status` (`ok`, `corrupted`, or `unverifiable`), `expected_digest`, and `actual_digest` fields.
7. THE Recovery_Engine SHALL decrypt encrypted archives using the same key derivation path used during backup before computing the Integrity_Digest; IF decryption fails, THE Recovery_Engine SHALL report that archive as `corrupted`.

---

### Requirement 5: AI-Assisted Risk Scoring

**User Story:** As a Soroban developer, I want StarForge to score my deployment's recovery readiness using AI risk analysis, so that I can identify the most dangerous gaps before they cause a real incident.

#### Acceptance Criteria

1. WHEN `starforge ai recovery plan` completes artifact inventory, THE Recovery_Engine SHALL compute a Risk_Score (0–100) for the overall deployment using the Offline_Fallback heuristics.
2. WHERE an AI_Provider API key is available (`OPENAI_API_KEY` or `STARFORGE_AI_API_KEY`), THE Recovery_Engine SHALL request a narrative risk assessment from the provider, augmenting (not replacing) the deterministic Risk_Score.
3. IF the AI_Provider call fails for any reason (network error, quota exceeded, timeout), THEN THE Recovery_Engine SHALL fall back to the Offline_Fallback heuristics and include a human-readable notice in the output that AI scoring was unavailable.
4. THE Offline_Fallback SHALL assign risk point contributions for: missing WASM binary (+30), missing Manifest (+25), stale digest mismatch (+20), unencrypted key reference in artifact path (+15), no backup in the last `cadence_hours` period (+10).
5. THE Recovery_Plan SHALL include a `risk_score` integer field, a `risk_level` string field set to `low` (0–29), `medium` (30–59), `high` (60–84), or `critical` (85–100), and a `risk_factors` array listing each contributing factor and its point value.
6. WHEN `--fail-on <level>` is passed, THE Recovery_Engine SHALL exit with a non-zero exit code if the computed `risk_level` meets or exceeds the specified level.
7. THE AI narrative SHALL be passed through the Secret_Redactor before being included in any output or persisted document.

---

### Requirement 6: Restore Dry-Run Simulation

**User Story:** As a Soroban developer, I want to simulate a full restore from a backup archive without writing any files, so that I can verify my recovery procedure is viable before an actual emergency.

#### Acceptance Criteria

1. WHEN `starforge ai recovery restore-dry-run` is invoked, THE Recovery_Engine SHALL select the most recent valid archive from the Backup_Store and simulate a full restore by reading and validating each artifact entry without writing any file to the filesystem.
2. WHEN `starforge ai recovery restore-dry-run --archive <path>` is invoked, THE Recovery_Engine SHALL simulate a restore from the specified archive file.
3. THE Recovery_Engine SHALL validate each artifact in the archive by checking: the Integrity_Digest of the artifact bytes, the presence of required Manifest fields (`contract_id`, `wasm_hash`, `network`, `deploy_timestamp`), and that no embedded secret values are present in clear text.
4. IF any artifact fails validation during the simulation, THE Recovery_Engine SHALL report all failures before exiting with a non-zero exit code; THE Recovery_Engine SHALL NOT stop at the first failure.
5. WHEN the simulation completes without failures, THE Recovery_Engine SHALL print a summary line confirming the artifact count, archive age, and estimated restore duration.
6. WHEN `--format json` is passed, THE Recovery_Engine SHALL emit a JSON object with `archive_path`, `artifact_count`, `validation_results` array, `simulation_passed` boolean, and `simulated_restore_duration_ms` fields.
7. WHEN `--fail-on-warning` is passed, THE Recovery_Engine SHALL treat validation warnings (missing optional fields, stale digests) as failures and exit non-zero.

---

### Requirement 7: Recovery Report Generation

**User Story:** As a Soroban developer, I want to generate a structured recovery report summarizing my project's backup health, risk posture, and recommended remediation steps, so that I can share it with teammates or use it in CI.

#### Acceptance Criteria

1. WHEN `starforge ai recovery report` is invoked, THE Recovery_Engine SHALL generate a Recovery_Report combining: the most recent Recovery_Plan, the result of the most recent `verify` run (if any), and a sorted list of remediation recommendations ordered by risk point contribution descending.
2. THE Recovery_Report SHALL be available in `--format markdown` (default) and `--format json`.
3. WHEN `--format json` is passed, THE Recovery_Report JSON SHALL include a `schema_version: 1` field and be stable enough for parsing by automation without breaking changes within the same schema version.
4. WHEN `--output <path>` is passed, THE Recovery_Engine SHALL write the report to the specified file and print a confirmation line to stdout.
5. WHERE an AI_Provider API key is available, THE Recovery_Engine SHALL request a remediation narrative from the provider; IF the call fails, THE Recovery_Engine SHALL fall back to deterministic recommendations without error.
6. THE Recovery_Report SHALL NOT include secret key values, full filesystem paths outside the project root, or unredacted AI-provider responses; THE Secret_Redactor SHALL be applied to all report content before persistence or display.
7. THE Recovery_Engine SHALL record each report generation as a telemetry event capturing `risk_level`, `artifact_count`, `recommendation_count`, and `ai_used` boolean.

---

### Requirement 8: CLI Surface and Command Structure

**User Story:** As a StarForge user, I want the disaster recovery commands to follow the same CLI conventions as other `starforge ai` subcommands, so that I can discover and use them without reading additional documentation.

#### Acceptance Criteria

1. THE Recovery_Engine SHALL be exposed as subcommands under `starforge ai recovery`: `plan`, `backup`, `verify`, `restore-dry-run`, and `report`.
2. WHEN any `starforge ai recovery` subcommand is invoked with `--help`, THE Recovery_Engine SHALL print a concise help string, the list of flags with their defaults, and a usage example; THE help text SHALL NOT expose secret values or internal file paths.
3. WHEN any `starforge ai recovery` subcommand exits with an error, THE Recovery_Engine SHALL print an actionable error message to stderr and exit with a non-zero exit code; THE Recovery_Engine SHALL preserve the source error chain using `anyhow::Context`.
4. WHEN `--network <name>` is passed to any subcommand, THE Recovery_Engine SHALL use the specified network from the StarForge config; IF the network name is not found in config, THE Recovery_Engine SHALL return an error naming the unknown network.
5. ALL `starforge ai recovery` subcommands SHALL support `--format json` for machine-readable output and `--format human` (default) for human-readable output.
6. WHEN `--yes` is passed to `backup` or any destructive operation, THE Recovery_Engine SHALL skip interactive confirmation prompts; WHILE `--yes` is absent and the operation is destructive, THE Recovery_Engine SHALL prompt for confirmation before proceeding.
7. THE Recovery_Engine SHALL support a `--deterministic` flag on `plan` and `report` subcommands that forces Offline_Fallback logic and suppresses all AI_Provider calls, making the command suitable for offline or CI use.

---

### Requirement 9: Persistence and Versioned Format Safety

**User Story:** As a StarForge maintainer, I want all recovery data to use versioned, forward-compatible JSON formats so that upgrades do not silently corrupt or drop user backup history.

#### Acceptance Criteria

1. THE Recovery_Engine SHALL store all persistent state (Recovery_Plan, Backup_Policy, verify results, report history) under `~/.starforge/data/recovery/` with file permissions set to `0600` for files and `0700` for directories on Unix systems.
2. EVERY persisted JSON document written by THE Recovery_Engine SHALL include a top-level `schema_version` integer field.
3. WHEN THE Recovery_Engine reads a persisted document whose `schema_version` is higher than the current supported version, THE Recovery_Engine SHALL return an error naming the unsupported version and instructing the user to upgrade StarForge.
4. WHEN THE Recovery_Engine reads a persisted document whose `schema_version` is lower than the current supported version, THE Recovery_Engine SHALL apply forward migrations in sequence and re-serialize the document before use; no silent data loss SHALL occur during migration.
5. ALL file writes to the Backup_Store SHALL use an atomic write pattern: write to a `.tmp` sidecar, then rename to the final path; IF the rename fails, THE Recovery_Engine SHALL delete the `.tmp` file and return an error.
6. THE Recovery_Engine SHALL never overwrite an existing archive file; WHEN a filename collision occurs, THE Recovery_Engine SHALL append a monotonic counter suffix before writing.

---

### Requirement 10: Test Coverage and Fixture-Based Isolation

**User Story:** As a StarForge contributor, I want the disaster recovery subsystem to have deterministic, network-free tests for all critical code paths, so that CI never depends on external service availability.

#### Acceptance Criteria

1. THE Recovery_Engine SHALL include unit tests for: the Offline_Fallback risk scorer, artifact inventory classification, archive write/read round-trip (FOR ALL valid artifact sets, serializing then deserializing a backup SHALL produce an equivalent artifact list), backup retention enforcement, and Integrity_Digest computation and verification.
2. THE Recovery_Engine SHALL include integration tests for: CLI subcommand output format (`--format json` stability), corrupted archive detection, missing sidecar detection, interrupted backup write cleanup, and restore-dry-run simulation pass and fail paths.
3. ALL integration tests that depend on filesystem state SHALL use `tempfile::TempDir` for isolation and SHALL NOT read from or write to `~/.starforge/` during test execution.
4. ALL integration tests that would normally call an AI_Provider SHALL use a mock or fixture response; THE tests SHALL NOT make outbound network requests.
5. THE Recovery_Engine SHALL include at least one property-based test verifying that FOR ALL valid Backup_Policy configurations, a backup followed by a verify SHALL return `ok` status for every archive written in that session.
6. THE Recovery_Engine SHALL include fixtures under `tests/fixtures/recovery/` for: a valid Recovery_Plan JSON, a corrupted archive (truncated bytes), a missing-sidecar archive, and a valid Backup_Policy JSON.

---

### Requirement 11: Security Posture

**User Story:** As a StarForge security reviewer, I want the disaster recovery subsystem to handle secrets, file permissions, and external-provider interactions safely, so that using the feature does not increase the project's attack surface.

#### Acceptance Criteria

1. THE Recovery_Engine SHALL redact all secret key values, mnemonic phrases, and bearer tokens from output and persisted documents using the existing Secret_Redactor before any write or print operation.
2. WHEN writing any file under `~/.starforge/data/recovery/`, THE Recovery_Engine SHALL set Unix permissions to `0600` (files) or `0700` (directories); on non-Unix platforms THE Recovery_Engine SHALL proceed without setting permissions and log a debug-level notice.
3. THE Recovery_Engine SHALL NOT log or emit the AES-256-GCM encryption key, the Argon2 salt, or the derived key material at any log level.
4. WHEN communicating with an AI_Provider, THE Recovery_Engine SHALL strip all filesystem paths outside the project root, all key values, and all contract IDs from the prompt before transmission, using the Secret_Redactor.
5. IF the AI_Provider response contains a pattern that matches a secret key format (Stellar `S...` keys, mnemonics, hex-encoded 32-byte values), THEN THE Recovery_Engine SHALL redact those values before including the response in any output.
6. THE Recovery_Engine SHALL NOT create world-readable files; IF a file is created with permissions broader than `0644`, THE Recovery_Engine SHALL immediately correct the permissions before returning.
