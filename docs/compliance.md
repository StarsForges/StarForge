# Compliance Checking

`starforge compliance` runs a configurable, deterministic regulatory-compliance
check against a Soroban contract artifact and its deployment metadata, with an
optional AI-assisted explanation layer.

> **This is a configurable starting point, not legal advice.** The built-in
> control catalog is illustrative — inspired by commonly cited regulatory
> themes (access control, data privacy, financial controls, upgrade
> governance, audit trails, incident response, disclosures) — and is not an
> authoritative interpretation of any specific jurisdiction's law. Adapt it
> with qualified legal review before relying on it operationally.

## Why deterministic evaluation is authoritative

Every control's pass/fail/waived/needs-evidence status comes from static wasm
inspection (`wasmparser`) and explicit fields in a deployment-metadata file you
control — never from a language model. AI assistance (`--explain`) only
attaches a plain-language explanation *after* the deterministic status is
already fixed; it is never consulted when computing that status, and a report
never changes based on which AI provider (or none) generated its
explanations. See `src/utils/compliance/scanner.rs` and
`src/utils/compliance/ai_assist.rs` for the enforcement boundary.

## Commands

### `starforge compliance profile init`

Creates `~/.starforge/compliance/profile.toml`, selecting which
jurisdictions/baselines are in scope:

```bash
starforge compliance profile init --jurisdiction global-baseline --jurisdiction aml-kyc-baseline
```

Defaults to `global-baseline` if no `--jurisdiction` is given. Re-running
without `--force` fails rather than silently overwriting; `--force`
re-initializes while preserving any waivers already on file.

### `starforge compliance profile show`

Prints the current profile, every available jurisdiction/baseline, and how
many controls are currently in scope.

### `starforge compliance check`

```bash
starforge compliance check \
  --wasm target/wasm32-unknown-unknown/release/my_contract.wasm \
  --metadata deployment-metadata.toml
```

- `--wasm` (optional): enables the wasm-based controls (e.g. `require_auth`
  presence, pause/emergency-stop export detection, a coarse scan for
  personal-data-shaped strings in the data section). Omitting it marks those
  controls `needs-evidence` rather than guessing.
- `--metadata` (optional): a TOML file describing signer setup and
  operational policy (see [Deployment metadata](#deployment-metadata) below).
  Omitted fields default to the least-compliant value (e.g. `false`), so an
  unconfigured check fails loudly instead of passing by omission.
- `--format human|json` (default `human`).
- `--explain`: attach an AI-assisted explanation to every non-passing
  finding. Requires `OPENAI_API_KEY` or `STARFORGE_AI_API_KEY` — fails fast
  with a clear error if neither is set, before any network call is attempted.
  Omit it to run a fully local, deterministic check with zero network
  dependency.
- `--reveal-secrets`: skip redaction of secret-shaped values in `--format
  json` output. Off by default.

Exit code is non-zero if any control is actively `fail`ing. A `needs-evidence`
control alone (nothing wasm/metadata could verify) does not fail the process,
but is called out in the report.

### Deployment metadata

A TOML file answering the operational-policy questions static analysis can't:

```toml
signer_public_keys = ["GALICE...", "GBOB..."]
signer_threshold = 2
upgrade_authority_multisig = true
upgrade_timelock_seconds = 86400
stores_personal_data = false
data_minimization_reviewed = false
kyc_provider_integrated = true
sanctions_screening = true
transfer_restrictions_documented = false
has_pause_mechanism = true
incident_response_contact = "security@example.com"
terms_of_service_url = "https://example.com/tos"
privacy_policy_url = "https://example.com/privacy"
```

Every field is optional and defaults to the least-compliant value.

### `starforge compliance evidence record` / `list`

Append-only log of supporting evidence (document references, reviewer
attestations) for a specific control, stored at
`~/.starforge/compliance/evidence.jsonl`:

```bash
starforge compliance evidence record \
  --control AT-2 --description "Quarterly review completed" --reviewer alice
starforge compliance evidence list --control AT-2
```

### `starforge compliance waiver add` / `list` / `revoke`

A waiver is a time-boxed, reasoned exception for a specific failing or
evidence-pending control. It never hides the original finding — a waived
control's report entry still shows what the scanner found and which waiver
(by ID) is covering it.

```bash
starforge compliance waiver add --control FC-1 --reason "Pilot phase, no regulated flows yet" \
  --expires-in-days 90 --approved-by "jane@example.com"
starforge compliance waiver list
starforge compliance waiver revoke <waiver-id>
```

Omitting `--expires-in-days` creates a waiver that never expires — use
sparingly.

### `starforge compliance report export`

Runs the same deterministic check as `compliance check` and writes the result
to a file, for audit records:

```bash
starforge compliance report export --wasm my_contract.wasm --metadata deployment-metadata.toml \
  --format markdown --output compliance-report.md
```

`--format json|markdown` (default `json`). Like `check`, secret-shaped values
are redacted unless `--reveal-secrets` is passed explicitly.

## Redaction

Evidence descriptions, waiver reasons, and metadata are free text a person
types — a Stellar secret key or full public key can end up pasted into them
by accident. Every report render path (`to_json_redacted`, `render_human`,
`render_markdown`) passes free-text fields through
`src/utils/compliance/redact.rs`, which:

- fully redacts anything shaped like a Stellar secret key (`S...`, 56 chars),
- partially redacts (`GDRX...4T`) anything shaped like a public key or
  contract ID, reusing `crate::utils::logging::redact_public_key`,
- and replaces a leading `$HOME` path prefix with `~` in evidence file
  references.

Pass `--reveal-secrets` to opt out for a specific export.

## Persistence

- `~/.starforge/compliance/profile.toml` — versioned (schema `version`
  field), migrated with the same `serde_json::Value`-based pure-migration
  engine as `crate::utils::config` (see
  `src/utils/compliance/migrations.rs`). Saving over a file with a different
  schema version writes `profile.toml.bak` first.
- `~/.starforge/compliance/evidence.jsonl` — append-only, one JSON record per
  line, schema-versioned per record.

## Testing without a network

The deterministic path (`compliance check` without `--explain`) never makes a
network call — controls are evaluated purely from static wasm inspection and
the metadata file you provide. `--explain` is exercised in tests only through
a mock `ComplianceExplainer` implementation
(`src/utils/compliance/ai_assist.rs`); a CLI test confirms `--explain` without
an API key fails immediately with a clear error instead of attempting a
request.
