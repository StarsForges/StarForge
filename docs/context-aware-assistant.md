# Context-aware Soroban assistant

StarForge can assemble a privacy-filtered view of a Soroban workspace and use
it for explanation, diagnosis, implementation suggestions, scaffold planning,
and review. The assistant always has a deterministic local mode, so CI and
offline development do not depend on an external AI service.

## Quick start

```bash
# Inspect what StarForge will index; no provider is contacted.
starforge ai assistant index --root .

# Deterministic, network-free workflows.
starforge ai assistant explain "how is authorization structured?" --offline
starforge ai assistant diagnose "simulation failed after an upgrade" --offline
starforge ai assistant suggest "add a pausable transfer operation" --offline
starforge ai assistant scaffold "escrow with a deadline" --name escrow --offline
starforge ai assistant review "review authorization and storage lifetime" --offline

# See the exact redacted prompt without sending it.
starforge ai assistant review "focus on token transfers" --preview

# Stable machine-readable output.
starforge -q ai assistant review "security review" --offline --format json
```

Without `--offline` or `--preview`, StarForge uses `OPENAI_API_KEY` (or
`STARFORGE_AI_API_KEY`) with `gpt-4o-mini` by default. Select another model with
`--model`. If credentials are absent, the request fails, or the provider does
not return the documented structured response, the command succeeds with
deterministic local guidance and reports `mode: "fallback"` and a sanitized
fallback reason. Provider-dependent tests are mocked or use this failure path;
CI never needs network access.

## Indexed context

The indexer recognizes:

- Cargo manifests, including workspace and contract crate manifests;
- Rust contract sources and Soroban contract metadata;
- text templates and project configuration;
- unit and integration tests;
- Stellar/Soroban deployment records and contract ID files.

The persisted index is `.starforge/assistant-index.json`. Its format is
versioned with `schema_version: 1`; readers accept compatible v1 data and ask
the user to rebuild unsupported data. Each entry contains only a relative path,
kind, source size, SHA-256 digest, redacted excerpt, and redaction count.
Absolute project paths are never persisted or placed in provider prompts.

Every assistant invocation refreshes the index so answers do not silently use
stale source. Pass `--no-persist` to keep the refreshed index in memory only.
On Unix, the `.starforge` directory is set to mode `0700` and the index is
written atomically with mode `0600`.

### Configuration

Optional project settings live in `.starforge/assistant.toml`:

```toml
schema_version = 1
redact = true
max_file_bytes = 32768
max_total_bytes = 262144
excluded_paths = ["vendor", "audit/private", "contracts/legacy/*"]
```

Limits are bounded by StarForge to prevent accidental oversized prompts.
Command-line `--exclude RELATIVE_PATH` values are additive and repeatable.
Absolute exclusions and `..` traversal are rejected. StarForge also reads
ordinary non-negated patterns from `.gitignore` and `.starforgeignore`.

## Privacy model

The following are excluded by default: `.git`, `.starforge`, `target`,
`node_modules`, dotenv files, private key/certificate formats, `Cargo.lock`,
and common secret directories covered by project ignore files. Symlinks are not
followed, preventing an indexed directory from escaping the chosen root.

Before persistence or prompt assembly, StarForge redacts common API keys,
authorization/password/seed assignments, provider tokens, JWT-like values,
and Stellar secret seeds. User-supplied request and focus text pass through the
same redactor. Redaction is intentionally conservative and is not a substitute
for reviewing a prompt with `--preview`.

`--no-redact` is an explicit unsafe override. It writes unredacted excerpts to
the local index and may send them to a provider; the CLI emits a warning. Prefer
an exclusion or `.starforgeignore` entry instead.

AI telemetry records provider/model, workflow, input/output token counts (or
deterministic estimates), latency, success, fallback category, and estimated
cost. It never stores prompts, response text, source excerpts, file paths, or
secret values. Manage it with `starforge ai telemetry`.

## JSON response contract (v1)

Workflow commands emit one JSON object and no banner when `--format json` is
used. The top-level fields are:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Response schema; currently `1`. |
| `workflow` | string | `explain`, `diagnose`, `suggest`, `scaffold`, or `review`. |
| `mode` | string | `online`, `offline`, `fallback`, or `preview`. |
| `summary` | string | Concise result summary. |
| `guidance` | array | Structured severity/title/detail findings with optional relative path and line. |
| `sources` | array | Relative indexed paths, kinds, and content digests used for the prompt. |
| `privacy` | object | Redaction/exclusion counts and whether a provider was contacted. |
| `prompt_preview` | object/null | Present only for `--preview`. |
| `provider` | object/null | Provider/model and optional fallback reason. |

Severity values are `info`, `suggestion`, `warning`, and `critical`. Consumers
must ignore unknown additive fields and should reject a larger unsupported
`schema_version`. The integration suite asserts the v1 envelope, modes,
relative paths, redaction, exclusions, previews, and provider fallback.

The `index --format json` response is also versioned. It reports project name,
persistence state, relative persistence path, aggregate counts, and entry
metadata; it intentionally omits excerpts.

## Operational and security review notes

- Secret handling: indexing and request text are redacted by default; preview
  supports inspection before external transmission. Provider responses may
  cite only indexed relative source paths.
- File permissions: versioned persistent data is confined to `.starforge`,
  written via a temporary file and atomic rename, and restricted to the user on
  Unix. Index data is regenerable and `.starforge/` is gitignored.
- Persistence safety: symlinks are skipped, reads are size-bounded, binary
  content is rejected, and path traversal is not accepted for exclusions.
- External providers: use is opt-in through command mode and credentials. Any
  provider or structured-response failure degrades to deterministic guidance;
  source errors are preserved in a short, redacted fallback reason.
- Limitations: deterministic review uses high-signal static heuristics and is
  not a formal audit. Redaction cannot guarantee discovery of every proprietary
  value, so exclusions and prompt previews remain the primary controls.

