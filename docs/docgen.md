# Documentation Generation & Knowledge Base

`starforge docs` turns compiled Soroban contract artifacts into deterministic,
commit-friendly documentation plus a machine-readable knowledge base
(`kb.json`). It is designed for CI: every output is byte-for-byte reproducible,
quality gates exit non-zero on failure, and secret redaction is on by default.

## Why a knowledge base instead of plain Markdown

- **Authoritative signatures.** Function, error, and type information comes
  from the WASM `contractspecv0` custom section — the same metadata the host
  environment enforces at invocation time.
- **Stable IDs.** Every entry gets an ID such as `fn:transfer`,
  `err:ContractError::InsufficientBalance`, or `key:DataKey::Balance`, so diffs
  match entries structurally rather than by prose similarity.
- **Regenerable prose is excluded from churn.** AI explanations are stored but
  never appear as changes in diffs; doc-only edits are surfaced without being
  flagged as breaking.

## Commands

### `starforge docs generate`

```bash
starforge docs generate target/wasm32-unknown-unknown/release/my_contract.wasm \
    --project-name my_contract \
    --format all            # markdown + json (default)
    --out docs              # default: ./docs
```

Produces:

| File | Purpose |
|---|---|
| `docs/kb.json` | The knowledge base: functions, events, errors, storage keys, types, deployment requirements, summary counters |
| `docs/<name>.md` | Human-readable reference with anchors (`<a id="fn-transfer"></a>`) and cross-links |

Extraction combines two evidence sources:

1. **Confirmed** — XDR spec entries from the WASM (functions, error enums,
   UDTs) plus module facts (env imports, memory pages, data segments,
   constructor export).
2. **Heuristic, marked as inferred** — source-tree scans for
   `#[contractevent]` structs and storage durability hints, since XDR v22 spec
   metadata does not carry events or durability.

Options of note:

- `--ai-explain` — augment function explanations via the configured AI
  provider (uses `OPENAI_API_KEY` / `STARFORGE_AI_API_KEY`). Capped at 25
  calls per run; prompts and responses pass through redaction; failures
  degrade silently to the deterministic template explanation.
- `--no-redact` — disable redaction (see below). Off by default.
- `--source-dir <dir>` — where to scan for heuristic event/storage evidence.

### `starforge docs validate`

CI-safe quality gate over an existing `kb.json`:

```bash
starforge docs validate docs/kb.json --min-coverage 80 --require-function-docs
```

Checks integrity (schema version, hash consistency), documentation coverage,
and optional strict policies (`--require-error-docs`, `--require-param-docs`).
With `--format json` it prints a machine-readable report; exit code is
non-zero when the gate fails.

### `starforge docs diff`

Structural comparison of two knowledge bases by stable ID:

```bash
starforge docs diff docs/kb.json docs-new/kb.json --fail-on-breaking
```

Removing a public function is breaking; changing its signature is breaking;
improving its docs is not. Output is a deterministic Markdown table (also the
JSON body with `--format json`).

### `starforge docs stale`

Fails when committed documentation no longer matches the freshly built
artifact — the complement of `diff` for keep-docs-honest workflows:

```bash
starforge docs stale target/.../my_contract.wasm docs/kb.json
starforge docs stale ... --allow-stale --format json   # report-only mode
```

### `starforge docs publish-preview`

Renders a review bundle (`index.md` + `manifest.json` with per-file SHA-256)
for PR previews:

```bash
starforge docs publish-preview docs/kb.json --out preview
```

## Redaction

Knowledge bases are meant to be committed, so every free-text field passes
through redaction at extraction time:

- Stellar `S…` secret keys → `S…[REDACTED_SECRET:<fingerprint>]`
- 64-character hex keys → `[REDACTED_HEX_KEY:<fingerprint>]`
- Bearer-token-shaped strings → `[REDACTED_BEARER_TOKEN]`
- Your home directory prefix → `~`

Fingerprints are short SHA-256 prefixes so reviewers can tell *which*
credential appeared without learning its value. Disable globally-inconvenient
cases with `--no-redact` only when you know the artifact is safe.

## Determinism

Given the same WASM artifact and flags, `generate`, `validate` (JSON),
`diff`, and `publish-preview` produce byte-identical outputs across runs and
machines. Timestamps live outside the hashed content model, and entries are
sorted deterministically before rendering.

## Testing without a network

All core paths (extraction, rendering, diffing, gates, preview bundling) are
fully offline. Only `--ai-explain` performs network calls, and it degrades to
template explanations when no API key is configured. The integration suite
(`tests/docgen_cli.rs`) exercises the CLI end-to-end against synthetic
contracts built from real XDR encodings.
