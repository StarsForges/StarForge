# Natural-language Soroban queries

`starforge query` turns a question into an inspectable, read-only Soroban RPC
plan. Common questions use deterministic offline interpretation; AI planning is
optional.

## Workflows

Preview without a network request:

```bash
starforge query plan "show the last 10 events for CABC..." --network testnet
```

Review and execute stable JSON:

```bash
starforge query plan "what is the current ledger?" \
  --format json --output query-plan.json
starforge query execute query-plan.json \
  --format json --output query-report.json
```

Ask and execute in one step:

```bash
starforge query ask "show storage and recent events for CABC..." --network testnet
```

Add `--dry-run` to `ask` or `execute` for a no-network check. Human output
displays the plan before execution. JSON output remains one parseable document.
Existing files require `--overwrite`; new artifacts use mode `0600` on Unix.

## Supported deterministic intents

- latest/current ledger;
- contract state and instance storage;
- recent contract events, with `last N`, `limit N`, or a quoted topic;
- transaction status using a 64-character hexadecimal hash;
- multiple intents, such as events and storage.

Contract queries require a 56-character contract ID beginning with `C`. An
unrecognized question fails with examples instead of being guessed.

## AI planning and fallback

```bash
export STARFORGE_QUERY_AI_API_KEY="..."
starforge query plan "summarize activity for CABC..." --ai
```

`OPENAI_API_KEY` is also accepted. `STARFORGE_QUERY_AI_ENDPOINT` selects an
OpenAI-compatible chat-completions endpoint and must use HTTPS, except for
localhost fixtures. `--model` defaults to `gpt-4`.

Only the question, network name, and fixed safety instructions go to the
provider. StarForge does not add wallet data, environment values, files, or
local paths. Provider JSON is untrusted and passes normal plan validation.
Provider failure falls back locally and is visible as `source: "ai_fallback"`
plus a warning. If both planners fail, the command exits non-zero with redacted
provider context.

## Safety model

Execution has a closed RPC allowlist: `getLatestLedger`, `getLedgerEntries`,
`getEvents`, and `getTransaction`. It cannot submit or simulate transactions,
invoke contracts, sign data, or load wallets. Requests for mutation, transfers,
deployment, invocation, credentials, seed phrases, API keys, environment
variables, or credential files fail before AI or RPC access.

RPC and AI endpoints require TLS except localhost development fixtures.
Embedded endpoint credentials are rejected. Evidence stores only endpoint
origins, omitting URL paths and queries. Sensitive response keys,
secret-key-shaped strings, and absolute home paths are redacted.

## Stable formats and failures

Plans use `starforge.query-plan/v1`; reports use
`starforge.query-report/v1`. Unknown plan versions fail closed. Reports contain
status, the validated plan, findings, and evidence. Each finding links to stable
evidence IDs. Timestamps and random IDs are intentionally absent, making equal
fixture inputs byte-stable.

If one RPC operation fails, later operations continue and the report becomes
`partial`; redacted failure context is linked as evidence. Unsafe plans,
malformed files, incompatible versions, and transport setup errors exit 1.

## Security review notes

- Secret redaction happens before provider access and recursively on RPC data.
- Explicit exports use owner-only Unix permissions and never overwrite by
  default.
- Only `--output` persists versioned deterministic JSON.
- AI is opt-in, receives minimal data, requires TLS, and cannot bypass safety.
- The executor exposes no state-changing RPC methods; CI uses mocks and does
  not depend on external services.
