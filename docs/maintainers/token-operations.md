# Maintainer guide: token operations

## Architecture

```
src/token/domain.rs     Versioned types, capabilities, receipts, batch manifests
src/token/spec.rs       SEP-41 capability detection from contract spec JSON
src/token/amount.rs     Decimal-safe parsing/formatting
src/token/transport.rs  TokenRpcTransport, Ureq + Mock + AnyTokenTransport
src/token/read.rs       Metadata, balance, allowance, supply reads
src/token/write.rs      Operation planning, simulation, signer checks
src/token/batch.rs      Manifest load/execute with partial failure reporting
src/token/engine.rs     Orchestrator used by CLI
src/commands/token/     Clap + rendering only
```

## Testing strategy

- Unit tests colocated in each module with `MockTokenTransport`.
- CLI tests in `tests/token_cli.rs` pass `--mock` to avoid live RPC.
- Fixtures: `tests/fixtures/token/sep41_spec.json`, `batch_manifest.json`.

## Capability detection

Never assume admin methods exist. `TokenWriter::plan_*` checks `TokenCapabilities` and fails fast with actionable errors.

## RPC boundaries

`UreqTokenTransport` delegates simulation to `utils::soroban::simulate_transaction` for production paths. Tests use deterministic mock responses keyed by function name.

## Versioning

- `TOKEN_SCHEMA_VERSION` — inspect/balance/allowance reports
- `TOKEN_RECEIPT_SCHEMA_VERSION` — operation receipts
- `TOKEN_BATCH_SCHEMA_VERSION` — batch manifests

Bump schema versions when fields change; add migration notes to this guide.

## Threat model

Untrusted inputs: contract IDs, amounts, batch manifests, RPC JSON, wallet names. Controls: strict amount parsing, capability gating, confirmation for admin ops, redaction in receipts, bounded RPC timeouts, no mandatory live network in CI.

## Recovery

1. Re-run with `--simulate` to preview failures.
2. Use `--format json` for stable automation output.
3. For batch partial failures, inspect per-entry `TokenReceipt.status` in the JSON report.
