# PR: Soroban token administration, allowance, and supply operations

closes #97

## Summary

Adds `starforge token inspect|balance|allowance|transfer|approve|mint|burn|authorize|admin|batch` with a typed SEP-41 interface layer, capability detection from contract specs, decimal-safe amount parsing, expiration-ledger support, simulation-first write paths, batch manifests with partial failure reporting, and stable versioned JSON receipts for automation.

## Architecture and decisions

- **Domain/transport/render split** — `src/token/*` holds contracts, RPC transport (`UreqTokenTransport` + `MockTokenTransport`), read/write engines; `src/commands/token/*` is CLI-only.
- **Capability detection** — `spec.rs` parses contract spec JSON and classifies SEP-41 functions/extensions; write planners fail fast when methods are absent.
- **Decimal safety** — amounts parsed/formatted as `i128` smallest units via `amount.rs`.
- **Simulation default** — write commands simulate unless submission is explicitly enabled in future; receipts use `schema_version: 1`.
- **Batch manifests** — versioned JSON with per-entry receipts; partial failures recorded without aborting the entire batch during simulation.
- **Offline CI** — hidden `--mock` flag routes through deterministic fixtures; no mandatory live Soroban RPC in tests.

## Threat model

Untrusted inputs include contract specs, user-supplied amounts, batch manifests, RPC responses, and wallet names. Controls: capability gating for privileged ops, `--yes` for admin confirmations, amount validation, RPC timeouts, receipt redaction, and mock-only CI paths.

## Compatibility

- Targets SEP-41-style fungible token interfaces; optional extensions (mint/burn/clawback/admin/authorization) detected at runtime.
- Does not assume every token exposes administrative methods.
- JSON output uses stable snake_case field names with explicit schema versions.

## Test evidence

- Colocated unit tests: amount parsing, spec detection, mock transport, read/write planners, batch partial failure, receipt redaction.
- CLI integration tests (`tests/token_cli.rs`): inspect, balance, allowance, transfer, approve, mint, burn, admin, batch, help text, banner-free JSON, negative amount rejection — all with `--mock`.

## Documentation

- User guide: `docs/token-operations.md`
- Maintainer guide: `docs/maintainers/token-operations.md`

## Follow-up

- Live submission path wiring through existing `utils::soroban::invoke_contract` with signer checks.
- `transfer_from` and `clawback` CLI exposure.
- Contract spec fetch caching parallel to compatibility evidence store.

## CI gate

- [ ] `cargo fmt --all --check`
- [ ] `cargo deny --all-features check`
- [ ] `cargo build --locked`
- [ ] `cargo test --locked`
- [ ] `cargo clippy --all-targets --all-features --locked -- -- -D warnings`
- [ ] `./scripts/e2e-smoke.sh`
