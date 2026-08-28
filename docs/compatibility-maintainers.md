# Compatibility subsystem maintainer guide

## Architecture

`src/compatibility/domain.rs` owns stable contracts, the matrix, evaluation, diagnostics, and gates with no terminal/HTTP behavior. `transport.rs` owns `RpcTransport`, the bounded `ureq` adapter, parsing, discovery, safe method checks, and redaction. `cache.rs` owns versioned persistence, TTL, migration, atomic writes, and permissions. `audit.rs` owns bounded filesystem inspection. `src/commands/compatibility.rs` resolves existing configuration, orchestrates the layers, renders human output, and emits JSON.

This separation gives domain, transport, cache, and audit tests no live-service dependency. The binary and library export the domain for other commands and plugin tooling.

## Matrix updates

A protocol upgrade is an evidence change, not a numeric edit:

1. Upgrade `stellar-xdr` and review `Cargo.lock`.
2. Add `ProtocolCapability` and update the XDR range.
3. Review method introductions and provider behavior.
4. Review every feature range and hard/optional method set.
5. Add old/current/future cases and XDR/transaction fixtures.
6. Add host-function and simulation regression fixtures.
7. Test discovery and invalid-parameter classification with mocks.
8. Date `MATRIX_VERSION` to the evidence review and cite evidence in the PR.

Never extend `MAX_PROTOCOL_VERSION` solely to clear a gate. Future versions remain incompatible until validated.

## Serialization and migration

Schema 1 permits additive optional fields only when existing meanings do not change. Renames, removals, enum semantic changes, or trust changes require schema 2. For a new persistent schema, use a new filename, deserialize schema-agnostic JSON first, migrate explicitly with fixtures, reject/preserve future versions, and retain permission/atomic-write tests. `BTreeMap`, `BTreeSet`, and explicit sorts keep reports deterministic.

## Probe rules

- Every new request uses `RpcTransport` and bounded timeouts.
- JSON-RPC evidence must have `jsonrpc: "2.0"` and either `result` or `error`.
- `-32601` is absent; `-32602` is implemented with invalid probe input.
- Probe inputs never contain valid XDR, hashes, accounts, signatures, or transactions.
- Never include raw URLs or `ureq` chains in findings; use `display_endpoint` and controlled detail.
- Vendor extensions never satisfy standard requirements implicitly.
- Horizon failure degrades RPC evidence; malformed core RPC evidence aborts the probe.

Sanitize provider regression fixtures: remove headers, identities, tokens, transaction material, and signatures.

## Threat model

Inputs include malicious endpoints, credential URLs, malformed JSON-RPC, inconsistent pairs, oversized projects, symlinks, malformed JSON/TOML/WASM, untrusted plugins, stale evidence, and future schemas. Controls are validation, redaction/hashing, request/file bounds, symlink exclusion, structural WASM validation, typed parsing, stable findings, private persistence, TTL, and non-destructive future-schema rejection.

Method presence is not attestation of correct execution. Fixture and simulation tests remain required. TLS trust is delegated to the configured HTTP stack; plain HTTP belongs only in local development.

## Test and release gates

Coverage includes old/current/future protocols, hard/optional methods, vendor discovery, inconsistent identities, malformed responses, redaction, exact TTL expiry, future schema, permissions, valid/invalid artifacts and fixtures, CLI help/JSON/mocks/exit gates, and offline smoke paths.

After the last merge/rebase run:

```bash
cargo fmt --all --check
cargo deny --all-features check
cargo build --locked
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
./scripts/e2e-smoke.sh
```

Normal CI does not set `STARFORGE_E2E=1`; compatibility networking uses mock servers.

## Rollback

The feature adds no required config field and never mutates project files. Preserve exports/cache for review, install the prior binary, and remove only `~/.starforge/compatibility` if the old release rejects it. Wallet, network, plugin, and telemetry state remain unchanged. A rollback must not be used to bypass a future-protocol gate: an older release has less evidence, not more.
