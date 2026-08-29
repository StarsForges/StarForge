# PR: Bidirectional Stellar CLI configuration and identity interoperability

closes #95

## Summary

Adds `starforge interop stellar discover|diff|import|export|sync|doctor` with a reusable, testable domain layer for synchronizing networks, identities, and contract aliases between StarForge (`~/.starforge`) and the official Stellar CLI (`~/.config/stellar`). Supports dry-run diffing, conflict classification, selective import/export, explicit precedence policies, public-only transfer by default, guarded secret migration, provenance tracking, and health checks — all without modifying external files during read-only operations.

## Architecture and decisions

- **Domain/transport/render split** — `src/interop/domain.rs` holds versioned contracts; `src/interop/stellar/*` implements parsers, discovery, diff, sync, doctor, and provenance; `src/commands/interop/*` handles Clap and stdout/stderr rendering only.
- **Format adapters** — Network TOML v1, identity TOML v1/v2, contract alias JSON v1/v2, plus legacy `~/.config/soroban/identity/` scanning.
- **Fingerprints** — SHA-256 content fingerprints per record and aggregate store fingerprints for provenance drift detection.
- **Precedence policies** — `fail_on_conflict` (default), `additive_only`, `starforge_wins`, `stellar_cli_wins`, `newest_fingerprint`.
- **Security defaults** — public-only import/export; `--include-secrets` + Unix `0600` checks for secret migration; `--yes` required to overwrite Stellar CLI files; redaction in JSON exports and output.
- **Exit codes** — `0` success, `1` operational failure, `2` blocking diff conflicts or doctor errors.

## Threat model

Untrusted inputs include Stellar CLI directory trees, symlinks, permissive modes, encrypted secrets, duplicate names, and partial writes. Controls: read-only discovery, atomic private persistence, explicit overwrite confirmation, permission validation, redaction, bounded file sizes, and symlink skipping (configurable). StarForge never overwrites Stellar CLI configuration or exports secret keys without explicit destination, confirmation, and secure-permission checks.

## Compatibility

- Stellar CLI default layout: `network/`, `identities/`, `contract-ids/<network>/`.
- Legacy Soroban CLI `identity/` path supported via `--include-legacy`.
- StarForge contract aliases stored under `~/.starforge/contract-aliases/`.
- JSON machine output uses `schema_version: 1`.

## Test evidence

- 22 colocated unit tests (parser, diff, discovery, permissions, redaction, sync dry-run, provenance, adapter migrations).
- 18 CLI integration tests covering versioned JSON, read-only discovery, network mismatch, public-only export, permission doctor findings, round-trip identity/alias sync, symlink skipping, duplicate detection, legacy path scanning, encrypted-secret opt-in, exit codes, and help text.
- Deterministic fixtures under `tests/fixtures/interop/stellar/` (no live network).

## Documentation

- User guide: `docs/stellar-cli-interop.md`
- Maintainer guide: `docs/maintainers/stellar-cli-interop.md`

## Follow-up

- Optional Stellar CLI global config TOML when a stable schema is documented.
- Signed export bundles after a key-management review.
- Interactive conflict resolution TUI for large diffs.

## CI gate

- [ ] `cargo fmt --all --check`
- [ ] `cargo deny --all-features check`
- [ ] `cargo build --locked`
- [ ] `cargo test --locked`
- [ ] `cargo clippy --all-targets --all-features --locked -- -- -D warnings`
- [ ] `./scripts/e2e-smoke.sh`
