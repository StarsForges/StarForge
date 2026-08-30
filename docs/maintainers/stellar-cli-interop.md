# Maintainer guide: Stellar CLI interoperability

## Architecture

```
src/interop/domain.rs          Versioned contracts, fingerprints, diff/sync reports
src/interop/stellar/parser.rs  Stellar CLI TOML/JSON parsers and serializers
src/interop/stellar/discovery  Read-only store scanning (no writes)
src/interop/stellar/diff.rs    Conflict classification
src/interop/stellar/sync.rs    Selective import/export engine
src/interop/stellar/store.rs   Provenance persistence
src/commands/interop/          CLI rendering only
```

Domain logic is independent from terminal rendering and network transport. All CI tests use fixture directories under `tests/fixtures/interop/stellar/`.

## Supported formats

| Asset | Versions | Location (Stellar CLI) |
|-------|----------|------------------------|
| Network | v1 TOML | `network/<name>.toml` |
| Identity | v1 seed/secret, v2 public+encrypted | `identities/<name>.toml` |
| Contract alias | v1 flat JSON, v2 nested `ids` | `contract-ids/<network>/<alias>.json` |

Legacy `~/.config/soroban/identity/` is scanned when `--include-legacy` is enabled.

## Threat model

**Untrusted inputs:** Stellar CLI config trees, symlinks, permissive file modes, encrypted secret blobs, duplicate names, interrupted writes.

**Controls:**
- Read-only discovery never mutates external files
- Export/import use atomic private writes (`0600` / `0700` on Unix)
- Secrets require `--include-secrets` plus permission validation
- Overwrites require `--yes` for Stellar CLI destinations
- Output redaction via `interop/stellar/redact.rs`

**Non-goals:** Decrypting Stellar CLI platform keychains, validating live network reachability during sync.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Operational error (I/O, validation, sync aborted) |
| 2 | Actionable conflicts (`diff`) or doctor `Error` findings |

## Testing

```bash
cargo test --lib interop
cargo test --test interop_cli
```

Fixtures must not contain real secrets. Use synthetic strkeys from `tests/fixtures/README.md`.

## Forward compatibility

Bump `INTEROP_SCHEMA_VERSION` when JSON report shapes change. Add adapter steps in `interop/stellar/adapter.rs` for new Stellar CLI file formats; preserve unknown future schemas in provenance when possible.
