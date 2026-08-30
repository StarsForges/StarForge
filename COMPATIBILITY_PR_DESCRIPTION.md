# PR: production Stellar protocol and Soroban RPC compatibility auditing

## Summary

Adds `starforge compatibility status|probe|matrix|audit|export` and a reusable evidence-backed domain. It detects unsupported old protocols, blocks unverified future protocols, distinguishes hard from optional capabilities, probes configured endpoints, caches versioned evidence, audits projects/artifacts/fixtures/plugins, gates supported workflows, and exports stable JSON.

## Architecture and decisions

- Domain contracts/evaluation are independent from rendering and transport.
- `RpcTransport` separates deterministic mocks from bounded `ureq` production behavior.
- Persistence has schema 1, TTL, schema-0 migration, future-schema preservation, atomic writes, and Unix `0700`/`0600` modes.
- The bounded auditor skips symlinks/build trees, validates WASM, XDR, transaction fixtures, project/plugin requirements, and endpoint status.
- JSON commands suppress the banner; explicit audit thresholds provide CI behavior.
- Simulation/submission paths consume fresh evidence and give actionable gates.
- Plugin manifests/SDK declare protocol and RPC requirements.

Protocols 20–22 are validated with `stellar-xdr` 22. Above 22 is hard-incompatible until XDR and behavior are tested. `-32601` is missing; `-32602` proves presence using invalid transaction data.

## Threat model

Untrusted inputs include URLs/credentials, malformed RPC, inconsistent endpoints, oversized/malformed files, symlinks, fixtures/plugins, stale caches, and future formats. Controls: bounded timeouts/files, controlled errors, hashing/redaction, invalid transaction probes, symlink exclusion, typed/structural validation, private atomic persistence, TTL, and future-schema preservation.

RPC presence is evidence, not attestation. Semantic fixture and simulation coverage remains required.

## Migration and recovery

No existing config field is required or rewritten. Schema-0 caches migrate in memory; future schemas are preserved. Rollback installs the prior binary and may remove only `~/.starforge/compatibility`; wallet/network/plugin data is unchanged.

## Test evidence

Added old/current/future protocol, missing method, vendor, inconsistent endpoint, malformed probe, redaction, cache expiry/schema/permission, WASM/XDR/fixture/plugin, CLI JSON/help/mock/exit/export, and offline smoke coverage.

Final commit gate:

- [ ] `cargo fmt --all --check`
- [ ] `cargo deny --all-features check`
- [ ] `cargo build --locked`
- [ ] `cargo test --locked`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `./scripts/e2e-smoke.sh`
- [ ] target branch integrated without conflicts; gates rerun if commit changed

## Follow-up

Add protocol 23 only after its XDR/host-function fixtures are validated. Add provider adapters only when standard discovery is insufficient. Consider signed exports after a key-management review; current private exports are deliberately unsigned.
