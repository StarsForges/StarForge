# Stellar protocol and Soroban RPC compatibility

StarForge records compatibility as evidence rather than assuming that a reachable endpoint is usable. The workflow covers the Stellar protocol, compiled `stellar-xdr` release, Soroban RPC methods, Horizon/RPC identity, retention, limits, project artifacts, transaction fixtures, and plugins.

## Quick start

```bash
starforge compatibility matrix
starforge compatibility probe
starforge compatibility status
starforge compatibility audit --path . --format json
starforge compatibility audit --path . --fail-on incompatible --format json
starforge compatibility export --audit-path . --output compatibility-evidence.json
```

Every JSON document has numeric `schema_version: 1`. The matrix also has a dated `matrix_version`; automation should validate both fields. Human output is for operators while JSON field and enum names are stable within schema 1.

## Commands and exit behavior

| Command | Exit 0 | Exit 1 |
|---|---|---|
| `status` | A report was produced, including an incompatible report | Configuration/cache/output failure |
| `probe` | Valid endpoint evidence was produced | Timeout, transport, malformed JSON-RPC, invalid URL, or persistence failure |
| `matrix` | The matrix passed self-validation | Serialization/output failure |
| `audit` | Selected `--fail-on` threshold was not met | Audit failure or threshold was met |
| `export` | Versioned bundle was written | Input, audit, or output failure |

`status` reports hard incompatibility without failing so it remains inspectable. Use `audit --fail-on incompatible` for CI. `--fail-on degraded` also fails on optional missing evidence. `never` is the default.

## Endpoint evidence

The probe calls `rpc.discover`, `getNetwork`, `getLatestLedger`, `getHealth`, and `getVersionInfo`. When discovery is absent, it makes safe invalid-parameter requests for known methods. JSON-RPC `-32602` proves a method exists; `-32601` proves it is missing. Simulation/submission checks use deliberately invalid envelopes and never submit a valid transaction.

Horizon root evidence is compared with RPC. Different hashed network passphrases are a hard incompatibility. A protocol difference is degraded because endpoints may briefly be out of sync; wait for convergence before signing.

```bash
starforge compatibility probe \
  --rpc-url 'https://rpc.example.test/rpc' \
  --horizon-url 'https://horizon.example.test' \
  --timeout-ms 2000 --refresh --format json
```

Requests have bounded connect/read/write timeouts. HTTP error bodies are parsed when they contain JSON-RPC. Vendor methods are evidence but do not satisfy standard method requirements.

## Feature gates and matrix policy

The matrix independently defines hard requirements and optional capabilities for network operations, contract simulation, transaction submission/status, contract events, ledger inspection, and upgrade analysis. Missing hard methods block a gated command with the feature, methods, and remediation. Optional methods degrade only their related features.

Protocols older than 20 are unsupported for this Soroban feature set. Protocols newer than 22 are also hard-incompatible until maintainers add XDR and behavioral evidence. A larger, unknown version is never inferred to be safe.

## Upgrade-readiness audit

The bounded audit skips `.git`, `target`, `node_modules`, `.starforge`, and symlinks. It checks:

- Cargo manifests and `stellar-xdr` release series;
- `.wasm` magic, structure, size, and SHA-256 identity;
- JSON transaction fixtures with protocol/RPC method evidence;
- `starforge-plugin.toml` compatibility declarations;
- optional `starforge.compatibility.toml` requirements;
- fresh cached endpoint evidence.

Example project declaration:

```toml
[protocol]
minimum = 20
maximum = 22
```

Malformed transaction fixtures, invalid WASM, unsupported old versions, and unverified future versions are hard findings. Missing artifacts are informational; missing endpoint evidence is degraded and visible rather than silently passing.

Live access is opt-in: `starforge compatibility audit --path . --probe-endpoints`. Normal CI has no live-network dependency. Deterministic mock responses live under `tests/fixtures/compatibility`.

## Cache, migration, and recovery

Evidence is stored in `~/.starforge/compatibility/capabilities-v1.json`. Default TTL is 300 seconds. Expired entries are excluded from status, audit, and export. `probe --refresh` bypasses a fresh entry; `--no-cache` avoids reads and writes.

The cache and each evidence record are versioned. Schema-0 arrays migrate in memory. A newer schema returns a contextual error and preserves the file. Upgrade StarForge rather than editing future-schema evidence.

Recovery:

1. Preserve the cache for incident review.
2. Validate JSON with `jq .`; malformed content is never silently replaced.
3. Remove only the compatibility cache, not main configuration.
4. Run `starforge compatibility probe --refresh`.
5. Compare identity, protocol, ledger, retention, and missing methods before resuming commands.

For identity mismatch, correct the Horizon/RPC pair. For removed required methods, upgrade or switch the provider. For short retention, use archival RPC and regenerate fixtures outside its window.

## Security

- Reports show only `scheme://host[:port]`; user info, paths, queries, fragments, and tokens are excluded.
- Cache keys are endpoint SHA-256 identifiers and passphrases are represented by hashes.
- Controlled probe errors do not include raw transport error chains.
- Cache directories use Unix mode `0700`; evidence and exports use `0600`. Cache writes are flushed and atomically replaced.
- Fixtures use synthetic identities and invalid envelopes. Never commit credentials, secret seeds, signatures, authorization headers, or provider tokens.
- Probing performs operator-configured outbound requests. Review custom URLs to reduce SSRF exposure.
- Exports contain artifact hashes and project paths; share them only with intended reviewers.

## Troubleshooting

- `protocol.unknown`: verify `getLatestLedger` includes `protocolVersion` and re-probe.
- `protocol.future_unverified`: pause transaction-producing workflows pending XDR/host-function validation.
- `rpc.required_method_missing`: check provider tier/API version or replace the endpoint.
- `endpoint.network_identity_mismatch`: correct the Horizon/RPC pair before signing.
- Expired cache: run `compatibility probe --refresh`.
- Malformed probe: compare a sanitized response with committed fixtures and verify JSON-RPC 2.0 plus `result`/`error`.
