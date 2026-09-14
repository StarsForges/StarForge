# Privacy-Safe RPC Traffic Recording, Redaction, and Deterministic Replay

StarForge includes a deterministic record and replay facility for JSON-RPC communications between developers, CLI tools, and Stellar / Soroban nodes. It enables capturing live traffic, scrubbing sensitive cryptographic credentials and private data on-the-fly, and deterministically replaying sessions with customizable fault injection to test application resilience and simulate rare network conditions.

---

## Overview

Reproducing intermittent RPC network failures, rate limits, and deserialization issues is notoriously difficult because exchanges are transient and often contain sensitive credentials. StarForge solves this with a privacy-by-default record/replay subsystem that features:

- **Versioned Session Schema (v1)**: Structured JSON capture storing HTTP method, JSON-RPC method, params, result/error payloads, duration, start/end timestamps, headers, and sequence ordering.
- **Deep Field-Aware Redaction**: Automatic multi-pass redaction scrubbing:
  - Stellar secret seeds (`S...` 56-character keys)
  - Bearer tokens, passwords, API keys, private keys, and session cookies
  - Transaction signatures and envelope credentials
  - Local filesystem paths (`/home/...`, `/Users/...`, `C:\...`)
  - Configurable public account masking or deterministic pseudonymization (`--account-strategy`)
  - Redaction evasion defense inspecting nested stringified JSON and Base64 payloads
- **Tamper-Evident Integrity**: SHA-256 digests for individual exchanges and overall session validation.
- **Deterministic Replay Server**: Local mock HTTP server matching incoming JSON-RPC calls against recorded sessions with parameter normalization (ignoring volatile fields, timestamps, and request IDs).
- **Chaos & Fault Injection**: Built-in simulation for artificial latency, jitter, network disconnects, HTTP 429 rate limits with `Retry-After`, and specific JSON-RPC error codes.
- **Strict File Permissions**: Automated Unix file permission enforcement (`0600`) ensuring recorded data remains restricted to the local owner.

---

## Command Reference

The feature is exposed through the `starforge rpc` subcommand tree:

```bash
starforge rpc --help
```

### 1. `starforge rpc record`
Spawns a local reverse-proxy that intercepts JSON-RPC requests, applies on-the-fly privacy redaction, forwards calls to upstream RPC endpoints, measures timing, and atomically writes a versioned session to disk.

```bash
# Record requests sent to local proxy on port 8545 forwarded to Soroban Testnet
starforge rpc record \
  --listen 127.0.0.1:8545 \
  --upstream https://soroban-testnet.stellar.org \
  --output session.json \
  --account-strategy preserve
```

#### Key Options:
- `--listen <ADDR>`: Local IP and port (default: `127.0.0.1:8545`).
- `--upstream <URL>`: Target RPC node URL.
- `--output <FILE>`, `-o`: Destination file path (saved with `0600` permissions).
- `--account-strategy <STRATEGY>`: `preserve`, `mask`, or `pseudonymize`.
- `--custom-pattern <REGEX>`: Custom regex pattern to scrub.
- `--custom-key <KEY>`: Additional JSON key names to treat as sensitive.
- `--max-exchanges <N>`: Automatically terminate after N exchanges.
- `--duration-secs <SECS>`: Automatically terminate after N seconds.

---

### 2. `starforge rpc replay`
Launches a mock JSON-RPC server powered by a recorded session file. Requests are matched either in unordered mode (matching method and normalized parameters) or causal mode (verifying strict sequential ordering).

```bash
# Replay recording with a simulated 150ms network latency
starforge rpc replay \
  --file session.json \
  --listen 127.0.0.1:8545 \
  --fault-delay-ms 150
```

#### Simulating Failures & Fault Injection:
```bash
# Simulate 20% rate limits (HTTP 429)
starforge rpc replay \
  --file session.json \
  --fault-rate-limit-pct 20

# Simulate custom Soroban RPC error code
starforge rpc replay \
  --file session.json \
  --fault-error-code -32000 \
  --fault-error-message "Ledger sequence out of bounds"

# Strict causal replay mode
starforge rpc replay \
  --file session.json \
  --mode causal \
  --strict
```

---

### 3. `starforge rpc inspect`
Inspects a recorded session, displaying exchange summaries, timings, endpoint metadata, and redaction metrics.

```bash
# Human-readable summary
starforge rpc inspect --file session.json --detailed

# Filter by JSON-RPC method
starforge rpc inspect --file session.json --filter-method getHealth

# Machine-readable JSON output for CI pipelines
starforge rpc inspect --file session.json --json
```

---

### 4. `starforge rpc sanitize`
Runs an additional redaction pass on an existing recording session, allowing retroactively masking account IDs or applying new project-specific sensitive keys.

```bash
starforge rpc sanitize \
  --input session.json \
  --output sanitized.json \
  --account-strategy mask \
  --custom-key internal_dev_id
```

---

### 5. `starforge rpc verify`
Performs cryptographic and structural verification of a recording file:
- Schema conformance (`schema_version: 1`)
- Exchange-level and session-level SHA-256 digest validation
- Monotonic causal sequence and parent pointer integrity
- Deep scan for unredacted secrets (Stellar secret seeds, Bearer tokens)
- Restrictive file permission audit (`0600`)

```bash
starforge rpc verify --file session.json --check-secrets --json
```

Exit code is `0` on success and `1` on verification failure.

---

## Security Model & Redaction Guarantees

1. **Opt-in Recording**: Recording is never triggered implicitly. Upstream traffic is only captured when explicitly directed through `starforge rpc record`.
2. **Restrictive Permissions**: Session files are written using atomic temporary files with Unix permission mode `0600` (read/write by owner only).
3. **Defense Against Evasion**: The redactor scans unquoted strings, JSON-escaped strings, and Base64-encoded fields.
4. **Post-Recording Verification**: `starforge rpc verify` provides a secondary security scan to ensure zero leakage before sessions are committed to version control or shared with team members.
