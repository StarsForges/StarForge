# Maintainer Guide: RPC Traffic Recording, Redaction, and Deterministic Replay

This document details internal architecture, schema invariants, forward-compatibility migrations, and operational recovery procedures for StarForge's RPC record/replay subsystem.

---

## 1. Subsystem Architecture

The subsystem is decoupled into independent domain layers located in `src/utils/rpc_recording/`:

| Module | Responsibility | Key Invariants |
|---|---|---|
| `types.rs` | Data models and serialization schemas | `CURRENT_SCHEMA_VERSION = 1`. Deterministic canonical digest calculation across exchanges. |
| `redaction.rs` | Field-aware and pattern-based sanitization | Recursive AST traversal. Deep inspection of Base64 strings and nested JSON. |
| `replay.rs` | Deterministic request matching & mock server | Parameter normalization (stripping nonces, timestamps). Causal vs unordered state tracking. |
| `fault.rs` | Chaos and failure injection engine | Thread-safe atomic counters for rate-limiting, latency, and RPC errors. |
| `verifier.rs` | Cryptographic verification & leak audit | Validates SHA-256 digests, causal chains, and scans for residual secret patterns. |
| `proxy.rs` | Live capture reverse-proxy | Bounded network timeouts, live redaction, atomic disk writes with `0600` permissions. |

CLI entrypoints and argument mapping are isolated in `src/commands/rpc.rs`.

---

## 2. Schema Evolution and Migration Contract

The recording schema version is indicated by the top-level `schema_version: u32` field:

### Version Invariants:
- **Schema Version 1 (`CURRENT_SCHEMA_VERSION = 1`)**:
  - Requires `session_id`, `created_at`, `updated_at`, `endpoint`, `exchanges`, and `session_digest`.
  - Each `RecordedExchange` maintains `sequence_id: u64` and optional `parent_id: Option<String>`.
- **Legacy Migration (Version 0)**:
  - If `schema_version` is missing or `0`, `RecordingSession::from_json_value_migrated` synthesizes missing metadata, re-sequences exchanges starting at index 0, establishes monotonic `parent_id` causal links, and calculates cryptographic digests.
- **Forward Incompatibility**:
  - If a file has `schema_version > CURRENT_SCHEMA_VERSION`, the parser immediately returns an explicit error to prevent data loss or silent field truncation.

---

## 3. Cryptographic Digest Calculation

Digest calculation is tamper-evident:
1. **Exchange Digest (`exchange_digest`)**:
   ```
   SHA256( sequence_id || parent_id || method || jsonrpc_method || canonical_params || status_code || canonical_body )
   ```
2. **Session Digest (`session_digest`)**:
   ```
   SHA256( session_id || schema_version || exchange_digest_0 || exchange_digest_1 || ... )
   ```

Any manual alteration of request parameters or response bodies invalidates the hash and is flagged by `starforge rpc verify`.

---

## 4. Replay Parameter Normalization Rules

In JSON-RPC workflows, clients generate volatile values that differ between recording and replay:
1. **Request IDs**: The `id` field is matched independently; the mock server replaces the recorded response's `id` with the client's current `id`.
2. **Volatile Parameters**: Fields named `timestamp`, `created_at`, `nonce`, and `request_id` are ignored during parameter equality comparisons.
3. **Canonical Empty Parameters**: An empty object `{}` and empty array `[]` (or `null`) are normalized to canonical empty arrays to support varying client implementations.

---

## 5. Troubleshooting & Operational Recovery

### Issue: Replay reports "Causal sequence exceeded"
- **Cause**: The client issued more requests than were recorded, or requests arrived out of order while running in `--mode causal`.
- **Remedy**: Switch to `--mode unordered` or re-record the full user journey.

### Issue: Verification fails with "Insecure file permissions"
- **Cause**: The recording file was modified, moved through an archive, or created on a non-standard umask.
- **Remedy**: Run `chmod 0600 <file.json>` or re-save with `starforge rpc sanitize --in-place`.

### Issue: "CRITICAL SECURITY LEAK" in verify output
- **Cause**: An unredacted secret seed (`S...`) or Bearer token was detected in the payload.
- **Remedy**: Run `starforge rpc sanitize --input <file> --in-place --account-strategy mask` with appropriate `--custom-key` or `--custom-pattern` arguments.
