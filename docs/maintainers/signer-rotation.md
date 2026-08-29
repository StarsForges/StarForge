# Maintainer guide: signer rotation

## Module boundary

`src/signer_rotation` is a library boundary used by the CLI and tests:

- `domain.rs` owns schema-1 policy types, availability, sponsorship, safety
  findings, canonical fingerprints, mutations, and approval selection.
- `planner.rs` owns deterministic ordering, intermediate authorization proofs,
  verification challenges, checkpoints, and full emergency rollback proof.
- `xdr.rs` is the only layer that translates policy mutations to Stellar XDR or
  evaluates transaction signatures.
- `transport.rs` defines `AccountTransport`, the bounded Horizon implementation,
  and a deterministic in-memory implementation.
- `executor.rs` owns offline handoff, submission, post-step verification,
  partial recovery, and the schema-1 checkpoint/approval contracts.
- `store.rs` owns bounded reads and atomic mode-600 writes.
- `commands/account.rs` contains Clap definitions and rendering only.

Domain code does not read the terminal, filesystem, config, or network. The
planner accepts complete evidence values and is deterministic except for the
display-only `created_at`; plan identity is deterministic. Network tests use
mockito, while execution tests use `InMemoryAccountTransport`.

## Invariants

Maintain these invariants when extending the feature:

1. A mutating step is authorized using the **before** state's high threshold.
2. Both before and after states must satisfy every threshold with declared
   available weight.
3. New authority is staged and verified before threshold increases or retirement.
4. Decreases and removals happen only after the exact next state is operable.
5. Every mutation has an inverse authorized by the resulting state.
6. Execution compares account/network, exact sequence, and an on-chain-only
   policy fingerprint before submission and after confirmation.
7. No code counts signature hints as approvals.
8. Persistent signature-bearing data is restricted and versioned.

The on-chain fingerprint intentionally excludes labels, availability channels,
ledger number, and sequence. Sequence is compared independently; metadata is
validated through challenge/checkpoint transitions.

## Threat model

The feature addresses accidental lockout, unavailable keys, malicious or stale
policy files, substituted signed envelopes, wrong-network endpoints, concurrent
account changes, incomplete multi-envelope execution, response-body secret
leakage, and over-permissive local artifacts. It does not protect an already
compromised threshold of signers, a dishonest device display, or an operator who
submits XDR outside the verified workflow.

## Persistent-format changes

Increase a schema constant only for an incompatible change. Add a migration in
`store.rs` before accepting an older version and add fixtures for the oldest
supported, current, and unknown-future versions. Never silently reinterpret a
future version. Integrity must be calculated over all execution-critical fields.

## Test matrix

Required local gates are:

```bash
cargo fmt --all --check
cargo deny --all-features check
cargo build --locked
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
./scripts/e2e-smoke.sh
```

Signer-rotation coverage must retain threshold boundaries, unavailable signers,
master removal, sponsorship, malformed Horizon data, identity mismatch, future
schemas, file modes, XDR body substitution, offline staging, resume binding,
concurrent sequence changes, final mismatch, and rollback ordering. Live Horizon
must remain opt-in.

## Operational incident procedure

Preserve the plan, checkpoint, approval bundle, handoff directory, and Horizon
transaction hashes. Do not overwrite the checkpoint. Fetch a fresh policy from
two independently configured endpoints, compare network identity and policy,
then prepare rollback for completed checkpoints. If endpoints disagree, stop
submissions until ledger history establishes the canonical state.
