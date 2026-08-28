# Safe account signer rotation

StarForge signer rotation migrates a Stellar account's on-chain signer entries,
master weight, and low/medium/high thresholds without making an intermediate
policy inoperable. It is separate from `wallet rotate`: local wallet records are
never changed automatically.

## Safety model

A policy identifies every signer by type, weight, availability channel, and
optional reserve sponsor. `software`, `hardware`, and `offline` signers count as
obtainable approvals; `unavailable` signers do not. The planner rejects a source
or target when available weight cannot satisfy any threshold.

The generated plan uses this order:

1. add new signers and increase useful weights;
2. prove control with signer-type verification challenges;
3. lower thresholds that must be relaxed;
4. apply final threshold increases only after new authority is usable;
5. reduce the master/old signer weights and remove old signers last;
6. fetch and compare the final on-chain policy.

Each state-changing step has one account sequence, an exact before/after policy
fingerprint, a deterministic approval summary, a checkpoint, and an inverse
mutation. Sponsored additions are encoded as
`beginSponsoringFutureReserves -> setOptions -> endSponsoringFutureReserves` and
name the sponsor approval separately. A sponsorship replacement is atomic in one
envelope.

Unknown future schemas are not assumed compatible. StarForge leaves them
untouched and tells the operator to update. A legacy policy lacking
`schema_version` is migrated in memory to policy schema 1; plan, checkpoint, and
approval formats require an exact supported version.

## Inspect current policy

Network inspection verifies the Horizon root `network_passphrase` before it
accepts account evidence. Calls are bounded (15 seconds by default, maximum 120).

```bash
starforge -q account signers inspect \
  --account G... \
  --network testnet \
  --availability signer-availability.json \
  --output current-policy.json \
  --format json
```

Horizon cannot know which keys are reachable locally, so an unannotated network
probe marks every signer `unavailable`. Supply a manifest:

```json
{
  "schema_version": 1,
  "account_id": "G...",
  "master_key": "hardware",
  "signers": [
    {"key": "G...", "availability": "offline", "label": "recovery"}
  ]
}
```

For an offline drill or CI, replace the network arguments with
`--input tests/fixtures/signer_rotation/current.json`. No command requires a live
network in CI.

## Declare and plan the target

Copy the current policy, edit signer entries, weights, sponsorship, master
weight, thresholds, and availability, then build the plan:

```bash
starforge -q account rotation plan \
  --current current-policy.json \
  --target target-policy.json \
  --output rotation-plan.json \
  --expires-after-ledgers 120 \
  --format json
```

Review all steps, approval selections, external sponsor approvals, final weight,
and `emergency_rollback`. The plan's ID derives from its inputs and options. Its
integrity hash covers the plan including all steps; hand editing is detected.
`--no-verification-challenges` is intended only when every introduced key was
proved through an independent procedure.

## Prepare, sign, and execute

First prepare every envelope and challenge without submitting:

```bash
starforge -q account rotation execute \
  --plan rotation-plan.json \
  --state rotation-state.json \
  --handoff-dir rotation-handoff \
  --format json
```

The handoff directory contains:

- an operation summary plus unsigned XDR for each mutating step;
- the exact UTF-8 proof challenge for each staged signer;
- expected sequence, transaction-body hash, fee, and approval channels;
- `approvals.template.json` for accumulated signed envelopes and challenge
  evidence.

All plan, checkpoint, approval, signature, and XDR files are mode `0600`; their
directories are mode `0700` on Unix. Software keys are read only from restricted
files. They are never accepted as command-line values or printed.

Software and Ledger/Trezor workflows can be combined with offline envelopes:

```bash
chmod 600 signer-key.txt
starforge -q account rotation resume \
  --plan rotation-plan.json \
  --state rotation-state.json \
  --handoff-dir rotation-handoff \
  --approvals approvals.json \
  --software-key-file signer-key.txt \
  --hardware-wallet ledger
```

StarForge validates the transaction body, then cryptographically verifies
ed25519, hash-x, preauthorized-transaction, and signed-payload authorization.
Signature hints alone never count as approval. Fully signed transactions remain
staged until the operator repeats the command with both `--submit` and `--yes`:

```bash
starforge -q account rotation resume \
  --plan rotation-plan.json \
  --state rotation-state.json \
  --handoff-dir rotation-handoff \
  --approvals approvals.json \
  --submit --yes
```

After every submission StarForge refetches the account. A changed sequence,
signer, weight, threshold, sponsorship, account identity, or network identity
stops execution before the next transaction. The persisted `next_step_index`
always equals the contiguous verified checkpoint count.

## Verification and automation

```bash
starforge -q account rotation verify \
  --plan rotation-plan.json \
  --format json
```

Stable JSON documents have `schema_version: 1`. Successful inspection, plan,
staging, and verification exit 0. Malformed/future data, safety rejection,
network mismatch, concurrent change, expired plan, invalid approval, or target
mismatch exit 1. `awaiting_approval` is a successful, resumable staging state and
therefore exits 0.

## Recovery

If a submission fails after any verified mutation, use
`--rollback-on-failure`. StarForge sets the checkpoint to `rollback_required`
and writes inverse envelopes for completed mutating steps only. They are ordered
from newest to oldest.

To prepare the same recovery explicitly:

```bash
starforge -q account rotation resume \
  --plan rotation-plan.json \
  --state rotation-state.json \
  --handoff-dir rotation-handoff \
  --rollback
```

Before signing rollback XDR, inspect the live account again, verify the sequence
and operations, and collect fresh high-threshold and sponsor approvals. If the
account changed concurrently, generate a fresh plan from new evidence rather
than editing fingerprints or sequences.

## Security and troubleshooting

- Store plan and approval media as sensitive: account relationships, signatures,
  and timing can reveal operational controls even without secret seeds.
- Horizon errors retain status/result codes but discard response bodies. URLs
  have credentials, query strings, and fragments removed from diagnostics.
- A network identity mismatch usually means the endpoint belongs to another
  Stellar network. Correct configuration before continuing.
- `insufficient_available_weight` means the declared reachable signers cannot
  authorize that threshold. Correct availability or the target policy.
- An expired plan or sequence mismatch means the evidence is stale. Reinspect
  and replan.
- Hardware builds require `--features hardware-wallet`. Keep device firmware
  current, compare the device address with the approval summary, and review each
  operation on an independent display.
