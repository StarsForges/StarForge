# Multisig Ceremonies

`starforge multisig ceremony` coordinates an M-of-N Stellar transaction across
independent signer machines using a single portable file — no shared process
state, no server, no single machine that ever holds enough signing authority
to submit alone.

This builds on the account-level primitives in `starforge wallet multisig`
(setting up on-chain signer weights and thresholds via `SetOptions`). Ceremonies
are for the *transaction* side: getting a specific payment or operation signed
by enough of those signers before it's submitted.

## Why a ceremony file

A traditional multisig flow passes a raw XDR blob between signers and hopes
everyone applies their signature to the same, unmodified transaction. A
ceremony file instead bundles:

- the unsigned transaction envelope XDR
- a **manifest**: source account, required signers, threshold, network, and
  expiry (transaction time bounds)
- a **signature log**: who signed, when, and whether via a hardware wallet
- two integrity hashes (see [Tamper detection](#tamper-detection)) that let
  every signer verify the file hasn't been altered since the ceremony started

The file is plain JSON (base64 XDR embedded as a string), so it's diffable and
safe to pass around a shared repository, attach to a pull request for
auditability, transfer via USB drive, or export/import as a QR code for fully
air-gapped signers.

## Walkthrough: a 3-of-4 treasury payout

Four signers hold keys to a treasury account: `alice`, `bob`, `carol`, and
`dave`. Any 3 of them must sign before a payout can go out. `bob` keeps his
key on a Ledger device that never touches the network.

### 1. Coordinator starts the ceremony

Whoever is coordinating the payout (any one signer, or an ops account) needs
network access once, to fetch the treasury account's current sequence number
and build the unsigned transaction:

```bash
starforge multisig ceremony start \
  --source GTREASURY... \
  --op '{"type":"payment","to":"GVENDOR...","amount":"5000","asset":"XLM"}' \
  --threshold 3 \
  --signers GALICE...,GBOB...,GCAROL...,GDAVE... \
  --network mainnet \
  --expires-in-minutes 1440 \
  --output payout.ceremony
```

`--op` accepts inline JSON or a path to a JSON file with the same shape
(currently `{"type":"payment","to":...,"amount":...,"asset":...}`; `asset`
defaults to `XLM`, or use `CODE:ISSUER`). `--expires-in-minutes` sets the
transaction's time bounds — pass `0` for no expiry.

This writes `payout.ceremony`, which is safe to commit to a private repo, post
in a PR, or copy to a USB drive. It contains no secrets.

### 2. Each signer signs independently

Every signer gets a copy of `payout.ceremony` — over the network, via a shared
repo, or by sneakernet to an air-gapped machine — and runs `sign` locally.
**No network access is required to sign.**

```bash
# alice, on her own machine
starforge multisig ceremony sign --input payout.ceremony --wallet alice --output alice.ceremony

# carol, on a separate machine
starforge multisig ceremony sign --input payout.ceremony --wallet carol --output carol.ceremony

# bob, using a connected Ledger instead of a local secret key
starforge multisig ceremony sign --input payout.ceremony --wallet bob --hardware ledger --output bob.ceremony
```

Each invocation is stateless: it re-derives everything it needs from the input
file, so it doesn't matter whether signers run this sequentially against one
shared file or in parallel against their own copies (see
[Merging independent copies](#merging-independent-copies-air-gapped--usb-workflow)
below for combining the latter).

`--wallet <name>` identifies a locally registered wallet (`starforge wallet
create`/`import`). With `--hardware <ledger|trezor>`, the signature comes from
the connected device instead of a stored secret key; the device's own derived
address is what gets checked against the ceremony's required signer list.

### 3. Check status before submitting

Anyone with a copy of the file — including someone with no signing authority
at all — can check progress:

```bash
starforge multisig ceremony status --input payout.ceremony
```

```
  Signatures           2 of 4 required (threshold 3)
    ✓ signed  GALICE...
    … waiting  GBOB...
    ✓ signed  GCAROL...
    … waiting  GDAVE...

⚠ Waiting on 1 more signature(s)
  Expires At           2026-08-01T12:00:00+00:00
  Time Remaining       18h 42m 10s
```

### 4. Submit once the threshold is met

```bash
starforge multisig ceremony submit --input payout.ceremony
```

`submit` re-verifies everything before touching the network:

- the manifest and transaction body haven't been tampered with
- at least `threshold` signatures are present, all from signers in the
  manifest's required-signer list
- the transaction hasn't expired

Only then does it assemble the final envelope and submit it to Horizon. If any
check fails, nothing is submitted and the error explains exactly what's
missing (e.g. `Not enough signatures to submit: 2 of 4 required signatures
collected (threshold 3). Outstanding signers: GDAVE...`).

## Merging independent copies (air-gapped / USB workflow)

For fully air-gapped signers, the coordinator copies `payout.ceremony` onto a
USB drive (or exports it as a QR code) for each signer, who signs on their
offline machine and hands back a signed copy. Because each `sign` invocation
only *adds* one signature to the file it's given, merge multiple independently
signed copies by re-applying each signer's step against a single accumulating
file rather than needing them all signed in one physical file at once:

```bash
# Coordinator, after collecting alice.ceremony, bob.ceremony, carol.ceremony
# back from USB transfers:
cp payout.ceremony merged.ceremony

# For each returned copy, the signer's own hardware/wallet re-signs the
# accumulating file (fast — signing an already-signed transaction with the
# same key is a no-op) or, if you trust the returned files directly, take the
# transaction_envelope_xdr field's signatures from each copy and append them
# in sequence with `ceremony sign` runs against `merged.ceremony`.
```

In practice, the simplest reliable pattern is to have each signer's `sign`
step performed directly against a copy of the file that already carries the
prior signers' signatures — pass the ceremony file along a chain (alice →
carol → bob) rather than fanning it out and merging independently-signed
forks. `ceremony sign`'s idempotent, stateless design supports both: signing
twice with the same key is a safe no-op either way (see
[Duplicate signers](#duplicate-signers)).

## Tamper detection

Every `sign`, `status`, and `submit` call recomputes two hashes from the
current file contents and compares them against the values stored at
`ceremony start`:

- **`tx_body_hash`** — a SHA-256 of the unsigned transaction body (source
  account, sequence number, operations, memo, and time bounds — everything
  except signatures). If anyone edits the operation, amount, destination, or
  sequence number after the ceremony started, this hash no longer matches and
  every subsequent `sign`/`status`/`submit` is refused.
- **`manifest_hash`** — a SHA-256 over the required signer set, threshold,
  network, and expiry. This catches tampering with the ceremony's *rules*
  (e.g. someone lowering the threshold from 3 to 1, or removing a required
  signer) independently of the transaction body.

```
✗ Error: Transaction integrity check failed: the unsigned transaction body
(source, sequence, operations, or preconditions) was altered after the
ceremony started. Refusing to sign or submit a tampered ceremony file.
```

`submit` additionally cross-checks the signature log against the raw XDR
envelope's actual signature count and rejects any signature attributed to a
signer outside the manifest's required-signer list — so a hand-edited
`signature_log` can't claim a threshold that isn't backed by real signatures.

These are integrity checks, not a substitute for reviewing the transaction.
Each signer should still confirm the operation summary printed by `sign`
matches what they expect before approving on their device or entering a
passphrase.

## Duplicate signers

Signing with the same key twice is a no-op: `sign` reports "had already
signed this ceremony; no change made" and the signature log and collected
count are unaffected. This makes it safe to re-run `sign` defensively (e.g.
after an interrupted USB transfer) without double-counting.

## Expiry

`--expires-in-minutes` sets the transaction's time bounds (`min_time: 0`,
`max_time: now + N minutes`) at `ceremony start`. Once that window passes,
`status` reports the ceremony as expired and `submit` refuses to send it —
start a new ceremony instead of trying to extend the deadline of an existing
one (extending it would itself be a transaction-body change, caught by tamper
detection above).
