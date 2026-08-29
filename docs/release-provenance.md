# Reproducible Releases, SBOM, Signing, and Provenance

`starforge release` gives StarForge maintainers a local, offline pipeline
from a built binary to a signed, verifiable release: normalized archives,
a versioned manifest, a software bill of materials, and a SLSA-shaped
provenance statement — all producible and checkable without a network
connection.

> **Publishing is still a manual, maintainer-controlled action.** Nothing
> in this command family uploads, tags, pushes, or talks to any external
> service. Every subcommand only reads and writes local files under
> `--dir`/`--out`/`~/.starforge/release/`. Uploading the resulting
> directory to a GitHub Release (or anywhere else) is a separate, deliberate
> step you take afterward.

## Commands

### `starforge release prepare`

Builds (or reuses) the binary for one or more targets, packages each into a
deterministic zip archive, and stages the result:

```bash
# Reuse an already-built host binary (what CI/CD and this repo's own
# CI use, since cross-toolchains for every target aren't installed here):
starforge release prepare --version 1.2.0 --target native --skip-build \
  --source-date-epoch "$(git log -1 --format=%ct)"

# Cross-compile for a specific target (requires that target's Rust
# toolchain/linker to already be installed):
starforge release prepare --version 1.2.0 --target x86_64-pc-windows-msvc
```

- `--target` is repeatable; omit it to build the `native` pseudo-target only.
- `--skip-build` reuses whatever is already at `target/<target-or-native>/release/<binary-name>` instead of invoking `cargo build`. This is the path used in CI and in this repo's own tests, since cross-compilation toolchains for every supported target aren't installed everywhere `cargo test` runs.
- `--source-date-epoch <unix seconds>` pins every archive entry's timestamp. **Omitting it is allowed but the release is then not marked reproducible** — see [Reproducibility](#reproducibility) below. `git log -1 --format=%ct` is a good source: the last commit's timestamp.
- Staging is rollback-safe: `prepare` writes into a temporary directory and only renames it into place once every requested target has built and archived successfully. A failure partway through (a missing cross toolchain, a build error) leaves nothing behind for `release manifest` to accidentally pick up.
- Re-running `prepare` for a version that's already staged fails unless `--force` is passed, so a stray re-run can't silently replace artifacts a maintainer already started signing.

### `starforge release manifest`

Reads back what `prepare` staged and writes the versioned
`release-manifest.json`:

```bash
starforge release manifest --version 1.2.0
```

Records: app name, version, git commit (best-effort — `None` if not run
inside a git checkout), the pinned toolchain channel from
`rust-toolchain.toml`, and one entry per artifact (target, file name,
size, SHA-256). The manifest is schema-versioned the same way
`~/.starforge/compliance/profile.toml` is: an old manifest read by a newer
`starforge` migrates forward automatically, and a manifest from a *newer*
`starforge` than the one running fails loudly ("version drift") instead of
being silently misread.

### `starforge release sbom`

Generates a CycloneDX 1.5 JSON SBOM purely from `Cargo.lock` and
`Cargo.toml` — no `cargo metadata` subprocess, no network:

```bash
starforge release sbom --out sbom.json --include-assets templates
```

- One `library` component per `[[package]]` in `Cargo.lock` (excluding the
  root package itself), with a `pkg:cargo/<name>@<version>` purl and, when
  present, the registry checksum as a `SHA-256` hash.
- `[features]` names from `Cargo.toml` are recorded as `cargo:feature`
  metadata properties — the declared surface, not which features happen to
  be active in a given build (SBOM generation can't see build flags).
- `--include-assets <dir>` (repeatable) adds one aggregate `file` component
  per bundled-asset directory (e.g. `templates/`), hashed by concatenating
  every file's relative path and content digest in sorted order — the same
  tree always hashes the same way regardless of file-system iteration order.
- **SPDX output is not implemented.** CycloneDX was chosen as the initial
  format; adding an SPDX writer is a tracked follow-up (see [Known
  limitations](#known-limitations)).

### `starforge release attest`

Signs the manifest and SBOM and writes a provenance statement:

```bash
starforge release attest --dir ~/.starforge/release/staging/1.2.0 \
  --signing-key ~/.starforge/release-signing.key
```

- Reads the signing key from `STARFORGE_RELEASE_SIGNING_KEY` (base64
  Ed25519 seed) if set, otherwise from `--signing-key <file>`.
- `--generate-key-if-missing` creates a new key at `--signing-key` the
  first time it's used. **Back that file up somewhere durable and out of
  version control** — losing it means future releases can no longer be
  verified against the same public key as past ones, and anyone who
  obtains it can forge signatures for releases claiming to be from you.
- Writes, alongside the existing manifest/SBOM: `provenance.json`
  ([in-toto Statement v1](https://in-toto.io/Statement/v1) wrapping a
  [SLSA Provenance v1](https://slsa.dev/spec/v1.0/provenance) predicate),
  `release-manifest.json.sig`, `sbom.json.sig`, `provenance.json.sig`
  (base64 Ed25519 signatures), and `release.pub` (the base64 public key).
- The provenance statement's `reproducible` metadata field is `true` only
  when the manifest recorded a `source_date_epoch` — i.e. only when
  `prepare` was run with `--source-date-epoch`.
- Signatures are detached base64, not a full DSSE envelope — sufficient for
  `starforge release verify`'s "was this signed by the maintainer key"
  check, but not directly interoperable with external DSSE/Sigstore
  tooling. See [Known limitations](#known-limitations).

### `starforge release verify`

Runs every check against a staged or downloaded release directory, entirely
offline:

```bash
starforge release verify --dir ./starforge-1.2.0 --format json
```

Checks performed (each recorded independently, so one failure doesn't hide
the rest of the report):

| Check | Failure mode it catches |
|---|---|
| `manifest-schema` | Malformed JSON, or a manifest from a newer `starforge` than the one verifying ("version drift") |
| `manifest-internal-consistency` | Duplicate targets, malformed checksums, artifact naming violations |
| `public-key-present` | No `--pubkey` and no `release.pub` in `--dir` |
| `manifest-signature` | Manifest bytes don't match `release-manifest.json.sig` under the resolved public key |
| `artifact[<target>]-checksum` | Artifact file missing, or its bytes don't hash to what the manifest recorded (tampering) |
| `artifact[<target>]-naming` | Artifact file name doesn't match `<name>-<version>-<target>.<ext>` |
| `sbom-parses` | SBOM missing or malformed |
| `sbom-signature` | SBOM bytes don't match `sbom.json.sig` |
| `sbom-dependency-completeness` (only with `--check-lock <Cargo.lock>`) | A dependency present in `Cargo.lock` has no matching SBOM component (stale/hand-edited SBOM) |
| `provenance-parses` | Provenance statement missing or malformed |
| `provenance-signature` | Provenance bytes don't match `provenance.json.sig` |
| `provenance-subjects-match-manifest` | Provenance statement doesn't cover every manifest artifact at its recorded digest |

Exit code is `0` when every check passes, `1` otherwise — safe to use
directly in an installer script:

```bash
if ! starforge release verify --dir ./starforge-1.2.0; then
  echo "release verification failed, refusing to install" >&2
  exit 1
fi
```

## Reproducibility

A release archive is only as reproducible as the inputs pinned into it.
`starforge release` pins archive entry order, permissions, and timestamps
given a `--source-date-epoch`; it does **not** by itself make `cargo build`
byte-reproducible (that depends on your toolchain, build flags, and
embedded paths). `manifest.source_date_epoch` and
`provenance.predicate.metadata.reproducible` are the honest signal: `null`
/ `false` unless a maintainer explicitly pinned the epoch, never assumed.

To confirm two independent builds actually produced the same archive:

```bash
sha256sum starforge-1.2.0-x86_64-unknown-linux-gnu.zip
# compare against the value recorded in release-manifest.json / SHA256SUMS
```

## Threat model

**In scope:**
- An attacker who can modify a release artifact in transit or at rest (a
  compromised mirror, a tampered download): caught by `artifact[...]-checksum`
  and `manifest-signature` in `release verify`.
- A stale or hand-edited SBOM that no longer matches `Cargo.lock`: caught by
  `--check-lock`.
- A manifest written by a future, incompatible `starforge` version being
  misread by an older one: caught by the schema-version migration check
  (fails closed rather than silently misinterpreting new fields).
- Accidental key leakage via loose file permissions: signing keys are
  written with `0600` permissions on Unix and are never printed to stdout
  in full (only the derived public key is).

**Out of scope (by design, documented rather than silently assumed away):**
- Compromise of the signing key itself. `starforge release` authenticates
  "signed by whoever holds this key," not "signed by a trustworthy
  maintainer" — key custody (hardware token, offline storage, access
  control) is the maintainer's responsibility and outside this tool.
- Supply-chain compromise *upstream* of `Cargo.lock` (a malicious crate
  version already recorded in the lockfile). The SBOM inventories what's
  pinned; it doesn't audit whether what's pinned is trustworthy.
- Reproducibility of the Rust compiler/linker output itself (debug info
  embedding absolute paths, non-deterministic codegen in some toolchains)
  — only archive-level normalization is in scope here.

## Recovery / troubleshooting

- **"expected built binary at ... but it does not exist"** — `--skip-build`
  was passed but nothing has been built yet for that target. Run
  `cargo build --release [--target <triple>]` first, or drop `--skip-build`
  to let `prepare` invoke it.
- **"a staged release already exists at ... (pass --force to replace it)"**
  — `prepare` refuses to silently overwrite a previous staging run for the
  same version. Pass `--force` only when you intend to discard the prior
  staged artifacts (e.g. after fixing a build issue).
- **"No migration path from release manifest schema version N"** — the
  manifest was written by a `starforge` release newer than the one running
  `verify`/`manifest`. Upgrade `starforge`.
- **"no signing key available"** — set `STARFORGE_RELEASE_SIGNING_KEY` or
  pass `--signing-key <file>` to `release attest`; add
  `--generate-key-if-missing` to create one on first use.
- **A verification check fails after a legitimate re-release** — re-run the
  full `prepare` → `manifest` → `sbom` → `attest` chain for the new version
  rather than hand-editing files in an existing staged directory; the
  signatures cover exact byte content, so any manual edit invalidates them.

## Known limitations

- SPDX SBOM output is not implemented; only CycloneDX 1.5 JSON is produced
  today.
- Provenance/manifest/SBOM signatures are detached base64 Ed25519, not a
  DSSE envelope — sufficient for this tool's own verification, not a drop-in
  for external Sigstore/DSSE-consuming tooling.
- `release prepare` cross-compiles by shelling out to `cargo build
  --target`; it does not install missing targets or linkers for you.
- Byte-for-byte reproducibility of the *binary itself* (as opposed to the
  archive wrapping it) depends on toolchain and build-flag determinism
  outside this tool's control.
