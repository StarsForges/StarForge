# StarForge

> The Stellar & Soroban developer productivity CLI — one Rust binary covering wallets, contract scaffolding and deployment, AI-assisted analysis, compliance, protocol-compatibility auditing, and release engineering.

![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)
![Language: Rust](https://img.shields.io/badge/Language-Rust%201.89%2B-orange.svg)
![Network: Stellar](https://img.shields.io/badge/Network-Stellar%20%26%20Soroban-blue.svg)
![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)
[![CI](https://github.com/StarsForges/StarForge/actions/workflows/ci.yml/badge.svg)](https://github.com/StarsForges/StarForge/actions/workflows/ci.yml)

---

## Overview

**StarForge** is a free, open-source command-line toolkit for developers building on the Stellar network. Think of it as the "Hardhat / Foundry" experience for the Stellar ecosystem: one fast, ergonomic Rust binary that brings together wallet management, project scaffolding, contract deployment, and a growing suite of AI-assisted developer and compliance tooling.

The CLI currently ships **39 top-level command groups** (run `starforge commands` or `starforge --help` for the live list), organized around a few themes:

- **Core Stellar workflows** — wallets, multisig, batch payments, networks, transactions.
- **Soroban contract development** — scaffolding, deployment, inspection, testing, gas/lint analysis, upgrade safety.
- **AI-assisted developer suite** — a context-aware assistant, cost estimation, performance profiling, anomaly detection, natural-language contract queries, and automated documentation generation — every AI-backed feature ships with a deterministic, offline fallback.
- **Governance & risk** — regulatory compliance checks, protocol/RPC compatibility auditing, transaction fee & resource budgets.
- **Ecosystem interoperability** — bidirectional sync with the official Stellar CLI, SEP-41 token administration, a rules-based notification router, and a native/WASM plugin system.
- **Maintainer/release tooling** — reproducible, signed release builds with SBOM and provenance for StarForge's own binaries.

StarForge is actively maintained and welcomes community contributions — see [Contributing](#contributing).

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Complete Command Reference](#complete-command-reference)
- [Feature Guides](#feature-guides)
  - [Wallets & Keys](#wallets--keys)
  - [Account Signer Rotation](#account-signer-rotation)
  - [Multisig](#multisig)
  - [Batch Payments](#batch-payments-airdrops--contributor-payouts)
  - [Networks & Local Devnet](#networks--local-devnet)
  - [Project Scaffolding & Templates](#project-scaffolding--templates)
  - [Contract Deployment & Inspection](#contract-deployment--inspection)
  - [Contract Testing, Gas & Linting](#contract-testing-gas--linting)
  - [Upgrade Safety Analysis](#upgrade-safety-analysis)
  - [Interactive Shell, Monitoring & Tutorials](#interactive-shell-monitoring--tutorials)
  - [AI-Assisted Developer Suite](#ai-assisted-developer-suite)
  - [Natural-Language Soroban Queries](#natural-language-soroban-queries)
  - [Cost Estimation](#cost-estimation)
  - [Performance Profiling](#performance-profiling)
  - [Real-Time Anomaly Detection](#real-time-anomaly-detection)
  - [Automated Documentation Generation](#automated-documentation-generation)
  - [Transaction Fee & Resource Budgets](#transaction-fee--resource-budgets)
  - [Regulatory Compliance](#regulatory-compliance)
  - [Protocol & RPC Compatibility Auditing](#protocol--rpc-compatibility-auditing)
  - [Stellar CLI Interoperability](#stellar-cli-interoperability)
  - [SEP-41 Token Administration](#sep-41-token-administration)
  - [Notification Router](#notification-router)
  - [Plugin System](#plugin-system)
  - [Raw Transactions](#raw-transactions)
  - [Diagnostics, Config, Info & Completions](#diagnostics-config-info--completions)
- [Configuration File](#configuration-file)
- [Security](#security)
- [Privacy & Telemetry](#privacy--telemetry)
- [Project Structure](#project-structure)
- [Maintainer Release Tooling](#maintainer-release-tooling)
- [Development & Contributing](#development--contributing)
- [License](#license)

---

## Installation

### Prerequisites

- **Rust 1.89.0** or later — the toolchain version is pinned in [`rust-toolchain.toml`](rust-toolchain.toml) with the `clippy` and `rustfmt` components. Install via [rustup](https://rustup.rs).
- **Linux only:** `libudev-dev` (needed by the optional `hardware-wallet` feature, e.g. `sudo apt-get install libudev-dev`).

### Build from source (recommended)

StarForge has not yet published a tagged binary release, so building from source is currently the most reliable installation path:

```bash
git clone https://github.com/StarsForges/StarForge.git
cd StarForge
cargo build --release

# Move the binary onto your PATH
cp target/release/starforge ~/.local/bin/
# or on macOS:
cp target/release/starforge /usr/local/bin/
```

To build with hardware wallet support (Ledger/Trezor):

```bash
cargo build --release --features hardware-wallet
```

### Pre-built binaries (once a release is tagged)

A release pipeline ([`.github/workflows/release.yml`](.github/workflows/release.yml)) is already wired up to build and publish signed archives for `linux-x86_64`, `linux-aarch64`, `macos-aarch64`, and `windows-x86_64` whenever a `v*` tag is pushed, along with `SHA256SUMS.txt` checksums and an auto-generated Homebrew formula. Once the first tag is cut, the standard install path will be:

```bash
curl -sL https://raw.githubusercontent.com/StarsForges/StarForge/main/install.sh | bash
```

```bash
brew install StarsForges/starforge/starforge
```

Until then, [`install.sh`](install.sh) and [`packaging/homebrew/starforge.rb`](packaging/homebrew/starforge.rb) are provided as templates for that first release.

### Docker

A dev-oriented Docker Compose stack spins up a local Stellar/Soroban network (`stellar/quickstart`) alongside a StarForge dev container with cargo caches mounted for fast rebuilds:

```bash
docker-compose up -d stellar-testnet     # local Stellar + Soroban RPC node
docker-compose run --rm starforge starforge deploy --wasm ./token.wasm --network docker-testnet
# live code editing:
docker-compose run --rm starforge cargo run -- <command>
```

The standalone [`Dockerfile`](Dockerfile) builds a minimal runtime image (multi-stage, `debian:bookworm-slim`) with the `starforge` binary and the official Stellar CLI pre-installed, useful for CI or one-off runs:

```bash
docker build -t starforge .
docker run --rm starforge --version
```

### Verify installation

```bash
starforge --version
# starforge 0.1.0

starforge info
starforge commands   # full command tree with one-line descriptions
```

### Shell completions

```bash
# Bash — add to ~/.bashrc
source <(starforge completions bash)

# Zsh — add to ~/.zshrc
source <(starforge completions zsh)

# Fish
starforge completions fish > ~/.config/fish/completions/starforge.fish
```

---

## Quick Start

```bash
# 1. Check your environment
starforge info

# 2. Create and fund a testnet wallet
starforge wallet create alice --fund

# 3. Scaffold a Soroban contract
starforge new contract my-token --template token

# 4. Build it (standard Soroban/Rust toolchain, not a StarForge step)
cd my-token && cargo build --target wasm32-unknown-unknown --release

# 5. Deploy it
starforge deploy \
  --wasm target/wasm32-unknown-unknown/release/my_token.wasm \
  --network testnet \
  --wallet alice

# 6. Inspect the deployed contract
starforge contract inspect <CONTRACT_ID>
```

---

## Complete Command Reference

Run `starforge <command> --help` for full flag documentation on any entry, or `starforge commands` for the CLI's own live summary.

| Command | Purpose |
|---|---|
| `wallet` | Create, list, fund, encrypt, rotate, export/import, and hardware-sign with local keypairs |
| `account` | Inspect on-chain signer policy and run safe, resumable signer-rotation migrations |
| `multisig` | Coordinate M-of-N multisig signing ceremonies as a portable, air-gap-friendly file |
| `batch` | Resumable CSV payouts (airdrops, contributor payments) with checkpointing |
| `tx` | Send payments, submit multi-op batches, view history, and check recommended fees |
| `network` | View, switch, add, remove, rename, and test Stellar network endpoints |
| `node` | Start a local Soroban devnet via Docker (`stellar/quickstart`) |
| `new` | Scaffold a Soroban contract or Stellar dApp (Vite + React) frontend |
| `template` | Search, install, publish, and manage community contract templates |
| `contract` | Invoke, inspect, upload, and generate typed bindings for deployed contracts |
| `deploy` | Validate, size-check, and deploy a compiled `.wasm` file |
| `inspect` | Deep contract storage inspection (state, individual keys, paginated dumps) |
| `upgrade` | Compare WASMs for breaking changes, and propose/approve/execute/roll back upgrades |
| `test` | Run a compiled contract's test suite with coverage and fuzzing support |
| `gas` | Analyze, optimize, and diff gas/CPU cost between WASM builds |
| `lint` | Static analysis and size-budget checks on compiled WASM |
| `shell` | Interactive REPL for local Soroban contract testing |
| `monitor` | Live monitoring of contract events or wallet balance thresholds |
| `tutorial` | Guided, interactive CLI tutorials |
| `benchmark` | Micro-benchmark WASM processing and CLI hot paths |
| `ai` | Context-aware assistant, code generation/analysis, security training, and impact analysis |
| `query` | Natural-language, read-only questions about public Soroban contract data |
| `cost` | AI-assisted fee/resource cost estimation with historical regression tracking |
| `profile` | AI-assisted performance profiling, baselines, and regression gating |
| `anomaly` | Real-time anomaly detection over a contract's live event/fee/error baseline |
| `docs` | Generate and validate deterministic Markdown/JSON docs from compiled contracts |
| `budget` | Enforceable transaction fee and Soroban resource ceilings, checked pre-signing |
| `compliance` | Deterministic regulatory-compliance checks, evidence, and waivers |
| `compatibility` | Audit Stellar protocol, Soroban RPC, XDR, and project compatibility |
| `interop` | Bidirectional sync with the official Stellar CLI's config and identities |
| `token` | SEP-41-style Soroban token inspection, transfers, mint/burn, and admin ops |
| `notify` | Rules-based notification router with dedup, retries, and delivery guarantees |
| `plugin` | Install, verify, audit, update, and run third-party native/WASM plugins |
| `release` | Reproducible builds, SBOM, signing, and provenance for StarForge's own releases |
| `diagnostics` | Connectivity diagnostics for attached Ledger/Trezor hardware wallets |
| `config` | Manage global configuration, schema migrations, and plugin trust |
| `telemetry` | Inspect and control local-only anonymous usage telemetry |
| `completions` | Generate Bash/Zsh/Fish shell completions |
| `info` | Show StarForge config and environment info |
| `commands` | Print the full command tree |

Installed plugins register additional top-level commands (e.g. `starforge <plugin-name> ...`) — see [Plugin System](#plugin-system).

---

## Feature Guides

### Wallets & Keys

Create and manage Stellar ed25519 keypairs locally, with proper Stellar strkey encoding (`G...` public, `S...` secret), optional AES-256-GCM encryption at rest, BIP39 mnemonic generation/import (SEP-0005 derivation), and hardware wallet (Ledger/Trezor) support.

```bash
# Create a wallet, funded immediately on testnet
starforge wallet create alice --fund

# Encrypted storage (prompts for a passphrase; --strict rejects weak passphrases)
starforge wallet create alice --encrypt --strict

# Generate from a fresh BIP39 recovery phrase
starforge wallet create alice --mnemonic --words 24

# List / show / reveal / fund / remove / rename
starforge wallet list
starforge wallet show alice
starforge wallet show alice --reveal
starforge wallet fund alice
starforge wallet remove alice
starforge wallet rename alice primary

# Rotate a wallet in place (new on-chain keypair, same local name)
starforge wallet rotate alice --fund --backup alice-before-rotation.json

# Merge (close) an account into another, encrypted export/import backups
starforge wallet merge --from old-wallet --to alice --yes
starforge wallet export --all --output backup.json
starforge wallet import --file backup.json

# Hardware wallets
starforge wallet connect ledger
starforge wallet hw-address ledger
starforge wallet sign alice "message to sign"
```

> Rotation keeps the same local wallet name in `~/.starforge/config.toml`, but generates a brand-new on-chain keypair — any external references to the previous public key need updating separately.

### Account Signer Rotation

Inspect on-chain signer policies and generate authorization-preserving, resumable, multi-envelope migrations — with hardware/offline signing handoff, sponsorship, exact on-chain verification, and emergency rollback.

```bash
starforge account signers inspect --account GABC...
starforge account rotation plan --account GABC... --target target.json
starforge account rotation execute --plan plan.json
starforge account rotation resume --plan plan.json
starforge account rotation verify --account GABC... --target target.json
```

See the [account signer rotation guide](docs/account-signer-rotation.md) for the full threshold-safety model.

### Multisig

StarForge ships **two** complementary multisig workflows:

**1. `wallet multisig` — on-chain signer setup for accounts you already control locally:**

```bash
starforge wallet multisig create treasury --threshold 2 --signers alice,bob,charlie
starforge wallet multisig sign treasury --transaction tx.xdr --network testnet
starforge wallet multisig submit treasury --transaction tx.xdr
starforge wallet multisig list
```

**2. `multisig ceremony` — a portable, single-file M-of-N signing session**, so no one machine ever needs both network access *and* enough signing authority to submit alone (great for air-gapped or hardware-distributed treasuries):

```bash
# Coordinator: build the unsigned transaction + manifest into one file
starforge multisig ceremony start \
  --source GTREASURY... \
  --op '{"type":"payment","to":"GDEST...","amount":"5000"}' \
  --threshold 3 --signers GALICE...,GBOB...,GCAROL...,GDAVE... \
  --network mainnet --output payout.ceremony

# Each signer (can be on a separate, air-gapped machine): copy the file
# (USB drive, QR export/import, or a shared repo/PR) and run
starforge multisig ceremony sign --input payout.ceremony --wallet alice
starforge multisig ceremony sign --input payout.ceremony --wallet bob --hardware ledger

# Anyone: check progress before submitting
starforge multisig ceremony status --input payout.ceremony

# Once the threshold is met: assemble and submit
starforge multisig ceremony submit --input payout.ceremony
```

See [docs/multisig-ceremony.md](docs/multisig-ceremony.md) for the full multi-machine walkthrough, including the air-gapped/USB-transfer workflow and tamper-detection model.

### Batch Payments (airdrops & contributor payouts)

Pay hundreds or thousands of recipients from a CSV file with checkpointing, resume support, and fee-bump retry.

**CSV format** (`destination,amount,asset[,memo]`):

```csv
destination,amount,asset,memo
GABC...XYZ,10,XLM,contributor-q1
GDEF...UVW,25,USDC:GISSUER...,payout
```

```bash
# Validate recipients and show total cost without submitting anything
starforge batch pay --file recipients.csv --wallet payer --network testnet --dry-run

# Execute the payout (writes recipients.csv.batch-state.json as it progresses)
starforge batch pay --file recipients.csv --wallet payer --network testnet

# Check progress / resume after interruption
starforge batch status --file recipients.csv
starforge batch resume --file recipients.csv --wallet payer --network testnet
```

If the process is killed mid-run, re-run the same `batch pay` command or use `batch resume` — already-confirmed rows are never resubmitted; the checkpoint records each row as `pending`, `submitted`, `confirmed`, or `failed`.

### Networks & Local Devnet

```bash
starforge network show
starforge network switch mainnet
starforge network add mynet --horizon-url https://my-horizon.example.com --soroban-rpc-url https://my-soroban.example.com
starforge network test              # tests the active network
starforge network test mainnet
starforge network rename mynet staging
starforge network remove staging
```

Spin up a fully local Soroban RPC node via Docker (`stellar/quickstart`) instead of relying on the public testnet:

```bash
starforge node start --port 8000
starforge shell --network docker-testnet --contract ./my_contract.wasm
```

### Project Scaffolding & Templates

```bash
# Built-in templates: hello-world, token, nft, voting
starforge new contract my-contract
starforge new contract my-contract --interactive
starforge new contract my-token --template token

# Marketplace templates
starforge template search defi
starforge new contract my-dex --template uniswap-v2 --from marketplace

# Stellar dApp frontend (Vite + React)
starforge new dapp my-dapp
```

Manage the local template marketplace:

```bash
starforge template init                     # seed with example templates
starforge template list
starforge template show uniswap-v2
starforge template search --tags dex,amm --verified
starforge template import ./my-template --name my-template
starforge template publish ./my-template --name my-template --author "Your Name" --tags "defi,custom"
starforge template update
starforge template remove my-template
```

| Built-in template | Description |
|---|---|
| `hello-world` | Basic contract with a `hello(to)` function — a great starting point |
| `token` | Fungible token scaffold: `initialize`, `mint`, `balance`, `transfer` |
| `nft` | Non-fungible token scaffold: `mint`, `owner_of`, `transfer` |
| `voting` | Proposal/voting contract: `create_proposal`, `vote`, `results` |

| Marketplace template (seeded registry) | Tags |
|---|---|
| `uniswap-v2` | defi, dex, amm, swap |
| `lending-pool` | defi, lending, borrowing |
| `governance` | dao, governance, voting |
| `multisig-wallet` | wallet, multisig, security |
| `sep-41-token` | token, sep-41, stellar-asset, standard |
| `sep-10-auth` | auth, sep-10, authentication, security |
| `escrow` | defi, escrow, payments, marketplace |
| `dao-governance` | dao, governance, voting |
| `multisig-vault` | wallet, multisig, security, treasury |

All templates include a working test suite and their own README with build/deploy instructions.

### Contract Deployment & Inspection

```bash
# Deploy a compiled contract
starforge deploy --wasm target/wasm32-unknown-unknown/release/my_contract.wasm

# Deploy to mainnet with a specific wallet, skipping the confirmation prompt (CI)
starforge deploy --wasm ./my_contract.wasm --network mainnet --wallet deployer --yes

# Optimize before deployment
starforge deploy --wasm ./my_contract.wasm --optimize

# Invoke a deployed function
starforge contract invoke <CONTRACT_ID> transfer --arg alice --arg 100 --type address --type i128 --network testnet

# Inspect a deployed instance / generate typed bindings
starforge contract inspect <CONTRACT_ID> --network mainnet
starforge contract generate-bindings ./my_contract.wasm --lang rust
starforge contract generate-bindings ./my_contract.wasm --lang ts

# Deep storage inspection
starforge inspect state <CONTRACT_ID>
starforge inspect key <CONTRACT_ID> balance --scope persistent
starforge inspect storage <CONTRACT_ID> --scope instance --limit 50
```

The local WASM hash shown by `deploy`/`inspect` is a SHA-256 digest of the raw file bytes, intended to match `stellar contract inspect --wasm <file>` for the same bytecode.

### Contract Testing, Gas & Linting

```bash
# Run a compiled contract's test suite (coverage + fuzzing supported)
starforge test --wasm ./my_contract.wasm --coverage --report html
starforge test --wasm ./my_contract.wasm --fuzz transfer

# Gas/CPU analysis and a heuristic optimizer
starforge gas analyze ./my_contract.wasm --network mainnet
starforge gas optimize --target ./my_contract.wasm --output ./my_contract.optimized.wasm
starforge gas diff old.wasm new.wasm

# Static lint + size-budget checks
starforge lint ./my_contract.wasm --format json
starforge lint ./my_contract.wasm --fix
```

### Upgrade Safety Analysis

Compare the currently deployed build with a candidate before creating an upgrade proposal, and manage the propose/approve/execute/rollback lifecycle:

```bash
starforge upgrade analyze --current artifacts/current.wasm --candidate target/wasm32-unknown-unknown/release/contract.wasm

# Machine-readable report for CI and an audit artifact
starforge upgrade analyze --current artifacts/current.wasm --candidate contract.wasm --format json --output upgrade-analysis.json

# Governance lifecycle
starforge upgrade propose --contract-id C... --wasm contract.wasm --description "v2: fix rounding" --threshold 2
starforge upgrade list --contract-id C...
starforge upgrade approve --contract-id C... --proposal-id <ID>
starforge upgrade execute --contract-id C... --proposal-id <ID>
starforge upgrade rollback --contract-id C...
starforge upgrade history --contract-id C...
```

`analyze` exits non-zero when it finds a breaking change. Interface findings come from Soroban's embedded contract specification and have `confirmed` confidence; storage findings are `heuristic` and always ask you to verify the storage layout manually. The versioned JSON format is documented by [`docs/upgrade-analysis.schema.json`](docs/upgrade-analysis.schema.json).

Recommended CI gate:

```yaml
- name: Analyze Soroban upgrade safety
  run: |
    starforge upgrade analyze \
      --current artifacts/production.wasm \
      --candidate target/wasm32-unknown-unknown/release/contract.wasm \
      --format json \
      --output upgrade-analysis.json
- name: Upload upgrade analysis
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: upgrade-analysis
    path: upgrade-analysis.json
```

### Interactive Shell, Monitoring & Tutorials

```bash
# REPL against a local sandbox (or a Docker devnet with --network docker-testnet)
starforge shell --contract ./my_contract.wasm --network testnet

# Live event/balance monitoring
starforge monitor --contract CABC... --follow
starforge monitor --wallet alice --balance-alert 50

# Guided tutorials
starforge tutorial list
starforge tutorial start hello-world
starforge tutorial status

# Micro-benchmarks
starforge benchmark --wasm ./my_contract.wasm --operations 50000
starforge benchmark --cli-commands --report json
```

### AI-Assisted Developer Suite

`starforge ai` groups several AI-backed workflows. Every subcommand that calls out to a model requires `OPENAI_API_KEY` or `STARFORGE_AI_API_KEY`; the context-aware assistant, impact analysis, and telemetry/training subcommands are fully local and work without one.

**Context-aware assistant** — indexes the current workspace for deterministic or provider-backed explanation, diagnosis, suggestions, scaffold planning, and security review. Context paths stay relative, common secrets are redacted before persistence or transmission, prompts can be previewed, and provider failures fall back to offline guidance:

```bash
starforge ai assistant index --root .
starforge ai assistant review "check authorization and storage TTL" --offline
starforge ai assistant diagnose "simulation failed" --preview --format json
```

See [docs/context-aware-assistant.md](docs/context-aware-assistant.md) for the full workflow, privacy, configuration, and JSON contract.

**Code generation / analysis:**

```bash
starforge ai generate --prompt "a simple escrow contract with buyer/seller/arbiter" --output escrow.rs
starforge ai analyze --file my_contract.rs --analysis-type security
starforge ai generate-tests --file my_contract.rs --output tests/
starforge ai explain --file my_contract.rs --function transfer
starforge ai optimize --file my_contract.rs --output my_contract.optimized.rs --yes
starforge ai explain-error --message "Error(Storage, MissingValue)"
```

**Security training and AI usage telemetry:**

```bash
starforge ai security-training list
starforge ai telemetry status
```

**Social & economic impact analysis** — evaluates a contract against a policy profile (`community`, `enterprise`, `public-sector`, `protocol-maintainer`):

```bash
starforge ai impact --file my_contract.wasm --profile community --format markdown
starforge ai impact --file my_contract.wasm --profile enterprise --compare previous-report.json --deterministic
```

### Natural-Language Soroban Queries

Plan and execute safe, read-only contract state, storage, event, ledger, and transaction questions. Common intents work fully offline; AI-assisted planning is opt-in and falls back deterministically.

```bash
starforge query "what is the current admin of contract CABC...?"
starforge query "show the last 10 transfer events" --contract-id CABC... --offline
```

See [docs/natural-language-query.md](docs/natural-language-query.md) for supported intents and the JSON output contract.

### Cost Estimation

Deterministic fee/resource cost modeling for a single Soroban operation, fed by manual parameters or a real RPC simulation response, with an optional AI narrative and versioned history for regression checks in CI.

```bash
starforge cost estimate deploy --network mainnet
starforge cost estimate invoke --simulation-file tests/fixtures/soroban_rpc/simulate_cost_with_footprint.json --label my-fn --save
starforge cost compare --label my-fn
starforge cost budget --label my-fn --max-fee-stroops 5000000
starforge cost export --label my-fn --format csv
starforge cost check-regression --label my-fn --threshold-percent 10
```

### Performance Profiling

AI-assisted (optional) profiling of CPU instructions, memory, ledger I/O, and events, with saved baselines and CI regression gating.

```bash
starforge profile run --label my-fn --simulation-file sim.json --save --description "post-refactor"
starforge profile run --label my-fn --compare-baseline --regression-threshold 10 --flame
starforge profile export --label my-fn --format json
starforge profile check-regression --label my-fn
starforge profile list
```

### Real-Time Anomaly Detection

Monitors a contract's live event stream, transaction outcomes, and fee/resource usage against its own historical baseline, raising alerts for volume spikes, unusual callers, error-rate shifts, fee/resource regressions, and suspicious event payloads. Detection is always deterministic (z-score against a baseline, or a fixed fallback threshold before enough history exists); an optional AI narrative only explains alerts already raised.

```bash
starforge anomaly monitor --contract CABC... --follow
starforge anomaly baseline update --contract CABC... --events-file events.json
starforge anomaly alert-test --contract CABC... --metrics-file window.json --fail-on high
starforge anomaly report --contract CABC... --since-hours 24
```

See [docs/anomaly-detection.md](docs/anomaly-detection.md) for the detector catalog and CI-gating workflow.

### Automated Documentation Generation

Turns compiled Soroban `.wasm` artifacts into deterministic, CI-friendly documentation and a machine-readable knowledge base (`kb.json`). Signatures come from the contract's `contractspecv0` XDR metadata, every entry gets a stable ID for structural diffing, secrets are redacted by default, and quality gates exit non-zero so docs can't silently rot.

```bash
starforge docs generate my_contract.wasm --project-name my_contract
starforge docs validate docs/kb.json --min-coverage 80
starforge docs diff old/kb.json new/kb.json --fail-on-breaking
starforge docs stale docs/kb.json --wasm my_contract.wasm
starforge docs publish-preview docs/kb.json
```

See [docs/docgen.md](docs/docgen.md) for the full guide.

### Transaction Fee & Resource Budgets

Deterministic, enforceable ceilings on classic fees, Soroban resource fees, instructions, memory, ledger I/O, event size, and transaction size — checked pre-signing in `deploy`, `contract invoke`, `batch pay`, and `tx send`/`batch`, with layered global/network/command/contract/function policy overrides, one-time audited overrides, and baseline regression tracking. Opt-in and network-free: nothing changes until you run `budget init`.

```bash
starforge budget init
starforge budget explain --command deploy --network mainnet
starforge budget check --command invoke --contract CABC... --function transfer \
  --simulation-file tests/fixtures/soroban_rpc/simulate_cost_with_footprint.json

# Proceed past a hard limit with an audited, one-time reason
starforge deploy --wasm ./my_contract.wasm --budget-override-reason "hotfix approved by release manager"

# Track metrics over time and fail CI on regression
starforge budget baseline --label ci-nightly --simulation-file sim.json
starforge budget diff --label ci-nightly --threshold-percent 10
starforge budget audit --decision block
```

See [docs/budgets.md](docs/budgets.md) for policy layering, security considerations, and CI setup.

### Regulatory Compliance

Runs a configurable, deterministic regulatory-compliance check against a Soroban contract artifact and its deployment metadata, with an optional AI-assisted explanation layer. **This is a configurable starting point, not legal advice** — the built-in control catalog is illustrative and should be adapted with qualified legal review.

Every control's pass/fail/waived/needs-evidence status comes from static WASM inspection and explicit fields in a deployment-metadata file you control — never from a language model; `--explain` only attaches a plain-language explanation *after* the deterministic status is fixed.

```bash
starforge compliance profile init --jurisdiction global-baseline --jurisdiction aml-kyc-baseline
starforge compliance profile show
starforge compliance check --wasm target/wasm32-unknown-unknown/release/my_contract.wasm --metadata deployment-metadata.toml
starforge compliance evidence record --control access-control --note "reviewed by security team"
starforge compliance waiver add --control upgrade-governance --reason "pending audit" --expires 2026-12-31
starforge compliance report export --wasm my_contract.wasm --output compliance-report.json
```

See [docs/compliance.md](docs/compliance.md) for the full control catalog and deployment-metadata schema.

### Protocol & RPC Compatibility Auditing

Audit a network or project before protocol upgrades and RPC provider changes — reports use a stable versioned JSON contract, redact endpoint credentials, and do not require a live network in CI.

```bash
starforge compatibility matrix
starforge compatibility probe
starforge compatibility status
starforge compatibility audit --path . --fail-on incompatible
starforge compatibility export --audit-path . --output compatibility-evidence.json
```

See the [user guide](docs/compatibility.md) and [maintainer guide](docs/compatibility-maintainers.md).

### Stellar CLI Interoperability

Discover, diff, import, export, and synchronize configuration with the official [Stellar CLI](https://developers.stellar.org/docs/tools/cli) without manual copy/paste drift — public-only by default, with explicit precedence policies and redacted output.

```bash
starforge interop stellar discover --format json
starforge interop stellar diff --format json --direction import
starforge interop stellar import --apply --category network --name testnet
starforge interop stellar export --source stellar --output bundle.json
starforge interop stellar sync --apply --direction bidirectional --precedence additive_only
starforge interop stellar doctor --format json
```

See [docs/stellar-cli-interop.md](docs/stellar-cli-interop.md) and the [maintainer guide](docs/maintainers/stellar-cli-interop.md).

### SEP-41 Token Administration

A typed CLI for SEP-41-style Soroban token contracts: metadata inspection, balances, allowances, transfers, approvals, mint/burn/admin flows, and batch manifests. Write commands simulate by default; privileged operations require detected contract capabilities and `--yes` in automation.

```bash
starforge token inspect --id <CONTRACT_ID> --format json
starforge token balance <ACCOUNT> --id <CONTRACT_ID>
starforge token allowance <OWNER> <SPENDER> --id <CONTRACT_ID>
starforge token transfer --id <ID> --from alice --to <G...> --amount 10.5 --simulate
starforge token approve --id <ID> --from alice --spender <G...> --amount 5 --expiration-ledger 900000
starforge token mint --id <ID> --from admin --to <G...> --amount 100 --yes
starforge token batch manifest.json --id <CONTRACT_ID>
```

See [docs/token-operations.md](docs/token-operations.md) and the [maintainer guide](docs/maintainers/token-operations.md).

### Notification Router

Production-grade event routing for StarForge's own operational events, with deduplication (SHA-256 fingerprints + idempotency keys), retries with exponential backoff, quiet-hour enforcement, throttling/grouping, dead-letter management, and automatic redaction of secrets/JWTs/Stellar secret keys. Delivers to stdout, local files, HTTP webhooks, subprocess scripts, email, or chat adapters.

```bash
starforge notify routes add --name "error-notifications" --event-type command_outcome --severity error --adapter stdout --max-attempts 3 --initial-backoff 5
starforge notify test --event-type command_outcome --severity error --title "Contract deployment failed"
starforge notify events emit --event-type command_outcome --title "Mainnet Deployment" --severity info --process true
starforge notify stats
starforge notify dead-letter list
```

See [docs/notification-router.md](docs/notification-router.md) for the full adapter and rule reference.

### Plugin System

Extend StarForge with third-party native (`.so`/`.dylib`/`.dll`) or WebAssembly plugins, using the [`starforge-plugin-sdk`](crates/starforge-plugin-sdk) crate. Plugins declare a trust source, an optional content-hash approval gate, capability requirements, and Stellar-protocol/RPC compatibility bounds; installed plugin commands run as `starforge <plugin-name> ...`.

```bash
starforge plugin install starforge-defi --path ./libstarforge_defi.so --source https://github.com/example/starforge-defi
starforge plugin list
starforge plugin verify --deep --runtime-check
starforge plugin audit
starforge plugin update
starforge plugin commands
starforge plugin uninstall starforge-defi --purge

# Manage which sources are trusted without full manifest approval
starforge config plugin-trust list
starforge config plugin-trust add https://github.com/trusted-org/
```

### Raw Transactions

```bash
starforge tx send --to GDEST... --amount 100 --asset XLM --from alice
starforge tx batch --file examples/operations.json --from alice --network testnet
starforge tx history GABC... --network testnet
starforge tx fees --network mainnet
```

### Diagnostics, Config, Info & Completions

```bash
starforge info                       # environment + config summary
starforge config show
starforge config get network
starforge config set network mainnet
starforge config set-encryption --mem 65536 --iterations 3 --parallelism 4
starforge config migrate --dry-run   # preview schema migration
starforge config migrate             # apply (backs up config.toml.bak first)

starforge diagnostics --wallet ledger   # hardware wallet connectivity checks
```

> `diagnostics` bridges to an external Node.js-based hardware diagnostics runner and requires that companion tooling to be present; treat it as experimental until that runner ships alongside the CLI.

---

## Configuration File

StarForge stores all data in `~/.starforge/config.toml`:

```toml
version = 2
network = "testnet"

[[wallets]]
name = "alice"
public_key = "GABC...XYZ"
secret_key = "SABC...XYZ"  # plaintext or encrypted — see Security
network = "testnet"
created_at = "2025-01-01T00:00:00Z"
funded = true

[networks.testnet]
horizon_url = "https://horizon-testnet.stellar.org"
soroban_rpc_url = "https://soroban-testnet.stellar.org"
```

### Schema migrations

The config file is versioned with a `version` field. When the CLI is upgraded and the schema changes, the file is read into a schema-agnostic value, its version is detected, and a sequence of migrations (`v1 → v2 → …`) reshapes it **before** it is deserialized into the current `Config` — preventing the most dangerous class of upgrade bug: silently dropping wallet entries when a field is renamed or restructured.

- A backup (`config.toml.bak`) plus a timestamped copy is written before any migration overwrites the file.
- `starforge config migrate --dry-run` shows exactly what would change without modifying anything.
- Reads (`config show`, telemetry, etc.) migrate in memory only and never rewrite the file; persistence happens on an explicit `config migrate` or the next save.

Common settings: **network** (default network name), **telemetry.enabled** (see [Privacy & Telemetry](#privacy--telemetry)), and **plugin_trust** (trusted plugin sources / approval requirements).

---

## Security

Secret keys can be stored **encrypted at rest** using `--encrypt` during wallet creation or rotation:

```bash
starforge wallet create mykey --encrypt --strict
# prompts for a passphrase; --strict rejects anything below "Strong" on the zxcvbn scale
```

Encryption uses:
- **AES-256-GCM** for authenticated encryption
- **Argon2id** for key derivation from your passphrase (tunable via `starforge config set-encryption`)
- A random salt and nonce for every encryption operation

Revealing an encrypted key requires the correct passphrase:

```bash
starforge wallet show mykey --reveal
```

Unencrypted keys (without `--encrypt`) are stored in plaintext and are suitable only for testnet or throwaway accounts. **Do not use plaintext keys on mainnet with real funds.**

Other security-relevant surfaces:
- **Hardware wallets** (Ledger/Trezor) keep secret material off the host entirely for signing (`wallet connect`, `wallet sign --hardware`, `multisig ceremony sign --hardware`).
- **Plugin trust** — plugins from unknown sources are blocked by default; `config plugin-trust` and content-hash approval gate what can execute.
- **Budget overrides** — bypassing a fee/resource policy limit requires an explicit `--budget-override-reason`, which is recorded in the audit log (`budget audit`).
- **Secret redaction** — the AI assistant, compliance, interop, token, and notification-router subsystems all redact strkeys, seed phrases, and secret-shaped values by default in logs, exports, and JSON output.

### Test environment secret

Some tests validate secret-key parsing without embedding a secret in the repository. Set the value at runtime before running the test suite (a throwaway testnet key, never a real one):

```bash
export STARFORGE_TEST_SECRET_KEY="S..."  # 56-character Stellar secret key
cargo test --locked
```

---

## Privacy & Telemetry

StarForge collects **anonymous, local-only** usage telemetry to help improve CLI usability — command names and execution times, never code, keys, config values, error messages, or personal data. **No network requests are ever made for telemetry; it never leaves your machine.** It is stored at `~/.starforge/data/telemetry.log`.

### Opt out

```bash
starforge config set telemetry.enabled false
# or
starforge telemetry disable
# or, useful for CI/CD:
export STARFORGE_TELEMETRY=false
```

Check status with `starforge telemetry status`.

### Telemetry schema (v1)

Each event is a single JSON line:

```json
{
  "schema_version": 1,
  "timestamp": "2025-01-01T12:00:00Z",
  "command": "wallet",
  "duration_ms": 42,
  "success": true,
  "anonymous_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

| Field | Type | Description |
|---|---|---|
| `schema_version` | `u8` | Bumped on breaking schema changes |
| `timestamp` | ISO 8601 string | UTC time of the command |
| `command` | string | Top-level command name (e.g. `wallet`, `deploy`) |
| `duration_ms` | integer | Execution time in milliseconds |
| `success` | boolean | Whether the command completed without error |
| `anonymous_id` | UUIDv4 string | Random ID generated once per install, never changes |

The log is capped at **10,000 entries or 5 MB**, whichever comes first; oldest entries are pruned automatically. Query it directly with `jq`:

```bash
jq 'select(.success == false)' ~/.starforge/data/telemetry.log
jq -r '.command' ~/.starforge/data/telemetry.log | sort | uniq -c | sort -rn
```

### Manage telemetry

```bash
starforge telemetry show --limit 50
starforge telemetry clear
starforge telemetry status
```

**What's NOT collected**: wallet addresses, secret keys, contract code, configuration values, error messages, or any personal information.

---

## Project Structure

```
StarForge/
├── Cargo.toml                    # the `starforge` crate: bin + lib target
├── build.rs                      # generates shell completions at build time
├── src/
│   ├── main.rs                   # CLI entry point, top-level Commands enum, banner
│   ├── lib.rs                    # public library surface (compatibility, interop,
│   │                              #   plugins, signer_rotation, token, utils)
│   ├── commands/                 # one module per CLI command (39 groups); thin
│   │                              #   clap layer that calls into domain modules
│   ├── compatibility/            # protocol/RPC compatibility domain + transport
│   ├── interop/                  # Stellar CLI interoperability domain
│   ├── signer_rotation/          # signer-policy migration planner/executor/XDR
│   ├── token/                    # SEP-41 token domain, transport, engine
│   ├── plugins/                  # plugin loader, registry, WASM runtime, manifest
│   ├── wallets/                  # wallet domain helpers
│   ├── diagnostics/              # hardware diagnostics domain helpers
│   └── utils/                    # shared infrastructure: config, horizon (Horizon
│                                  #   API), soroban (RPC), crypto, mnemonic, print,
│                                  #   telemetry, budget/, compliance/, docgen/,
│                                  #   notify_router/, performance/, release/, repl,
│                                  #   sandbox, templates, tutorial_engine, tx_batch…
├── crates/
│   └── starforge-plugin-sdk/     # public SDK crate for building native/WASM plugins
├── docs/                         # deep-dive guides for the AI/compliance/interop/
│                                  #   release feature suites (see links throughout
│                                  #   this README) + maintainer-only guides
├── templates/                    # local template marketplace registry + examples
├── tutorials/                    # interactive CLI tutorial content (e.g. hello-world)
├── examples/                     # sample fixture files (e.g. batch tx operations)
├── scripts/e2e-smoke.sh          # shell-based smoke test suite, run in CI
├── benches/                      # criterion benchmarks
├── packaging/homebrew/           # Homebrew formula template
├── tests/                        # integration tests (one file per feature area)
├── Dockerfile / Dockerfile.dev   # runtime and dev-container images
├── docker-compose.yml            # local Soroban devnet + dev container stack
└── .github/workflows/            # ci.yml (fmt/deny/build+test/clippy/smoke),
                                   #   release.yml (tagged multi-platform releases)
```

---

## Maintainer Release Tooling

`starforge release` is StarForge's own reproducible-release pipeline (not a general-purpose tool for *your* Soroban projects): deterministic per-target archive staging, a versioned manifest, a CycloneDX SBOM, signing, and a SLSA-shaped provenance statement — all verifiable fully offline. Publishing itself remains a manual, maintainer-controlled step; nothing in this command family uploads, tags, or pushes anything.

```bash
starforge release prepare --version 1.2.0 --target native --skip-build --source-date-epoch "$(git log -1 --format=%ct)"
starforge release manifest --version 1.2.0
starforge release sbom --out sbom.json --include-assets templates
starforge release attest --dir ~/.starforge/release/staging/1.2.0 --signing-key ~/.starforge/release-signing.key --generate-key-if-missing
starforge release verify --dir ~/.starforge/release/staging/1.2.0
```

See [docs/release-provenance.md](docs/release-provenance.md) for the full command reference, threat model, and reproducibility notes.

The actual public release *artifacts* (the binaries end users download) are built separately by [`.github/workflows/release.yml`](.github/workflows/release.yml) on every `v*` tag push, across four target platforms, with checksums and an auto-generated Homebrew formula.

---

## Development & Contributing

We welcome contributions from developers of all experience levels!

### Quick start

```bash
git clone https://github.com/StarsForges/StarForge.git
cd StarForge
cargo build
cargo test --locked
git checkout -b feat/issue-XXX-description
```

### Before opening a pull request

Run the same checks CI runs — all five must pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo deny --all-features check
cargo build --locked
cargo test --locked
cargo test --test cli_smoke --locked
./scripts/e2e-smoke.sh
```

### Continuous Integration

Every push and pull request runs [`.github/workflows/ci.yml`](.github/workflows/ci.yml) on the pinned `1.89.0` toolchain:

| Job | What it checks |
|---|---|
| **Rustfmt** | `cargo fmt --all --check` |
| **Cargo Deny** | Advisories, license compliance, banned/duplicate dependencies, source allowlist |
| **Build and Test** | `cargo build --locked` + the full `cargo test --locked` suite |
| **Clippy Lint** | `cargo clippy --all-targets --all-features --locked -- -D warnings` |
| **CLI Smoke Tests** | `cargo test --test cli_smoke --locked` + [`scripts/e2e-smoke.sh`](scripts/e2e-smoke.sh) end-to-end CLI checks |

Tagged pushes (`v*`) additionally trigger [`.github/workflows/release.yml`](.github/workflows/release.yml), which cross-compiles release binaries for Linux (x86_64/aarch64), macOS (aarch64), and Windows (x86_64), publishes a GitHub Release with checksums, and generates an updated Homebrew formula.

### Guidelines

1. Fork and clone the repository.
2. Install Rust 1.89+ via [rustup](https://rustup.rs) — the pinned toolchain in `rust-toolchain.toml` will be installed automatically.
3. Keep changes scoped: one feature or fix per pull request, with tests covering new behavior.
4. Run the full check list above before pushing.
5. Open a pull request with a clear description of *why*, not just *what*.

---

## License

Licensed under the **MIT License**. See [`LICENSE`](LICENSE) for the full text.

---

## Acknowledgements

Built for the Stellar ecosystem. Powered by the [Stellar Horizon API](https://developers.stellar.org/api/horizon) and [Soroban](https://soroban.stellar.org).
