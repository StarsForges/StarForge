use crate::utils::print as p;
use anyhow::Result;
use colored::*;

struct CmdEntry {
    name: &'static str,
    about: &'static str,
    subs: &'static [(&'static str, &'static str)],
}

const COMMANDS: &[CmdEntry] = &[
    CmdEntry {
        name: "wallet",
        about: "Manage test wallets (create, list, fund, show, remove)",
        subs: &[
            ("create", "Create a new keypair and save it locally"),
            ("list", "List all saved wallets"),
            (
                "show",
                "Show details of a saved wallet including live balance",
            ),
            ("fund", "Fund a wallet via a configured network faucet"),
            ("remove", "Remove a wallet from local storage"),
            ("rename", "Rename a wallet"),
            (
                "merge",
                "Close a source account and send remaining XLM to a destination",
            ),
            (
                "rotate",
                "Rotate a wallet in place while keeping the same logical name",
            ),
            ("export", "Export a wallet to an encrypted JSON backup file"),
            (
                "import",
                "Import a wallet from a backup file, BIP39 phrase, or raw secret key",
            ),
            (
                "connect",
                "Connect to a hardware wallet (Ledger/Trezor) and show device info",
            ),
            (
                "hw-address",
                "Show the Stellar address derived from a connected hardware wallet",
            ),
            (
                "hw-status",
                "Show connection status of a hardware wallet without full connect",
            ),
            (
                "sign",
                "Sign an arbitrary message using a local or hardware-backed key",
            ),
            ("multisig", "Multi-signature account management"),
        ],
    },
    CmdEntry {
        name: "template",
        about: "Manage community contract templates from the marketplace",
        subs: &[
            ("search", "Search for templates in the marketplace"),
            ("list", "List all available templates"),
            ("show", "Show details of a specific template"),
            (
                "info",
                "Show full metadata: author, license, repository, trust badges",
            ),
            (
                "install",
                "Install a template from a Git URL, local path, or registry name",
            ),
            (
                "update",
                "Update installed templates to their latest versions",
            ),
            ("publish", "Publish a template to the local marketplace"),
            ("remove", "Remove a template from the local marketplace"),
            (
                "init",
                "Initialize the template registry with example templates",
            ),
        ],
    },
    CmdEntry {
        name: "new",
        about: "Generate Soroban project boilerplate",
        subs: &[
            ("contract", "Scaffold a new Soroban smart contract"),
            ("dapp", "Scaffold a new Soroban dapp"),
        ],
    },
    CmdEntry {
        name: "contract",
        about: "Contract operations (invoke, inspect, etc.)",
        subs: &[
            ("invoke", "Invoke a deployed contract function"),
            ("inspect", "Inspect a compiled contract .wasm file"),
        ],
    },
    CmdEntry {
        name: "deploy",
        about: "Deploy a compiled Soroban contract (.wasm)",
        subs: &[],
    },
    CmdEntry {
        name: "inspect",
        about: "Deep contract storage inspection (state, key, storage)",
        subs: &[
            ("state", "Show all storage entries for a contract"),
            ("key", "Show a specific storage key"),
            ("storage", "Dump raw storage"),
        ],
    },
    CmdEntry {
        name: "network",
        about: "View or switch the active network (testnet/mainnet)",
        subs: &[
            ("show", "Show the active network and its configuration"),
            ("switch", "Switch the active network"),
            ("add", "Add a custom network"),
            ("remove", "Remove a custom network"),
            ("configure", "Edit network configuration"),
        ],
    },
    CmdEntry {
        name: "node",
        about: "Local Soroban devnet (Docker quickstart)",
        subs: &[
            ("start", "Start the local Soroban devnet via Docker"),
            ("stop", "Stop the running devnet"),
            ("status", "Check devnet status"),
            ("logs", "Stream devnet container logs"),
        ],
    },
    CmdEntry {
        name: "batch",
        about: "Resumable CSV batch payouts (airdrops, contributor payments)",
        subs: &[
            ("pay", "Pay recipients from a CSV with checkpointing"),
            ("status", "Show payout progress from the checkpoint file"),
            ("resume", "Explicitly resume an interrupted batch payout"),
        ],
    },
    CmdEntry {
        name: "tx",
        about: "Fetch transaction details for an account",
        subs: &[],
    },
    CmdEntry {
        name: "plugin",
        about: "Manage third-party plugins",
        subs: &[
            ("install", "Install a plugin from a shared library path"),
            ("list", "List all installed plugins"),
            ("uninstall", "Remove an installed plugin"),
            ("update", "Update a plugin to a newer version"),
        ],
    },
    CmdEntry {
        name: "multisig",
        about: "Coordinate M-of-N multisig ceremonies as a portable file",
        subs: &[
            (
                "ceremony start",
                "Build the unsigned transaction + manifest into one file",
            ),
            (
                "ceremony sign",
                "Add this signer's signature (no network access required)",
            ),
            (
                "ceremony status",
                "Show collected vs. required signatures and time to expiry",
            ),
            (
                "ceremony submit",
                "Verify the threshold is met and submit the transaction",
            ),
        ],
    },
    CmdEntry {
        name: "shell",
        about: "Interactive REPL for local Soroban contract testing",
        subs: &[],
    },
    CmdEntry {
        name: "monitor",
        about: "Live monitoring (contract events or wallet threshold)",
        subs: &[],
    },
    CmdEntry {
        name: "tutorial",
        about: "Interactive CLI tutorials",
        subs: &[
            ("list", "List available tutorials"),
            ("start", "Start an interactive tutorial"),
            ("reset", "Reset tutorial progress"),
        ],
    },
    CmdEntry {
        name: "benchmark",
        about: "Performance benchmarking utilities",
        subs: &[],
    },
    CmdEntry {
        name: "test",
        about: "Contract testing utilities for Soroban wasm",
        subs: &[],
    },
    CmdEntry {
        name: "gas",
        about: "Gas analysis and optimization helpers",
        subs: &[
            ("estimate", "Estimate gas cost for a contract invocation"),
            ("report", "Generate a gas usage report"),
        ],
    },
    CmdEntry {
        name: "upgrade",
        about: "Contract upgrade management (propose, approve, execute, rollback)",
        subs: &[
            ("propose", "Propose a contract upgrade"),
            ("approve", "Approve a pending upgrade"),
            ("execute", "Execute an approved upgrade"),
            ("rollback", "Roll back to the previous contract version"),
        ],
    },
    CmdEntry {
        name: "lint",
        about: "Static analysis and linting for Soroban contracts",
        subs: &[],
    },
    CmdEntry {
        name: "completions",
        about: "Generate shell completions for bash, zsh, and fish",
        subs: &[
            ("bash", "Generate bash completions"),
            ("zsh", "Generate zsh completions"),
            ("fish", "Generate fish completions"),
        ],
    },
    CmdEntry {
        name: "info",
        about: "Show starforge config and environment info",
        subs: &[],
    },
    CmdEntry {
        name: "commands",
        about: "Display the full command tree (this command)",
        subs: &[],
    },
];

pub fn handle() -> Result<()> {
    p::header("StarForge Command Tree");
    println!();

    for cmd in COMMANDS {
        print!("  {:<16}", cmd.name.bold().cyan());
        println!("{}", cmd.about.dimmed());

        for (sub, desc) in cmd.subs {
            print!("    {:<14}", sub.bold());
            println!("{}", desc.dimmed());
        }

        if !cmd.subs.is_empty() {
            println!();
        }
    }

    println!();
    p::info("Plugin-provided commands are shown after `starforge <plugin-name> --help`.");
    p::info("Use `starforge <command> --help` for full flag documentation.");
    Ok(())
}
