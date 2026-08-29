use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate_to, Shell};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Parser)]
#[command(name = "starforge", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Wallet,
    New,
    Contract,
    Inspect,
    Deploy,
    Info,
    Tx,
    Network,
    Completions,
    Shell,
    Monitor,
    Tutorial,
    Benchmark,
    Test,
    Gas,
    Plugin,
    Template,
    Upgrade,
    #[command(external_subcommand)]
    #[allow(dead_code)]
    External(Vec<String>),
}

fn main() {
    let _outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(_outdir) => _outdir,
    };

    let mut cmd = Cli::command();

    // Create a directory for completions in the project root for easier access
    // or just leave them in OUT_DIR as per standard practice.
    // The issue says "Install completions to appropriate system directories".
    // We'll generate them to a 'completions' folder in the project root for now.
    let project_root = env::var("CARGO_MANIFEST_DIR").unwrap();
    let completions_dir = Path::new(&project_root).join("completions");
    fs::create_dir_all(&completions_dir).unwrap();

    for &shell in &[Shell::Bash, Shell::Zsh, Shell::Fish] {
        generate_to(shell, &mut cmd, "starforge", &completions_dir)
            .expect("Failed to generate completions");
    }

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .expect("Failed to get rustc version");
    let version = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=RUSTC_VERSION={}", version.trim());

    // Exposed to `starforge release` so build provenance can record the exact
    // target triple this binary was compiled for without re-deriving it from
    // `std::env::consts` (which cannot express e.g. glibc vs musl).
    if let Ok(target) = env::var("TARGET") {
        println!("cargo:rustc-env=STARFORGE_TARGET_TRIPLE={}", target);
    }

    println!("cargo:rerun-if-changed=build.rs");
}
