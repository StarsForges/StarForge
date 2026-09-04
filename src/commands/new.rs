use crate::utils::preflight;
use crate::utils::print as p;
use crate::utils::templates;
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum NewCommands {
    /// Scaffold a new Soroban smart contract project
    Contract {
        /// Project name
        #[arg(required_unless_present = "search")]
        name: Option<String>,
        /// Contract template (built-in or marketplace name)
        #[arg(long, default_value = "hello-world")]
        template: String,
        /// Template source label (example: marketplace)
        #[arg(long)]
        from: Option<String>,
        /// Search available templates
        #[arg(long)]
        search: Option<String>,
        /// Filter templates by tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,
        /// Interactively customize the generated contract
        #[arg(long)]
        interactive: bool,
        /// Re-download the template even if a local cache exists
        #[arg(long)]
        force_refresh: bool,
    },
    /// Scaffold a new Stellar dApp (Vite + React)
    Dapp {
        /// Project name
        name: String,
    },
}

pub fn handle(cmd: NewCommands) -> Result<()> {
    match cmd {
        NewCommands::Contract {
            name,
            template,
            from,
            search,
            tags: _,
            interactive,
            force_refresh,
        } => {
            if let Some(query) = search {
                return search_templates(&query);
            }
            let name = name.ok_or_else(|| {
                anyhow::anyhow!("A contract name is required unless --search is used")
            })?;
            if interactive {
                scaffold_contract_interactive(name)
            } else {
                scaffold_contract(
                    name,
                    template,
                    from.as_deref().unwrap_or("official"),
                    "MIT",
                    "",
                    "none",
                    true,
                    force_refresh,
                )
            }
        }
        NewCommands::Dapp { name } => scaffold_dapp(name),
    }
}

fn search_templates(query: &str) -> Result<()> {
    let results = templates::search_templates(query, None)?;
    p::header(&format!("Template search results for '{}'", query));

    if results.is_empty() {
        p::info("No templates matched that query.");
        return Ok(());
    }

    for (i, entry) in results.iter().enumerate() {
        println!("  {:>2}. {}@{}", i + 1, entry.name, entry.version);
        p::kv("Description", &entry.description);
        p::kv("Source", &entry.source.to_string());
        if !entry.tags.is_empty() {
            p::kv("Tags", &entry.tags.join(", "));
        }
        if i + 1 < results.len() {
            println!();
        }
    }

    Ok(())
}

// ?? Interactive mode ??????????????????????????????????????????????????????????

struct ContractOptions {
    name: String,
    author: String,
    license: String,
    storage: String,
    include_tests: bool,
}

fn scaffold_contract_interactive(default_name: String) -> Result<()> {
    let theme = ColorfulTheme::default();

    println!();
    println!("  {} Let's set up your contract.\n", "?".cyan());

    // 1. Contract name
    let name: String = Input::with_theme(&theme)
        .with_prompt("Contract name")
        .default(default_name)
        .interact_text()?;

    // 2. Author
    let author: String = Input::with_theme(&theme)
        .with_prompt("Author name")
        .default(String::from("Your Name"))
        .interact_text()?;

    // 3. License
    let licenses = &["MIT", "Apache-2.0", "None"];
    let license_idx = Select::with_theme(&theme)
        .with_prompt("License")
        .items(licenses)
        .default(0)
        .interact()?;
    let license = licenses[license_idx].to_string();

    // 4. Storage type
    let storage_opts = &["persistent", "temporary", "none"];
    let storage_idx = Select::with_theme(&theme)
        .with_prompt("Storage type")
        .items(storage_opts)
        .default(0)
        .interact()?;
    let storage = storage_opts[storage_idx].to_string();

    // 5. Test suite
    let include_tests = Confirm::with_theme(&theme)
        .with_prompt("Include a test module?")
        .default(true)
        .interact()?;

    let opts = ContractOptions {
        name,
        author,
        license,
        storage,
        include_tests,
    };

    // Summary + confirm
    println!();
    println!("  {} Summary:", "?".bright_white());
    println!("    Contract name : {}", opts.name.cyan());
    println!("    Author        : {}", opts.author.cyan());
    println!("    License       : {}", opts.license.cyan());
    println!("    Storage       : {}", opts.storage.cyan());
    println!(
        "    Tests         : {}",
        if opts.include_tests {
            "yes".green()
        } else {
            "no".yellow()
        }
    );
    println!();

    let confirmed = Confirm::with_theme(&theme)
        .with_prompt("Write files?")
        .default(true)
        .interact()?;

    if !confirmed {
        println!("\n  {} Aborted - no files written.\n", "?".red());
        return Ok(());
    }

    scaffold_contract(
        opts.name,
        "hello-world".to_string(), // template base; content is overridden by opts
        "official",
        &opts.license,
        &opts.author,
        &opts.storage,
        opts.include_tests,
        false, // interactive path never force-refreshes
    )
}

fn scaffold_contract(
    name: String,
    template: String,
    source: &str,
    license: &str,
    author: &str,
    storage: &str,
    include_tests: bool,
    force_refresh: bool,
) -> Result<()> {
    let dir = Path::new(&name);
    if dir.exists() {
        anyhow::bail!(
            "Directory '{}' already exists.\n  . Choose a different project name, or remove the existing directory first.",
            name
        );
    }

    p::header(&format!("Scaffolding Soroban contract: {}", name));
    println!("  Template: {}\n", template.cyan());

    let preflight = preflight::run_contract_preflight(false)?;
    p::success(&format!(
        "Rust toolchain ready: cargo {}, wasm32 target installed",
        preflight.cargo_version
    ));
    if !preflight.stellar_cli_available {
        p::warn(
            "`stellar` CLI was not found. The contract can be scaffolded now, but install Stellar CLI before building or deploying.",
        );
    }

    // Ensure selected template is compatible with current CLI version
    let entry = templates::get_template(&template)?;
    match templates::check_template_compatibility(&entry) {
        templates::CompatibilityStatus::Compatible => {}
        templates::CompatibilityStatus::TooOld {
            required_min,
            running,
        } => {
            p::error(&format!(
                "Template '{}' requires StarForge >= {} but you are running {}.\nPlease upgrade StarForge: https://github.com/Nanle-code/StarForge#installation",
                entry.name, required_min, running
            ));
            return Ok(());
        }
        templates::CompatibilityStatus::TooNew {
            required_max,
            running,
        } => {
            p::error(&format!(
                "Template '{}' only supports StarForge <= {} but you are running {}.\nUse an older StarForge version or choose a compatible template.",
                entry.name, required_max, running
            ));
            return Ok(());
        }
        templates::CompatibilityStatus::MalformedMetadata { reason } => {
            p::error(&format!(
                "Template '{}' has malformed version metadata: {}.\nContact the template author to fix the cli_version_min / cli_version_max fields.",
                entry.name, reason
            ));
            return Ok(());
        }
    }

    // Roll back the partially-created directory if any step below fails.
    let mut target_guard = PathCleanup::new(dir.to_path_buf());

    p::step(1, 4, "Creating directory structure.");
    fs::create_dir_all(dir.join("src"))?;
    fs::create_dir_all(dir.join(".cargo"))?;

    p::step(2, 4, "Writing Cargo.toml.");
    fs::write(dir.join("Cargo.toml"), cargo_toml(&name, license, author))?;
    fs::write(dir.join(".cargo/config.toml"), cargo_config())?;
    fs::write(dir.join(".gitignore"), "target/\n.soroban/\n")?;

    p::step(3, 4, &format!("Generating '{}' contract source.", template));
    let src = match template.as_str() {
        "token" => token_template(&name),
        "voting" => voting_template(&name),
        "nft" => nft_template(&name),
        _ => {
            if let Some(custom) = templates::template_source_content(&template, force_refresh)? {
                custom
            } else if template == "hello-world" {
                hello_world_template(&name, storage, include_tests)
            } else {
                anyhow::bail!(
                    "Unknown template '{}'. Search available templates with `starforge new contract --search <query>`.",
                    template
                );
            }
        }
    };
    fs::write(dir.join("src/lib.rs"), src)?;

    p::step(4, 4, "Writing README.md.");
    fs::write(dir.join("README.md"), readme(&name, &template, source))?;

    // Scaffolding completed: keep the directory.
    target_guard.commit();

    println!();
    p::success(&format!("Contract '{}' scaffolded!", name));
    println!();
    println!("  Next steps:");
    p::info(&format!("  cd {}", name));
    p::info("  stellar contract build");
    p::info(&format!(
        "  starforge deploy --wasm target/wasm32-unknown-unknown/release/{}.wasm",
        name.replace('-', "_")
    ));
    println!();
    Ok(())
}

fn scaffold_dapp(name: String) -> Result<()> {
    let dir = Path::new(&name);
    if dir.exists() {
        anyhow::bail!("Directory '{}' already exists", name);
    }

    p::header(&format!("Scaffolding Stellar dApp: {}", name));

    p::step(1, 3, "Creating project structure.");
    fs::create_dir_all(dir.join("src/components"))?;
    fs::create_dir_all(dir.join("public"))?;

    p::step(2, 3, "Writing package.json.");
    fs::write(dir.join("package.json"), dapp_package(&name))?;

    p::step(3, 3, "Writing app scaffold.");
    fs::write(dir.join("index.html"), dapp_index(&name))?;
    fs::write(dir.join("src/main.jsx"), dapp_main())?;
    fs::write(dir.join("src/App.jsx"), dapp_app(&name))?;
    fs::write(dir.join(".gitignore"), "node_modules/\ndist/\n")?;
    fs::write(dir.join("README.md"), dapp_readme(&name))?;

    println!();
    p::success(&format!("dApp '{}' scaffolded!", name));
    p::info(&format!("cd {} && npm install && npm run dev", name));
    println!();
    Ok(())
}

// ?? Helpers ??????????????????????????????????????????????????????????????????

fn to_pascal(s: &str) -> String {
    s.split(['-', '_', ' '])
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

// ?? Cargo files ??????????????????????????????????????????????????????????????

fn cargo_toml(name: &str, license: &str, author: &str) -> String {
    let license_field = if license == "None" || license.is_empty() {
        String::new()
    } else {
        format!("license = \"{license}\"\n")
    };
    let author_field = if author.is_empty() {
        String::new()
    } else {
        format!("authors = [\"{author}\"]\n")
    };
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
{author_field}{license_field}
[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = "21.0.0"

[dev-dependencies]
soroban-sdk = {{ version = "21.0.0", features = ["testutils"] }}

[profile.release]
opt-level = "z"
overflow-checks = true
debug = 0
strip = "symbols"
debug-assertions = false
panic = "abort"
codegen-units = 1
lto = true
"#
    )
}

fn cargo_config() -> &'static str {
    r#"[target.wasm32-unknown-unknown]
rustflags = ["-C", "target-feature=+multivalue,+sign-ext"]
"#
}

// ?? Contract templates ????????????????????????????????????????????????????????

fn hello_world_template(name: &str, storage: &str, include_tests: bool) -> String {
    let pascal = to_pascal(name);

    let storage_import = match storage {
        "persistent" | "temporary" => "\nuse soroban_sdk::storage::Storage;",
        _ => "",
    };

    let storage_method = match storage {
        "persistent" => r#"
    pub fn set_value(env: Env, key: Symbol, value: u64) {
        env.storage().persistent().set(&key, &value);
    }

    pub fn get_value(env: Env, key: Symbol) -> Option<u64> {
        env.storage().persistent().get(&key)
    }"#
        .to_string(),
        "temporary" => r#"
    pub fn set_value(env: Env, key: Symbol, value: u64) {
        env.storage().temporary().set(&key, &value);
    }

    pub fn get_value(env: Env, key: Symbol) -> Option<u64> {
        env.storage().temporary().get(&key)
    }"#
        .to_string(),
        _ => String::new(),
    };

    let test_module = if include_tests {
        format!(
            r#"

#[cfg(test)]
mod test {{
    use super::*;
    use soroban_sdk::{{Env, symbol_short}};

    #[test]
    fn test_hello() {{
        let env = Env::default();
        let id  = env.register_contract(None, {pascal});
        let client = {pascal}Client::new(&env, &id);
        let words = client.hello(&symbol_short!("Dev"));
        assert_eq!(words, vec![&env, symbol_short!("Hello"), symbol_short!("Dev")]);
    }}
}}"#,
            pascal = pascal
        )
    } else {
        String::new()
    };

    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, symbol_short, vec, Env, Symbol, Vec}};{storage_import}

#[contract]
pub struct {pascal};

#[contractimpl]
impl {pascal} {{
    pub fn hello(env: Env, to: Symbol) -> Vec<Symbol> {{
        vec![&env, symbol_short!("Hello"), to]
    }}{storage_method}
}}{test_module}
"#,
        pascal = pascal,
        storage_import = storage_import,
        storage_method = storage_method,
        test_module = test_module,
    )
}

fn token_template(name: &str) -> String {
    let pascal = to_pascal(name);
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, contracttype, symbol_short, Address, Env, String}};

#[derive(Clone)]
#[contracttype]
pub struct TokenMetadata {{
    pub decimal: u32,
    pub name: String,
    pub symbol: String,
}}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {{
    Admin,
    Metadata,
    Balance(Address),
    TotalSupply,
}}

#[contract]
pub struct {pascal};

#[contractimpl]
impl {pascal} {{
    pub fn initialize(env: Env, admin: Address, decimal: u32, name: String, symbol: String) {{
        admin.require_auth();
        
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Metadata, &TokenMetadata {{ decimal, name, symbol }});
        env.storage().instance().set(&DataKey::TotalSupply, &0i128);
    }}

    pub fn mint(env: Env, to: Address, amount: i128) {{
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        
        let balance = Self::balance(env.clone(), to.clone());
        env.storage().persistent().set(&DataKey::Balance(to), &(balance + amount));
        
        let total: i128 = env.storage().instance().get(&DataKey::TotalSupply).unwrap();
        env.storage().instance().set(&DataKey::TotalSupply, &(total + amount));
    }}

    pub fn balance(env: Env, id: Address) -> i128 {{
        env.storage().persistent().get(&DataKey::Balance(id)).unwrap_or(0)
    }}

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {{
        from.require_auth();
        
        let from_balance = Self::balance(env.clone(), from.clone());
        if from_balance < amount {{
            panic!("insufficient balance");
        }}
        
        env.storage().persistent().set(&DataKey::Balance(from), &(from_balance - amount));
        
        let to_balance = Self::balance(env.clone(), to.clone());
        env.storage().persistent().set(&DataKey::Balance(to), &(to_balance + amount));
    }}

    pub fn total_supply(env: Env) -> i128 {{
        env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0)
    }}
}}

#[cfg(test)]
mod test {{
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_token_lifecycle() {{
        let env = Env::default();
        let contract_id = env.register_contract(None, {pascal});
        let client = {pascal}Client::new(&env, &contract_id);
        
        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);
        
        env.mock_all_auths();
        
        client.initialize(&admin, &18, &String::from_str(&env, "Test Token"), &String::from_str(&env, "TST"));
        
        client.mint(&user1, &1000);
        assert_eq!(client.balance(&user1), 1000);
        assert_eq!(client.total_supply(), 1000);
        
        client.transfer(&user1, &user2, &300);
        assert_eq!(client.balance(&user1), 700);
        assert_eq!(client.balance(&user2), 300);
    }}
}}
"#,
        pascal = pascal
    )
}

fn voting_template(name: &str) -> String {
    let pascal = to_pascal(name);
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, contracttype, Address, Env, String, Vec}};

#[derive(Clone)]
#[contracttype]
pub struct Proposal {{
    pub id: u32,
    pub creator: Address,
    pub title: String,
    pub yes_votes: u32,
    pub no_votes: u32,
    pub active: bool,
}}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {{
    ProposalCount,
    Proposal(u32),
    Vote(u32, Address),
}}

#[contract]
pub struct {pascal};

#[contractimpl]
impl {pascal} {{
    pub fn create_proposal(env: Env, creator: Address, title: String) -> u32 {{
        creator.require_auth();
        
        let count: u32 = env.storage().instance().get(&DataKey::ProposalCount).unwrap_or(0);
        let proposal_id = count + 1;
        
        let proposal = Proposal {{
            id: proposal_id,
            creator,
            title,
            yes_votes: 0,
            no_votes: 0,
            active: true,
        }};
        
        env.storage().persistent().set(&DataKey::Proposal(proposal_id), &proposal);
        env.storage().instance().set(&DataKey::ProposalCount, &proposal_id);
        
        proposal_id
    }}

    pub fn vote(env: Env, voter: Address, proposal_id: u32, approve: bool) {{
        voter.require_auth();
        
        let vote_key = DataKey::Vote(proposal_id, voter.clone());
        if env.storage().persistent().has(&vote_key) {{
            panic!("already voted");
        }}
        
        let mut proposal: Proposal = env.storage().persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| panic!("proposal not found"));
        
        if !proposal.active {{
            panic!("proposal is closed");
        }}
        
        if approve {{
            proposal.yes_votes += 1;
        }} else {{
            proposal.no_votes += 1;
        }}
        
        env.storage().persistent().set(&DataKey::Proposal(proposal_id), &proposal);
        env.storage().persistent().set(&vote_key, &approve);
    }}

    pub fn results(env: Env, proposal_id: u32) -> (u32, u32) {{
        let proposal: Proposal = env.storage().persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| panic!("proposal not found"));
        
        (proposal.yes_votes, proposal.no_votes)
    }}

    pub fn close_proposal(env: Env, proposal_id: u32) {{
        let mut proposal: Proposal = env.storage().persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| panic!("proposal not found"));
        
        proposal.creator.require_auth();
        proposal.active = false;
        env.storage().persistent().set(&DataKey::Proposal(proposal_id), &proposal);
    }}
}}

#[cfg(test)]
mod test {{
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_voting_lifecycle() {{
        let env = Env::default();
        let contract_id = env.register_contract(None, {pascal});
        let client = {pascal}Client::new(&env, &contract_id);
        
        let creator = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);
        
        env.mock_all_auths();
        
        let proposal_id = client.create_proposal(&creator, &String::from_str(&env, "Proposal 1"));
        assert_eq!(proposal_id, 1);
        
        client.vote(&voter1, &proposal_id, &true);
        client.vote(&voter2, &proposal_id, &false);
        
        let (yes, no) = client.results(&proposal_id);
        assert_eq!(yes, 1);
        assert_eq!(no, 1);
        
        client.close_proposal(&proposal_id);
    }}
}}
"#,
        pascal = pascal
    )
}

fn nft_template(name: &str) -> String {
    let pascal = to_pascal(name);
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, contracttype, Address, Env, String}};

#[derive(Clone)]
#[contracttype]
pub struct NFTMetadata {{
    pub owner: Address,
    pub uri: String,
}}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {{
    Admin,
    Token(u64),
    TotalSupply,
}}

#[contract]
pub struct {pascal};

#[contractimpl]
impl {pascal} {{
    pub fn initialize(env: Env, admin: Address) {{
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::TotalSupply, &0u64);
    }}

    pub fn mint(env: Env, to: Address, token_id: u64, uri: String) {{
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        
        if env.storage().persistent().has(&DataKey::Token(token_id)) {{
            panic!("token already exists");
        }}
        
        let metadata = NFTMetadata {{ owner: to, uri }};
        env.storage().persistent().set(&DataKey::Token(token_id), &metadata);
        
        let total: u64 = env.storage().instance().get(&DataKey::TotalSupply).unwrap();
        env.storage().instance().set(&DataKey::TotalSupply, &(total + 1));
    }}

    pub fn owner_of(env: Env, token_id: u64) -> Address {{
        let metadata: NFTMetadata = env.storage().persistent()
            .get(&DataKey::Token(token_id))
            .unwrap_or_else(|| panic!("token not found"));
        metadata.owner
    }}

    pub fn transfer(env: Env, from: Address, to: Address, token_id: u64) {{
        from.require_auth();
        
        let mut metadata: NFTMetadata = env.storage().persistent()
            .get(&DataKey::Token(token_id))
            .unwrap_or_else(|| panic!("token not found"));
        
        if metadata.owner != from {{
            panic!("not token owner");
        }}
        
        metadata.owner = to;
        env.storage().persistent().set(&DataKey::Token(token_id), &metadata);
    }}

    pub fn token_uri(env: Env, token_id: u64) -> String {{
        let metadata: NFTMetadata = env.storage().persistent()
            .get(&DataKey::Token(token_id))
            .unwrap_or_else(|| panic!("token not found"));
        metadata.uri
    }}

    pub fn total_supply(env: Env) -> u64 {{
        env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0)
    }}
}}

#[cfg(test)]
mod test {{
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_nft_lifecycle() {{
        let env = Env::default();
        let contract_id = env.register_contract(None, {pascal});
        let client = {pascal}Client::new(&env, &contract_id);
        
        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);
        
        env.mock_all_auths();
        
        client.initialize(&admin);
        
        client.mint(&user1, &1, &String::from_str(&env, "ipfs://token1"));
        assert_eq!(client.owner_of(&1), user1);
        assert_eq!(client.total_supply(), 1);
        
        client.transfer(&user1, &user2, &1);
        assert_eq!(client.owner_of(&1), user2);
        
        let uri = client.token_uri(&1);
        assert_eq!(uri, String::from_str(&env, "ipfs://token1"));
    }}
}}
"#,
        pascal = pascal
    )
}

// ?? dApp scaffold files ???????????????????????????????????????????????????????

fn dapp_package(name: &str) -> String {
    format!(
        r#"{{
  "name": "{name}",
  "version": "0.1.0",
  "type": "module",
  "scripts": {{
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  }},
  "dependencies": {{
    "@stellar/stellar-sdk": "^12.3.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0"
  }},
  "devDependencies": {{
    "@vitejs/plugin-react": "^4.3.1",
    "vite": "^5.4.0"
  }}
}}
"#
    )
}

fn dapp_index(name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{name}</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
"#
    )
}

fn dapp_tsconfig() -> String {
    r#"{"compilerOptions": {"target": "es2020", "module": "esnext", "moduleResolution": "node", "esModuleInterop": true}}"#.to_string()
}

fn dapp_tsconfig_node() -> String {
    r#"{"extends": "./tsconfig.json", "compilerOptions": {"module": "commonjs", "target": "es2020", "moduleResolution": "node", "esModuleInterop": true}}"#.to_string()
}

fn dapp_vite_env_types(wallet_kit: bool) -> String {
    if wallet_kit {
        r#"interface ImportMetaEnv { VITE_NETWORK: string; VITE_WALLET_KIT: boolean; }"#.to_string()
    } else {
        r#"interface ImportMetaEnv { VITE_NETWORK: string; }"#.to_string()
    }
}

fn dapp_main() -> &'static str {
    r#"import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode><App /></React.StrictMode>
)
"#
}

fn dapp_app(name: &str) -> String {
    format!(
        r#"import React from 'react'

export default function App() {{
  return (
    <div style={{{{ fontFamily: 'monospace', padding: '2rem' }}}}>
      <h1>? {name}</h1>
      <p>Your Stellar dApp is ready. Start building!</p>
    </div>
  )
}}
"#
    )
}

fn dapp_readme(name: &str) -> String {
    format!(
        r#"# {name}

A Stellar dApp scaffolded with [starforge](https://github.com/StarsForges/StarForge).

## Getting Started

```bash
npm install
npm run dev
```
"#
    )
}

fn readme(name: &str, template: &str, source: &str) -> String {
    format!(
        r#"# {name}

A Soroban smart contract scaffolded with [starforge](https://github.com/StarsForges/StarForge).

## Build

```bash
stellar contract build
```

## Test

```bash
cargo test
```

## Deploy

```bash
starforge deploy \
  --wasm target/wasm32-unknown-unknown/release/{snake}.wasm \
  --network testnet
```

Template: `{template}`
Source: `{source}`
"#,
        name = name,
        snake = name.replace('-', "_"),
        template = template,
        source = source
    )
}

// ?? Template Marketplace ??????????????????????????????????????????????????????

fn handle_template_search(query: &str, tags: Option<&str>) -> Result<()> {
    p::header("Template Marketplace - Search");
    p::kv("Query", query);

    let tag_list = tags.map(|t| {
        t.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });

    if let Some(ref tags) = tag_list {
        p::kv("Tags", &tags.join(", "));
    }

    println!();

    let results = templates::search_templates(query, tag_list.as_deref())?;

    if results.is_empty() {
        p::info("No templates found matching your search.");
        p::info("Try: starforge template publish ./my-template");
        return Ok(());
    }

    p::separator();
    println!("  Found {} template(s):\n", results.len());

    for (i, tmpl) in results.iter().enumerate() {
        let verified = if tmpl.verified {
            " ?".green()
        } else {
            "".normal()
        };
        println!("  {}. {}{}", i + 1, tmpl.name.cyan().bold(), verified);
        println!("     {}", tmpl.description.dimmed());
        println!(
            "     {} . {} . {} downloads",
            tmpl.version.yellow(),
            tmpl.author.dimmed(),
            tmpl.downloads
        );

        if !tmpl.tags.is_empty() {
            println!("     Tags: {}", tmpl.tags.join(", ").bright_black());
        }

        if i < results.len() - 1 {
            println!();
        }
    }

    p::separator();
    println!();
    p::info("Use a template:");
    println!(
        "  {}",
        format!(
            "starforge new contract my-project --template {} --from marketplace",
            results[0].name
        )
        .cyan()
    );

    Ok(())
}

/// RAII guard that removes a filesystem path when dropped, unless it has been
/// committed. This gives clean rollback for partial template installs: if any
/// step fails and the function returns early, the partially-written directory
/// is removed automatically while the error unwinds.
struct PathCleanup {
    path: PathBuf,
    committed: bool,
}

impl PathCleanup {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    /// Keep the directory instead of removing it on drop.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PathCleanup {
    fn drop(&mut self) {
        if !self.committed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Run a single install step behind a spinner, finishing with a check mark on
/// success or clearing the spinner and attaching an actionable message on
/// failure.
fn install_step<T>(
    label: &str,
    done: &str,
    action: impl FnOnce() -> Result<T>,
    err_context: impl FnOnce() -> String,
) -> Result<T> {
    let pb = p::spinner(label);
    match action() {
        Ok(value) => {
            pb.finish_with_message(format!("? {}", done));
            Ok(value)
        }
        Err(e) => {
            pb.finish_and_clear();
            Err(e).with_context(err_context)
        }
    }
}

fn scaffold_from_marketplace(name: String, template_name: String) -> Result<()> {
    p::header(&format!("Scaffolding from Marketplace: {}", template_name));

    // Get template from registry
    let template = templates::get_template(&template_name).with_context(|| {
        format!(
            "Template '{}' not found in the registry.\n  . List templates with `starforge template list`.\n  . Search with `starforge new contract --search {}`.",
            template_name, template_name
        )
    })?;

    let dir = Path::new(&name);
    if dir.exists() {
        anyhow::bail!(
            "Directory '{}' already exists.\n  . Choose a different project name, or remove the existing directory first.",
            name
        );
    }

    p::separator();
    p::kv("Template", &template.name);
    p::kv("Version", &template.version);
    p::kv("Author", &template.author);
    p::kv("Description", &template.description);
    p::separator();
    println!();

    // Stage the download in a temporary directory. The guard guarantees the
    // temp dir is removed whether the install succeeds or fails.
    let temp_dir =
        std::env::temp_dir().join(format!("starforge-template-{}", uuid::Uuid::new_v4()));
    let temp_guard = PathCleanup::new(temp_dir.clone());

    // The target project directory is only kept if every step succeeds.
    let mut target_guard = PathCleanup::new(dir.to_path_buf());

    install_step(
        &format!("[1/3] Fetching template '{}'.", template.name),
        &format!("Fetched template '{}'", template.name),
        || templates::fetch_template(&template, &temp_dir),
        || {
            format!(
                "Failed to fetch template '{}' from {}.\n  . Check your network connection and that `git` is installed.\n  . The partial download was rolled back automatically.",
                template.name, template.source
            )
        },
    )?;

    install_step(
        "[2/3] Validating template structure.",
        "Template structure is valid",
        || {
            templates::validate_template_structure(
                &temp_dir,
                &template.name,
                &template.description,
                &template.author,
                &template.version,
            )
        },
        || {
            format!(
                "Template '{}' is missing required files (expected Cargo.toml, src/ and src/lib.rs).\n  . The template may be malformed; contact its author or pick another.\n  . The partial install was rolled back automatically.",
                template.name
            )
        },
    )?;

    install_step(
        "[3/3] Installing into project directory.",
        &format!("Installed into '{}'", name),
        || {
            fs::create_dir_all(dir).with_context(|| {
                format!("Failed to create project directory '{}'", dir.display())
            })?;
            copy_template_contents(&temp_dir, dir, &name)
        },
        || {
            format!(
                "Failed to install template into '{}'.\n  . Check that you have write permission for this location and enough disk space.\n  . The half-written project directory was rolled back automatically.",
                name
            )
        },
    )?;

    // Everything succeeded: keep the project directory; the temp dir is removed
    // by its guard when this function returns.
    target_guard.commit();
    drop(temp_guard);

    // Update download count (best-effort; failure here must not roll back a
    // successfully installed project).
    if let Ok(mut registry) = templates::load_registry() {
        if let Some(entry) = registry
            .templates
            .iter_mut()
            .find(|t| t.name == template.name)
        {
            entry.downloads += 1;
            if let Err(e) = templates::save_registry(&registry) {
                p::warn(&format!(
                    "Installed, but could not update download count: {}",
                    e
                ));
            }
        }
    }

    println!();
    p::success(&format!("Contract '{}' scaffolded from marketplace!", name));
    println!();
    println!("  Next steps:");
    p::info(&format!("  cd {}", name));
    p::info("  stellar contract build");
    p::info(&format!(
        "  starforge deploy --wasm target/wasm32-unknown-unknown/release/{}.wasm",
        name.replace('-', "_")
    ));
    println!();

    Ok(())
}

fn copy_template_contents(src: &Path, dst: &Path, project_name: &str) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();

        // Skip .git and target directories
        if file_name == ".git" || file_name == "target" {
            continue;
        }

        let dest_path = dst.join(&file_name);

        if path.is_dir() {
            fs::create_dir_all(&dest_path)?;
            copy_template_contents(&path, &dest_path, project_name)?;
        } else {
            // Read file content
            let mut content = fs::read_to_string(&path)?;

            // Replace template placeholders
            content = content.replace("{{PROJECT_NAME}}", project_name);
            content = content.replace("{{PROJECT_NAME_SNAKE}}", &project_name.replace('-', "_"));
            content = content.replace("{{PROJECT_NAME_PASCAL}}", &to_pascal(project_name));

            fs::write(&dest_path, content)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod install_tests {
    use super::PathCleanup;
    use std::fs;

    #[test]
    fn cleanup_removes_dir_when_not_committed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("partial-install");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/lib.rs"), "partial").unwrap();
        assert!(dir.exists());

        {
            let _guard = PathCleanup::new(dir.clone());
            // guard dropped here without commit -> directory should be removed
        }

        assert!(!dir.exists(), "uncommitted install should be rolled back");
    }

    #[test]
    fn cleanup_keeps_dir_when_committed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("good-install");
        fs::create_dir_all(&dir).unwrap();

        {
            let mut guard = PathCleanup::new(dir.clone());
            guard.commit();
        }

        assert!(dir.exists(), "committed install should be kept");
    }
}
