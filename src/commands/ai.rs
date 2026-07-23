use anyhow::{Context, Result};
use async_openai::{
    types::{
        ChatCompletionRequestMessage, ChatCompletionRequestSystemMessage,
        ChatCompletionRequestUserMessage, CreateChatCompletionRequest,
    },
    Client,
};
use clap::{Parser, Subcommand};
use colored::*;
use std::env;

#[derive(Parser)]
#[command(about = "AI-powered development assistance for Soroban contracts")]
pub struct AiArgs {
    #[command(subcommand)]
    command: AiCommands,
}

#[derive(Subcommand)]
enum AiCommands {
    /// Generate Soroban contract code from natural language description
    Generate {
        /// Natural language description of the contract
        #[arg(long)]
        prompt: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
        /// Model to use (default: gpt-4)
        #[arg(long, default_value = "gpt-4")]
        model: String,
    },
    /// Analyze existing Soroban contract for security vulnerabilities
    Analyze {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Analysis type (security, gas, optimization)
        #[arg(long, default_value = "security")]
        analysis_type: String,
    },
    /// Generate test cases for a Soroban contract
    GenerateTests {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Output directory for tests
        #[arg(long)]
        output: Option<String>,
    },
    /// Explain Soroban contract code in natural language
    Explain {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Specific function to explain (optional)
        #[arg(long)]
        function: Option<String>,
    },
    /// Optimize Soroban contract code
    Optimize {
        /// Path to the contract file
        #[arg(long)]
        file: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
}

pub async fn handle(args: AiArgs) -> Result<()> {
    let api_key = env::var("OPENAI_API_KEY")
        .or_else(|_| env::var("STARFORGE_AI_API_KEY"))
        .context("OPENAI_API_KEY or STARFORGE_AI_API_KEY environment variable not set")?;

    let client = Client::new().with_api_key(api_key);

    match args.command {
        AiCommands::Generate {
            prompt,
            output,
            model,
        } => generate_contract(&client, &prompt, output.as_deref(), &model).await,
        AiCommands::Analyze {
            file,
            analysis_type,
        } => analyze_contract(&client, &file, &analysis_type).await,
        AiCommands::GenerateTests {
            file,
            output,
        } => generate_tests(&client, &file, output.as_deref()).await,
        AiCommands::Explain { file, function } => {
            explain_contract(&client, &file, function.as_deref()).await
        }
        AiCommands::Optimize { file, output } => {
            optimize_contract(&client, &file, output.as_deref()).await
        }
    }
}

async fn generate_contract(
    client: &Client,
    prompt: &str,
    output: Option<&str>,
    model: &str,
) -> Result<()> {
    println!("{} Generating Soroban contract...", "✨".cyan());

    let system_prompt = "You are an expert Soroban smart contract developer. Generate complete, compilable Soroban contract code in Rust based on the user's description. Include proper error handling, comments, and follow Soroban best practices. Return only the code without markdown formatting.";

    let messages = vec![
        ChatCompletionRequestMessage::System(ChatCompletionRequestSystemMessage {
            content: system_prompt.to_string(),
            name: None,
        }),
        ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
            content: prompt.to_string(),
            name: None,
        }),
    ];

    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    let response = client.chat().create(request).await?;

    if let Some(choice) = response.choices.first() {
        let code = choice.message.content.trim();
        
        if let Some(output_path) = output {
            std::fs::write(output_path, code)
                .context("Failed to write generated code to file")?;
            println!("{} Contract generated and saved to {}", "✓".green(), output_path);
        } else {
            println!("{}", "Generated contract:".bold());
            println!("{}", code);
        }
    }

    Ok(())
}

async fn analyze_contract(client: &Client, file: &str, analysis_type: &str) -> Result<()> {
    println!("{} Analyzing contract for {}...", "🔍".cyan(), analysis_type);

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = match analysis_type {
        "security" => "You are a Soroban smart contract security expert. Analyze the provided Soroban contract code for security vulnerabilities, potential attack vectors, and best practice violations. Provide specific recommendations for each issue found.",
        "gas" => "You are a Soroban gas optimization expert. Analyze the provided Soroban contract code for gas inefficiencies and provide specific optimization recommendations.",
        "optimization" => "You are a Soroban code optimization expert. Analyze the provided Soroban contract code for performance improvements and provide specific recommendations.",
        _ => "You are a Soroban smart contract expert. Analyze the provided contract code.",
    };

    let messages = vec![
        ChatCompletionRequestMessage::System(ChatCompletionRequestSystemMessage {
            content: system_prompt.to_string(),
            name: None,
        }),
        ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
            content: format!("Analyze this Soroban contract:\n\n{}", code),
            name: None,
        }),
    ];

    let request = CreateChatCompletionRequest {
        model: "gpt-4".to_string(),
        messages,
        ..Default::default()
    };

    let response = client.chat().create(request).await?;

    if let Some(choice) = response.choices.first() {
        println!("{}", "Analysis results:".bold());
        println!("{}", choice.message.content);
    }

    Ok(())
}

async fn generate_tests(client: &Client, file: &str, output: Option<&str>) -> Result<()> {
    println!("{} Generating test cases...", "🧪".cyan());

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = "You are a Soroban testing expert. Generate comprehensive test cases for the provided Soroban contract. Include unit tests, edge cases, and integration tests. Use the Soroban SDK testing framework. Return only the test code without markdown formatting.";

    let messages = vec![
        ChatCompletionRequestMessage::System(ChatCompletionRequestSystemMessage {
            content: system_prompt.to_string(),
            name: None,
        }),
        ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
            content: format!("Generate tests for this Soroban contract:\n\n{}", code),
            name: None,
        }),
    ];

    let request = CreateChatCompletionRequest {
        model: "gpt-4".to_string(),
        messages,
        ..Default::default()
    };

    let response = client.chat().create(request).await?;

    if let Some(choice) = response.choices.first() {
        let test_code = choice.message.content.trim();
        
        if let Some(output_path) = output {
            std::fs::write(output_path, test_code)
                .context("Failed to write test code to file")?;
            println!("{} Tests generated and saved to {}", "✓".green(), output_path);
        } else {
            println!("{}", "Generated test cases:".bold());
            println!("{}", test_code);
        }
    }

    Ok(())
}

async fn explain_contract(
    client: &Client,
    file: &str,
    function: Option<&str>,
) -> Result<()> {
    println!("{} Explaining contract...", "📖".cyan());

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = "You are a Soroban smart contract educator. Explain the provided Soroban contract code in clear, natural language. Break down complex concepts and provide examples. If a specific function is requested, focus your explanation on that function.";

    let user_prompt = if let Some(func_name) = function {
        format!(
            "Explain this Soroban contract, focusing on the '{}' function:\n\n{}",
            func_name, code
        )
    } else {
        format!("Explain this Soroban contract:\n\n{}", code)
    };

    let messages = vec![
        ChatCompletionRequestMessage::System(ChatCompletionRequestSystemMessage {
            content: system_prompt.to_string(),
            name: None,
        }),
        ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
            content: user_prompt,
            name: None,
        }),
    ];

    let request = CreateChatCompletionRequest {
        model: "gpt-4".to_string(),
        messages,
        ..Default::default()
    };

    let response = client.chat().create(request).await?;

    if let Some(choice) = response.choices.first() {
        println!("{}", "Contract explanation:".bold());
        println!("{}", choice.message.content);
    }

    Ok(())
}

async fn optimize_contract(client: &Client, file: &str, output: Option<&str>) -> Result<()> {
    println!("{} Optimizing contract...", "⚡".cyan());

    let code = std::fs::read_to_string(file).context("Failed to read contract file")?;

    let system_prompt = "You are a Soroban optimization expert. Optimize the provided Soroban contract code for gas efficiency and performance while maintaining the same functionality. Return only the optimized code without markdown formatting.";

    let messages = vec![
        ChatCompletionRequestMessage::System(ChatCompletionRequestSystemMessage {
            content: system_prompt.to_string(),
            name: None,
        }),
        ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
            content: format!("Optimize this Soroban contract:\n\n{}", code),
            name: None,
        }),
    ];

    let request = CreateChatCompletionRequest {
        model: "gpt-4".to_string(),
        messages,
        ..Default::default()
    };

    let response = client.chat().create(request).await?;

    if let Some(choice) = response.choices.first() {
        let optimized_code = choice.message.content.trim();
        
        if let Some(output_path) = output {
            std::fs::write(output_path, optimized_code)
                .context("Failed to write optimized code to file")?;
            println!("{} Optimized contract saved to {}", "✓".green(), output_path);
        } else {
            println!("{}", "Optimized contract:".bold());
            println!("{}", optimized_code);
        }
    }

    Ok(())
}
