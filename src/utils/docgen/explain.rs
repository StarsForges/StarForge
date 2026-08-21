//! Function explanations: deterministic templates by default, AI as opt-in.
//!
//! The knowledge base must remain useful without any network access, so
//! every function always receives a rule-based [`template_explanation`].
//! When the operator passes an explicit opt-in flag *and* an API key is
//! configured, [`maybe_generate_ai_explanations`] augments individual
//! functions with provider-written narratives. Prompts and responses are
//! redacted, failures degrade to the template, and AI usage is recorded via
//! the shared telemetry helper.

use crate::utils::docgen::model::{ExplanationSource, FunctionDoc, KnowledgeBase};
use crate::utils::docgen::redact::redact_text;
use anyhow::Result;
use async_openai::{
    config::OpenAIConfig,
    types::{ChatCompletionRequestMessage, CreateChatCompletionRequest, Role},
    Client,
};
use std::env;

/// Upper bound on AI calls per generation run so a large contract cannot
/// silently rack up a large bill. Functions beyond the cap keep their
/// template explanations.
pub const MAX_AI_FUNCTIONS: usize = 25;

/// Builds the deterministic explanation for a single function. Pure and
/// offline — this is what ships unless AI assistance is explicitly enabled.
pub fn template_explanation(f: &FunctionDoc) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "`{}` {}",
        f.name,
        match f.doc.as_deref() {
            Some(doc) => format!("— {doc}"),
            None => "is part of the contract's public interface.".to_string(),
        }
    ));

    if f.params.is_empty() {
        lines.push("It takes no parameters.".to_string());
    } else {
        let params = f
            .params
            .iter()
            .map(|p| format!("{} ({})", p.name, p.type_name))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("Parameters: {params}."));
    }

    match f.outputs.as_slice() {
        [] => lines.push("It returns nothing.".to_string()),
        [only] if only == "()" => lines.push("It returns nothing.".to_string()),
        [only] => lines.push(format!("It returns `{only}`.")),
        many => lines.push(format!("It returns ({}).", many.join(", "))),
    }

    if f.outputs.iter().any(|o| o.contains("Result")) {
        lines.push(
            "The Result return type means failures surface as contract errors rather than \
             panics; handle the error variant at the call site."
                .to_string(),
        );
    }
    if f.params.iter().any(|p| p.type_name == "Address") {
        lines.push(
            "Address parameters are authenticated by the host environment; ensure the \
             caller is the party intended to authorize this operation."
                .to_string(),
        );
    }

    lines.join("\n")
}

/// Fills in template explanations for every function that lacks one.
pub fn apply_template_explanations(kb: &mut KnowledgeBase) {
    for f in &mut kb.functions {
        if f.explanation.is_none() {
            f.explanation = Some(template_explanation(f));
            f.explanation_source = Some(ExplanationSource::Template);
        }
    }
}

/// Attempts AI explanations for undocumented or template-explained
/// functions. Returns `Ok(None)` when no API key is configured (never a hard
/// failure), so callers can proceed with templates. Individual function
/// failures are skipped, not fatal.
pub async fn maybe_generate_ai_explanations(
    kb: &KnowledgeBase,
    model: &str,
) -> Result<Option<Vec<(String, String)>>> {
    let api_key = match env::var("OPENAI_API_KEY").or_else(|_| env::var("STARFORGE_AI_API_KEY")) {
        Ok(key) => key,
        Err(_) => return Ok(None),
    };

    let client = Client::with_config(OpenAIConfig::new().with_api_key(api_key));
    let mut explanations = Vec::new();
    for f in kb.functions.iter().take(MAX_AI_FUNCTIONS) {
        // A per-function failure should not block documentation of the rest.
        if let Ok(text) = generate_ai_explanation(&client, f, model).await {
            explanations.push((f.id.clone(), text));
        }
    }
    Ok(Some(explanations))
}

async fn generate_ai_explanation(
    client: &Client<OpenAIConfig>,
    f: &FunctionDoc,
    model: &str,
) -> Result<String> {
    let params = f
        .params
        .iter()
        .map(|p| format!("- {}: {}", p.name, p.type_name))
        .collect::<Vec<_>>()
        .join("\n");

    let prompt = format!(
        "Explain the Soroban contract function `{}` with signature `{}`.\n\n\
         Parameters:\n{}\n\
         Returns: {}\n\
         Author doc comment: {}\n\n\
         Write 2-4 sentences for contract integrators covering: what the function does, \
         when to call it, and any authorization or failure-mode caveats visible from the \
         signature. Do not invent behaviour that is not implied by the signature.",
        f.name,
        f.signature,
        params,
        f.outputs.join(", "),
        f.doc.as_deref().unwrap_or("(none provided)"),
    );

    let system_prompt = "You are a Soroban smart-contract documentation assistant. Be precise, \
         conservative, and concise; never fabricate storage layouts or guarantees.";

    let messages = vec![
        ChatCompletionRequestMessage {
            role: Role::System,
            content: Some(system_prompt.to_string()),
            name: None,
            function_call: None,
        },
        ChatCompletionRequestMessage {
            role: Role::User,
            content: Some(redact_text(&prompt, None)),
            name: None,
            function_call: None,
        },
    ];

    let request = CreateChatCompletionRequest {
        model: model.to_string(),
        messages,
        ..Default::default()
    };

    // Direct provider call — lib-side modules (see
    // `utils/compliance/ai_assist.rs`) talk to the client directly rather
    // than through the bin-crate telemetry helper.
    let response = client
        .chat()
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("docgen AI explanation request failed: {e}"))?;

    let text = response
        .choices
        .first()
        .and_then(|c| c.message.content.as_deref())
        .unwrap_or_default()
        .trim();

    anyhow::ensure!(
        !text.is_empty(),
        "AI provider returned an empty explanation for `{}`",
        f.name
    );
    Ok(redact_text(text, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::docgen::extract::{build_kb, ExtractOptions};
    use crate::utils::docgen::fixtures::{build_spec_wasm, sample_entries};
    use std::path::Path;

    fn sample_kb() -> KnowledgeBase {
        build_kb(
            Path::new("token.wasm"),
            &build_spec_wasm(&sample_entries()),
            &ExtractOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn template_explanation_covers_signature_facts() {
        let kb = sample_kb();
        let transfer = kb.find_function("fn:transfer").unwrap();
        let text = template_explanation(transfer);
        assert!(text.contains("`transfer`"), "{text}");
        assert!(text.contains("from (Address)"), "{text}");
        assert!(text.contains("returns `bool`"), "{text}");
        assert!(text.contains("authenticated"), "{text}");
    }

    #[test]
    fn template_explanation_handles_no_params_and_void_return() {
        let f = FunctionDoc {
            id: "fn:mint".to_string(),
            anchor: String::new(),
            name: "mint".to_string(),
            signature: "() -> ()".to_string(),
            doc: None,
            params: vec![],
            outputs: vec![],
            examples: vec![],
            content_hash: String::new(),
            explanation: None,
            explanation_source: None,
        };
        let text = template_explanation(&f);
        assert!(text.contains("takes no parameters"));
        assert!(text.contains("returns nothing"));
        assert!(text.contains("public interface"));
    }

    #[test]
    fn apply_template_is_idempotent_and_marks_source() {
        let mut kb = sample_kb();
        apply_template_explanations(&mut kb);
        let first: Vec<_> = kb.functions.iter().map(|f| f.explanation.clone()).collect();
        assert!(kb
            .functions
            .iter()
            .all(|f| f.explanation_source == Some(ExplanationSource::Template)));

        apply_template_explanations(&mut kb);
        let second: Vec<_> = kb.functions.iter().map(|f| f.explanation.clone()).collect();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn missing_api_key_yields_none_not_error() {
        // Test-only env var clearing, scoped to this process; no other test
        // in this crate reads these two variables.
        env::remove_var("OPENAI_API_KEY");
        env::remove_var("STARFORGE_AI_API_KEY");
        let result = maybe_generate_ai_explanations(&sample_kb(), "gpt-4")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
