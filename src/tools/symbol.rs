use anyhow::Result;
use serde_json::Value;
use std::path::Path;

use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};
use crate::sanitizer;

pub(super) async fn inspect_symbol(file_path: &str, symbol_name: &str) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {}", e))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied: {} is protected by .mcpignore.\n\
             The symbol '{}' exists but cannot be inspected.",
            file_path, symbol_name
        ))]));
    }
    drop(index);

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {}", e))),
    };

    let func = match analysis.functions.iter().find(|f| f.name == symbol_name) {
        Some(f) => f,
        None => {
            return Ok(tool_response(vec![text_content(format!(
                "Symbol '{}' not found in {}.\n\
                 Available functions: {}",
                symbol_name,
                file_path,
                analysis
                    .functions
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))]))
        }
    };

    // Phase 4 — Apply Privacy Gateway sanitization pipeline.
    // If the function is strip-marked and we have an AST-derived body range,
    // use strip_body_by_range for precise, false-positive-free stripping.
    // Otherwise fall through to sanitize_function_source which uses regex.
    let body_for_sanitization = if func.is_strip_marked {
        if let Some(range) = func.body_byte_range {
            sanitizer::strip_body_by_range(&func.body_source, range)
        } else {
            func.body_source.clone()
        }
    } else {
        func.body_source.clone()
    };
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_code, redactions) = privacy_gateway::sanitize_function_source(
        &body_for_sanitization,
        &func.signature,
        &analysis.language,
        &policy,
    );

    let mut out = format!(
        "// Symbol: {} in {}\n// Lines {}-{}\n\n{}",
        symbol_name, file_path, func.start_line, func.end_line, sanitized_code
    );

    if !redactions.is_empty() {
        out.push_str(&format!(
            "\n\n// ⚠ MCP Privacy Gateway: the following were redacted: {}",
            redactions.join(", ")
        ));
    }

    Ok(tool_response(vec![text_content(out)]))
}
