use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use crate::linter::render_lint_summary_scoped;
use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};
use crate::sanitizer;

const INSPECT_SYMBOL_LINT_MAX_ITEMS: usize = 5;

pub(super) async fn inspect_symbol(
    file_path: &str,
    symbol_name: &str,
    match_mode: &str,
    return_all_matches: bool,
    signature_hint: Option<&str>,
) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {e}"))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied: {file_path} is protected by .mcpignore.\n\
             The symbol '{symbol_name}' exists but cannot be inspected."
        ))]));
    }
    drop(index);

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {e}"))),
    };

    let mut matches: Vec<_> = match match_mode {
        "simple" => analysis
            .functions
            .iter()
            .filter(|f| f.name == symbol_name)
            .collect(),
        "qualified" => analysis
            .functions
            .iter()
            .filter(|f| f.qualified_name == symbol_name)
            .collect(),
        // auto: if caller provides a qualified-looking symbol, use qualified mode.
        // Otherwise try simple mode first, then qualified fallback.
        _ => {
            let looks_qualified = symbol_name.contains('.') || symbol_name.contains("::");
            if looks_qualified {
                analysis
                    .functions
                    .iter()
                    .filter(|f| f.qualified_name == symbol_name)
                    .collect()
            } else {
                let simple_matches: Vec<_> = analysis
                    .functions
                    .iter()
                    .filter(|f| f.name == symbol_name)
                    .collect();
                if simple_matches.is_empty() {
                    analysis
                        .functions
                        .iter()
                        .filter(|f| f.qualified_name == symbol_name)
                        .collect()
                } else {
                    simple_matches
                }
            }
        }
    };

    if let Some(hint) = signature_hint.map(str::trim).filter(|s| !s.is_empty()) {
        let hint_lc = hint.to_ascii_lowercase();
        matches.retain(|f| {
            f.normalized_signature
                .as_deref()
                .unwrap_or(f.signature.as_str())
                .to_ascii_lowercase()
                .contains(&hint_lc)
        });
    }

    if matches.is_empty() {
        let available: Vec<_> = analysis
            .functions
            .iter()
            .map(|f| f.qualified_name.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        return Ok(tool_response(vec![text_content(format!(
            "Symbol '{}' not found in {}.\n\
             match_mode='{}'.{}\n\
             Available functions: {}",
            symbol_name,
            file_path,
            match_mode,
            signature_hint
                .map(|h| format!(" signature_hint='{h}'"))
                .unwrap_or_default(),
            available.join(", ")
        ))]));
    }

    if matches.len() > 1 && !return_all_matches {
        let candidates = matches
            .iter()
            .map(|f| {
                json!({
                    "qualified_name": f.qualified_name,
                    "signature": f.signature,
                    "start_line": f.start_line,
                    "end_line": f.end_line
                })
            })
            .collect::<Vec<_>>();

        let payload = json!({
            "status": "ambiguous",
            "symbol": symbol_name,
            "file_path": file_path,
            "match_mode": match_mode,
            "signature_hint": signature_hint,
            "message": "Multiple symbol matches found. Use a qualified symbol, a signature_hint, or set return_all_matches=true.",
            "candidates": candidates
        });

        return Ok(tool_response(vec![text_content(payload.to_string())]));
    }

    let policy = privacy_gateway::PrivacyPolicy::default();
    let strip_placeholder = state
        .security_config()
        .custom_strip_placeholder
        .clone()
        .unwrap_or_else(|| sanitizer::DEFAULT_STRIP_PLACEHOLDER.to_string());
    let mut inspected = Vec::with_capacity(matches.len());
    for func in &matches {
        let body_for_sanitization = if func.is_strip_marked {
            if let Some(range) = func.body_byte_range {
                sanitizer::strip_body_by_range(
                    &func.body_source,
                    range,
                    &analysis.language,
                    &strip_placeholder,
                )
            } else {
                #[allow(deprecated)]
                {
                    sanitizer::strip_function_body_with_placeholder(
                        &func.body_source,
                        &analysis.language,
                        &strip_placeholder,
                    )
                }
            }
        } else {
            func.body_source.clone()
        };

        let (sanitized_code, redactions) = privacy_gateway::sanitize_function_source(
            &body_for_sanitization,
            &func.signature,
            &analysis.language,
            &policy,
        );

        inspected.push(json!({
            "qualified_name": func.qualified_name,
            "signature": func.signature,
            "start_line": func.start_line,
            "end_line": func.end_line,
            "source": sanitized_code,
            "redactions": redactions,
        }));
    }

    if return_all_matches {
        let payload = json!({
            "status": "ok",
            "symbol": symbol_name,
            "file_path": file_path,
            "match_mode": match_mode,
            "signature_hint": signature_hint,
            "count": inspected.len(),
            "matches": inspected
        });
        return Ok(tool_response(vec![text_content(payload.to_string())]));
    }

    let item = &inspected[0];
    let qualified_name = item["qualified_name"].as_str().unwrap_or(symbol_name);
    let start_line = item["start_line"].as_u64().unwrap_or(0);
    let end_line = item["end_line"].as_u64().unwrap_or(0);
    let source = item["source"].as_str().unwrap_or("");
    let mut out = format!(
        "// Symbol: {qualified_name} in {file_path}\n// Lines {start_line}-{end_line}\n\n{source}"
    );

    if let Some(redactions) = item["redactions"].as_array() {
        if !redactions.is_empty() {
            let list = redactions
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                out,
                "\n\n// ⚠ MCP Privacy Gateway: the following were redacted: {list}"
            );
        }
    }

    let role_hint = match analysis.language.as_str() {
        "rust" => "\n\n[Think like a Rust architect: explain control flow, ownership, and pre/postconditions.]",
        "javascript" | "typescript" | "tsx" => {
            "\n\n[Think like a TypeScript/JavaScript architect: explain control flow, module contracts, and pre/postconditions.]"
        }
        "python" => "\n\n[Think like a Python architect: explain control flow, intent, and pre/postconditions.]",
        "java" => "\n\n[Think like a Java architect: explain control flow, service contracts, and pre/postconditions.]",
        "c" | "csharp" => "\n\n[Think like a systems architect: explain control flow, coupling, and pre/postconditions.]",
        _ => "\n\n[Think like an architect: explain control flow, contracts, and pre/postconditions.]",
    };
    out.push_str(role_hint);

    let state = crate::state::ServerState::get();
    if state.lint_pool().enabled() {
        let lint_result = state.lint_pool().get_or_schedule(&path, &analysis).await;
        let selected = matches[0];
        if let Some(summary) = render_lint_summary_scoped(
            &lint_result,
            selected.start_line,
            selected.end_line,
            INSPECT_SYMBOL_LINT_MAX_ITEMS,
        ) {
            out.push_str(&summary);
        }
    }

    Ok(tool_response(vec![text_content(out)]))
}
