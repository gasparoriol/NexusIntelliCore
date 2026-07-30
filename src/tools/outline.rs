use anyhow::Result;
use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;

use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};
use crate::sanitizer;

fn role_hint_for(language: &str) -> &'static str {
    match language {
        "rust" => {
            "[Think like a Rust architect: map module seams, ownership boundaries, and AST shape.]"
        }
        "javascript" | "typescript" | "tsx" => {
            "[Think like a TypeScript/JavaScript architect: map module seams, data flow, and AST shape.]"
        }
        "python" => "[Think like a Python architect: map module seams, intent, and AST shape.]",
        "java" => "[Think like a Java architect: map service seams, contracts, and AST shape.]",
        "c" | "csharp" => {
            "[Think like a systems architect: map coupling points, boundaries, and AST shape.]"
        }
        _ => "[Think like an architect: map boundaries, intent, and AST shape.]",
    }
}

fn append_html_sections(out: &mut String, html_elements: &[crate::analyzer::HtmlElementInfo]) {
    let components: Vec<_> = html_elements
        .iter()
        .filter(|e| e.is_angular_component)
        .map(|e| e.tag_name.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let all_classes: Vec<_> = html_elements
        .iter()
        .flat_map(|e| e.class_names.iter())
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    if !components.is_empty() {
        out.push_str("## Angular Components Used\n");
        for component in &components {
            let _ = writeln!(out, "  {component}");
        }
        out.push('\n');
    }

    if !all_classes.is_empty() {
        out.push_str("## CSS Classes Referenced\n");
        for class_name in &all_classes {
            let _ = writeln!(out, "  .{class_name}");
        }
        out.push('\n');
    }
}

/// Outline for plain-text configuration files (`.properties`, `.yaml`, `.env`, …).
/// These have no tree-sitter grammar, so instead of an empty outline this lists
/// each key with sensitive values redacted via `sanitizer::sanitize_config_text`.
async fn render_config_outline(path: &Path, file_path: &str) -> Result<Value> {
    let path_for_read = path.to_path_buf();
    let source =
        match tokio::task::spawn_blocking(move || std::fs::read_to_string(&path_for_read)).await {
            Ok(Ok(content)) => content,
            Ok(Err(e)) => return Ok(error_response(format!("Cannot read file: {e}"))),
            Err(e) => return Ok(error_response(format!("Cannot read file: {e}"))),
        };

    let (sanitized, _redactions) = sanitizer::sanitize_config_text(&source);

    let mut out = String::new();
    let _ = writeln!(out, "# File outline: {file_path}");
    out.push_str("Language: config\n\n");
    out.push_str("## Configuration Keys (sensitive values redacted)\n");
    for line in sanitized.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        let _ = writeln!(out, "  {line}");
    }

    Ok(tool_response(vec![text_content(out)]))
}

pub(super) async fn get_file_outline(
    state: &crate::state::ServerState,
    file_path: &str,
) -> Result<Value> {
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {e}"))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied by .mcpignore policy: {file_path}\n\
             The file exists but its implementation cannot be exposed to the LLM.",
        ))]));
    }
    drop(index);

    if sanitizer::is_config_file(&path) {
        return render_config_outline(&path, file_path).await;
    }

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {e}"))),
    };

    let mut out = String::new();
    let _ = writeln!(out, "# File outline: {file_path}");
    let _ = writeln!(out, "Language: {}", analysis.language);
    out.push('\n');

    // Imports
    if !analysis.imports.is_empty() {
        out.push_str("## Imports\n");
        let policy = privacy_gateway::PrivacyPolicy::default();
        for imp in &analysis.imports {
            // Sanitize import strings (may contain internal hostnames, etc.)
            let (sanitized_import, _redactions) =
                privacy_gateway::sanitize_import(&imp.raw, &policy);
            let _ = writeln!(out, "  {sanitized_import}");
        }
        out.push('\n');
    }

    // Classes / structs / traits
    if !analysis.classes.is_empty() {
        out.push_str("## Types\n");
        for cls in &analysis.classes {
            let _ = writeln!(
                out,
                "  {} {} (lines {}-{})",
                cls.kind, cls.name, cls.start_line, cls.end_line
            );
        }
        out.push('\n');
    }

    // Functions
    if !analysis.functions.is_empty() {
        out.push_str("## Functions / Methods\n");
        for func in &analysis.functions {
            let canonical = if func.qualified_name.is_empty() {
                func.name.as_str()
            } else {
                func.qualified_name.as_str()
            };
            if func.is_strip_marked {
                let _ = writeln!(
                    out,
                    "  {canonical} | {} - [implementation restricted by @mcp-strip] (lines {}-{})",
                    func.signature, func.start_line, func.end_line
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {canonical} | {} (lines {}-{})",
                    func.signature, func.start_line, func.end_line
                );
            }
        }
        out.push_str("\nUse inspect_symbol with the canonical identifier shown before '|'.\n");
    }

    // CSS selectors
    if let Some(css_rules) = &analysis.css_rules {
        if !css_rules.is_empty() {
            out.push_str("## CSS Selectors\n");
            for rule in css_rules {
                let media = rule
                    .media_query
                    .as_deref()
                    .map(|q| format!(" [@media {q}]"))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  {} ({} props, lines {}-{}){media}",
                    rule.selector,
                    rule.properties.len(),
                    rule.start_line,
                    rule.end_line
                );
            }
            out.push('\n');
        }
    }

    // HTML elements
    if let Some(html_elements) = &analysis.html_elements {
        append_html_sections(&mut out, html_elements);
    }

    // Sanitize the entire outline through the Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_outline, _redactions) = privacy_gateway::sanitize_file_outline(&out, &policy);

    let role_hint = role_hint_for(analysis.language.as_str());
    let sanitized_outline = format!("{role_hint}\n{sanitized_outline}");

    Ok(tool_response(vec![text_content(sanitized_outline)]))
}
