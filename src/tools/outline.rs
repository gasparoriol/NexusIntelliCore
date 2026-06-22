use anyhow::Result;
use serde_json::Value;
use std::path::Path;

use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

pub(super) async fn get_file_outline(file_path: &str) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {}", e))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied by .mcpignore policy: {}\n\
             The file exists but its implementation cannot be exposed to the LLM.",
            file_path
        ))]));
    }
    drop(index);

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {}", e))),
    };

    let mut out = String::new();
    out.push_str(&format!(
        "# File outline: {}\nLanguage: {}\n\n",
        file_path, analysis.language
    ));

    // Imports
    if !analysis.imports.is_empty() {
        out.push_str("## Imports\n");
        let policy = privacy_gateway::PrivacyPolicy::default();
        for imp in &analysis.imports {
            // Sanitize import strings (may contain internal hostnames, etc.)
            let (sanitized_import, _redactions) =
                privacy_gateway::sanitize_import(&imp.raw, &policy);
            out.push_str(&format!("  {}\n", sanitized_import));
        }
        out.push('\n');
    }

    // Classes / structs / traits
    if !analysis.classes.is_empty() {
        out.push_str("## Types\n");
        for cls in &analysis.classes {
            out.push_str(&format!(
                "  {} {} (lines {}-{})\n",
                cls.kind, cls.name, cls.start_line, cls.end_line
            ));
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
                out.push_str(&format!(
                    "  {} | {} — [implementation restricted by @mcp-strip] (lines {}-{})\n",
                    canonical, func.signature, func.start_line, func.end_line
                ));
            } else {
                out.push_str(&format!(
                    "  {} | {} (lines {}-{})\n",
                    canonical, func.signature, func.start_line, func.end_line
                ));
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
                    .map(|q| format!(" [@media {}]", q))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  {} ({} props, lines {}-{}){}\n",
                    rule.selector,
                    rule.properties.len(),
                    rule.start_line,
                    rule.end_line,
                    media
                ));
            }
            out.push('\n');
        }
    }

    // HTML elements
    if let Some(html_elements) = &analysis.html_elements {
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
            .map(|s| s.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        if !components.is_empty() {
            out.push_str("## Angular Components Used\n");
            for c in &components {
                out.push_str(&format!("  {}\n", c));
            }
            out.push('\n');
        }
        if !all_classes.is_empty() {
            out.push_str("## CSS Classes Referenced\n");
            for cls in &all_classes {
                out.push_str(&format!("  .{}\n", cls));
            }
            out.push('\n');
        }
    }

    // Sanitize the entire outline through the Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_outline, _redactions) = privacy_gateway::sanitize_file_outline(&out, &policy);

    let role_hint = match analysis.language.as_str() {
        "rust" => {
            "[Think like a Rust architect: map module seams, ownership boundaries, and AST shape.]"
        }
        "javascript" | "typescript" | "tsx" => {
            "[Think like a TypeScript/JavaScript architect: map module seams, data flow, and AST shape.]"
        }
        "python" => "[Think like a Python architect: map module seams, intent, and AST shape.]",
        "java" => "[Think like a Java architect: map service seams, contracts, and AST shape.]",
        "c" | "csharp" => "[Think like a systems architect: map coupling points, boundaries, and AST shape.]",
        _ => "[Think like an architect: map boundaries, intent, and AST shape.]",
    };
    let sanitized_outline = format!("{}\n{}", role_hint, sanitized_outline);

    Ok(tool_response(vec![text_content(sanitized_outline)]))
}
