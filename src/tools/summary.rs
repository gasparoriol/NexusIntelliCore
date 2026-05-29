use anyhow::Result;
use serde_json::Value;
use std::path::Path;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

pub(super) async fn get_module_summary(file_path: &str, public_only: bool) -> Result<Value> {
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

    let policy = privacy_gateway::PrivacyPolicy::default();
    let mut out = String::new();

    // --- Header ---
    out.push_str(&format!(
        "# Module summary: {}\nLanguage: {}\n\n",
        file_path, analysis.language
    ));

    // --- Module-level doc ---
    if let Some(ref mdoc) = analysis.module_doc {
        let (clean, _) = privacy_gateway::sanitize_doc_comment(mdoc, &policy);
        out.push_str("## Module documentation\n");
        for line in clean.lines() {
            out.push_str(&format!("  {}\n", line));
        }
        out.push('\n');
    }

    // --- Functions ---
    let public_fns: Vec<_> = analysis.functions.iter().filter(|f| f.is_public).collect();
    let private_fns: Vec<_> = analysis.functions.iter().filter(|f| !f.is_public).collect();

    if !public_fns.is_empty() {
        out.push_str(&format!("## Public functions ({})\n", public_fns.len()));
        for func in &public_fns {
            if func.is_strip_marked {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n  [implementation restricted by @mcp-strip]\n",
                    func.signature, func.start_line, func.end_line
                ));
            } else {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n",
                    func.signature, func.start_line, func.end_line
                ));
            }
            if let Some(ref doc) = func.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    }

    if !private_fns.is_empty() && !public_only {
        out.push_str(&format!("## Private functions ({})\n", private_fns.len()));
        for func in &private_fns {
            if func.is_strip_marked {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n  [implementation restricted by @mcp-strip]\n",
                    func.signature, func.start_line, func.end_line
                ));
            } else {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n",
                    func.signature, func.start_line, func.end_line
                ));
            }
            if let Some(ref doc) = func.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    } else if !private_fns.is_empty() && public_only {
        let names: Vec<&str> = private_fns.iter().map(|f| f.name.as_str()).collect();
        out.push_str(&format!(
            "## Private functions ({}) — hidden (public_only=true)\n  {}\n\n",
            private_fns.len(),
            names.join(", ")
        ));
    }

    if analysis.functions.is_empty() {
        out.push_str("## Functions\n  (none found)\n\n");
    }

    // --- Types ---
    let public_types: Vec<_> = analysis.classes.iter().filter(|c| c.is_public).collect();
    let private_types: Vec<_> = analysis.classes.iter().filter(|c| !c.is_public).collect();

    if !public_types.is_empty() {
        out.push_str(&format!("## Public types ({})\n", public_types.len()));
        for cls in &public_types {
            out.push_str(&format!(
                "### {} {}  [lines {}-{}]\n",
                cls.kind, cls.name, cls.start_line, cls.end_line
            ));
            if let Some(ref doc) = cls.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    }

    if !private_types.is_empty() && !public_only {
        out.push_str(&format!("## Private types ({})\n", private_types.len()));
        for cls in &private_types {
            out.push_str(&format!(
                "### {} {}  [lines {}-{}]\n",
                cls.kind, cls.name, cls.start_line, cls.end_line
            ));
            if let Some(ref doc) = cls.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    } else if !private_types.is_empty() && public_only {
        let names: Vec<&str> = private_types.iter().map(|c| c.name.as_str()).collect();
        out.push_str(&format!(
            "## Private types ({}) — hidden (public_only=true)\n  {}\n\n",
            private_types.len(),
            names.join(", ")
        ));
    }

    // --- Imports: split external vs internal ---
    if !analysis.imports.is_empty() {
        let mut external: Vec<String> = Vec::new();
        let mut internal: Vec<String> = Vec::new();

        for imp in &analysis.imports {
            let (clean, _) = privacy_gateway::sanitize_import(&imp.raw, &policy);
            // Use the semantic ImportKind set at extraction time.
            let is_internal = matches!(
                imp.kind,
                analyzer::ImportKind::InternalLocal | analyzer::ImportKind::InternalRestricted
            );
            if is_internal {
                internal.push(clean);
            } else {
                external.push(clean);
            }
        }

        if !external.is_empty() {
            out.push_str("## External imports\n");
            for imp in &external {
                out.push_str(&format!("  {}\n", imp));
            }
            out.push('\n');
        }
        if !internal.is_empty() {
            out.push_str("## Internal imports\n");
            for imp in &internal {
                out.push_str(&format!("  {}\n", imp));
            }
            out.push('\n');
        }
    }

    // Note for Python (V1 limitation)
    if analysis.language == "python" {
        out.push_str(
            "---\n\
             ⚠ Note: Python function docstrings (inside function bodies) are not \
             extracted in V1. Only `#`-style comments preceding the `def` line \
             are shown as documentation.\n",
        );
    }

    // Final sanitization pass on the entire output
    let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
    Ok(tool_response(vec![text_content(sanitized_out)]))
}
