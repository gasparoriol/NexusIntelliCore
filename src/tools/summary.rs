use anyhow::Result;
use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

fn append_doc_lines(out: &mut String, doc: &str, policy: &privacy_gateway::PrivacyPolicy) {
    let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, policy);
    for line in clean.lines() {
        let _ = writeln!(out, "  {line}");
    }
}

fn append_function_section(
    out: &mut String,
    title: &str,
    functions: &[&analyzer::FunctionInfo],
    policy: &privacy_gateway::PrivacyPolicy,
) {
    if functions.is_empty() {
        return;
    }

    let _ = writeln!(out, "## {title} ({})", functions.len());
    for func in functions {
        if func.is_strip_marked {
            let _ = writeln!(
                out,
                "### {}  [lines {}-{}]\n  [implementation restricted by @mcp-strip]",
                func.signature, func.start_line, func.end_line
            );
        } else {
            let _ = writeln!(
                out,
                "### {}  [lines {}-{}]",
                func.signature, func.start_line, func.end_line
            );
        }

        if let Some(ref doc) = func.doc_comment {
            append_doc_lines(out, doc, policy);
        } else {
            out.push_str("  (no documentation)\n");
        }
        out.push('\n');
    }
}

fn append_type_section(
    out: &mut String,
    title: &str,
    classes: &[&analyzer::ClassInfo],
    policy: &privacy_gateway::PrivacyPolicy,
) {
    if classes.is_empty() {
        return;
    }

    let _ = writeln!(out, "## {title} ({})", classes.len());
    for cls in classes {
        let _ = writeln!(
            out,
            "### {} {}  [lines {}-{}]",
            cls.kind, cls.name, cls.start_line, cls.end_line
        );
        if let Some(ref doc) = cls.doc_comment {
            append_doc_lines(out, doc, policy);
        } else {
            out.push_str("  (no documentation)\n");
        }
        out.push('\n');
    }
}

fn append_import_sections(
    out: &mut String,
    imports: &[analyzer::ImportInfo],
    policy: &privacy_gateway::PrivacyPolicy,
) {
    if imports.is_empty() {
        return;
    }

    let mut external: Vec<String> = Vec::new();
    let mut internal: Vec<String> = Vec::new();

    for imp in imports {
        let (clean, _) = privacy_gateway::sanitize_import(&imp.raw, policy);
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
            let _ = writeln!(out, "  {imp}");
        }
        out.push('\n');
    }

    if !internal.is_empty() {
        out.push_str("## Internal imports\n");
        for imp in &internal {
            let _ = writeln!(out, "  {imp}");
        }
        out.push('\n');
    }
}

pub(super) async fn get_module_summary(
    state: &crate::state::ServerState,
    file_path: &str,
    public_only: bool,
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

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {e}"))),
    };

    let policy = privacy_gateway::PrivacyPolicy::default();
    let mut out = String::new();

    // --- Header ---
    let _ = writeln!(out, "# Module summary: {file_path}");
    let _ = writeln!(out, "Language: {}", analysis.language);
    out.push('\n');

    // --- Module-level doc ---
    if let Some(ref mdoc) = analysis.module_doc {
        out.push_str("## Module documentation\n");
        append_doc_lines(&mut out, mdoc, &policy);
        out.push('\n');
    }

    // --- Functions ---
    let public_fns: Vec<_> = analysis.functions.iter().filter(|f| f.is_public).collect();
    let private_fns: Vec<_> = analysis.functions.iter().filter(|f| !f.is_public).collect();

    append_function_section(&mut out, "Public functions", &public_fns, &policy);

    if !private_fns.is_empty() && !public_only {
        append_function_section(&mut out, "Private functions", &private_fns, &policy);
    } else if !private_fns.is_empty() && public_only {
        let names: Vec<&str> = private_fns.iter().map(|f| f.name.as_str()).collect();
        let _ = writeln!(
            out,
            "## Private functions ({}) - hidden (public_only=true)\n  {}\n",
            private_fns.len(),
            names.join(", ")
        );
    }

    if analysis.functions.is_empty() {
        out.push_str("## Functions\n  (none found)\n\n");
    }

    // --- Types ---
    let public_types: Vec<_> = analysis.classes.iter().filter(|c| c.is_public).collect();
    let private_types: Vec<_> = analysis.classes.iter().filter(|c| !c.is_public).collect();

    append_type_section(&mut out, "Public types", &public_types, &policy);

    if !private_types.is_empty() && !public_only {
        append_type_section(&mut out, "Private types", &private_types, &policy);
    } else if !private_types.is_empty() && public_only {
        let names: Vec<&str> = private_types.iter().map(|c| c.name.as_str()).collect();
        let _ = writeln!(
            out,
            "## Private types ({}) - hidden (public_only=true)\n  {}\n",
            private_types.len(),
            names.join(", ")
        );
    }

    // --- Imports: split external vs internal ---
    append_import_sections(&mut out, &analysis.imports, &policy);

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
