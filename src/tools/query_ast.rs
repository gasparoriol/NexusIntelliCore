use anyhow::Result;
use serde_json::json;
use serde_json::Value;
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

pub(super) async fn query_ast(
    state: &crate::state::ServerState,
    file_path: &str,
    query_source: &str,
) -> Result<Value> {
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {e}"))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied: {file_path} is protected by .mcpignore."
        ))]));
    }
    drop(index);

    let Some(grammar) = analyzer::detect_grammar(&path) else {
        return Ok(error_response(format!(
            "Unsupported language for file: {file_path}"
        )));
    };
    let Some(ts_lang) = grammar.tree_sitter_language() else {
        return Ok(error_response(format!(
            "No tree-sitter grammar available for language '{}'",
            grammar.name()
        )));
    };

    let path_for_read = path.clone();
    let source =
        match tokio::task::spawn_blocking(move || std::fs::read_to_string(&path_for_read)).await {
            Ok(Ok(content)) => content,
            Ok(Err(e)) => return Ok(error_response(format!("Cannot read file: {e}"))),
            Err(e) => return Ok(error_response(format!("Cannot read file: {e}"))),
        };

    let mut parser = Parser::new();
    if parser.set_language(&ts_lang).is_err() {
        return Ok(error_response(format!(
            "Failed to initialize parser for language '{}'",
            grammar.name()
        )));
    }

    let Some(tree) = parser.parse(&source, None) else {
        return Ok(error_response("Failed to parse source file"));
    };

    let query = match Query::new(&ts_lang, query_source) {
        Ok(q) => q,
        Err(e) => return Ok(error_response(format!("Invalid tree-sitter query: {e}"))),
    };

    let capture_names = query.capture_names();
    let policy = privacy_gateway::PrivacyPolicy::default();
    let mut cursor = QueryCursor::new();
    let mut captures = Vec::new();

    for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
        for cap in m.captures {
            let node = cap.node;
            let start = node.start_position();
            let end = node.end_position();
            let raw = source.get(node.byte_range()).unwrap_or_default();
            let (sanitized_text, redactions) = privacy_gateway::sanitize_output_text(raw, &policy);
            captures.push(json!({
                "capture": capture_names
                    .get(cap.index as usize)
                    .cloned()
                    .unwrap_or("capture"),
                "range": {
                    "start_line": start.row + 1,
                    "start_col": start.column + 1,
                    "end_line": end.row + 1,
                    "end_col": end.column + 1,
                },
                "text": sanitized_text,
                "redactions": redactions,
            }));
        }
    }

    let payload = json!({
        "status": "ok",
        "file_path": file_path,
        "language": grammar.name(),
        "query": query_source,
        "capture_count": captures.len(),
        "captures": captures,
    });

    Ok(tool_response(vec![text_content(payload.to_string())]))
}
