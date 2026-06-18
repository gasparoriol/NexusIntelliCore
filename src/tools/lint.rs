use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

pub(super) async fn lint_file(file_path: &str) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {}", e))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied by .mcpignore policy: {}",
            file_path
        ))]));
    }
    drop(index);

    let analysis = match state.get_analysis(&path).await {
        Ok(analysis) => analysis,
        Err(e) => return Ok(error_response(format!("Analysis error: {}", e))),
    };

    let lint_result = state.lint_pool().run_sync(&path, &analysis).await;
    let summary = crate::linter::render_lint_summary(&lint_result)
        .unwrap_or_else(|| "\n\n// Lint: no diagnostics reported".to_string());

    state.invalidate_tool_cache_for_file(&path).await;

    let payload = json!({
        "file_path": file_path,
        "language": analysis.language,
        "enabled": state.lint_pool().enabled(),
        "diagnostics": lint_result.diagnostics,
        "sources": lint_result.sources,
        "summary": summary,
        "error": lint_result.error,
    });

    let policy = privacy_gateway::PrivacyPolicy::default();
    let result_str = serde_json::to_string_pretty(&payload).unwrap_or_default();
    let (sanitized, _) = privacy_gateway::sanitize_output_text(&result_str, &policy);

    Ok(tool_response(vec![text_content(sanitized)]))
}
