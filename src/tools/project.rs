use anyhow::Result;
use serde_json::Value;

use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

pub(super) async fn get_project_structure(state: &crate::state::ServerState) -> Result<Value> {
    let index = state.index().await?;
    let summary = index.render_tree();

    let summary = format!(
        "[Think like a project architect: reason about layers, module seams, and cross-cutting boundaries.]\n{summary}"
    );

    // Sanitize structure output through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_summary, _redactions) = privacy_gateway::sanitize_output_text(&summary, &policy);

    Ok(tool_response(vec![text_content(sanitized_summary)]))
}
