use anyhow::Result;
use serde_json::Value;

use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

pub(super) async fn get_project_structure(
    state: &crate::state::ServerState,
    args: &Value,
) -> Result<Value> {
    let proj = if let Some(p) = args
        .get("project")
        .or_else(|| args.get("project_id"))
        .and_then(|v| v.as_str())
    {
        state.get_project(Some(p))?
    } else {
        state.default_project()?
    };
    let index = proj.index().await?;
    let summary = index.render_tree();

    let summary = format!(
        "[Think like a project architect: reason about layers, module seams, and cross-cutting boundaries.]\n{summary}"
    );

    // Sanitize structure output through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_summary, _redactions) = privacy_gateway::sanitize_output_text(&summary, &policy);

    Ok(tool_response(vec![text_content(sanitized_summary)]))
}
