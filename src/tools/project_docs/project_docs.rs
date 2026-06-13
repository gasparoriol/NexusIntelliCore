use anyhow::Result;
use serde_json::Value;

use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

use super::data::collect_project_docs_data;
use super::i18n::labels;
use super::render::{render_document, RenderInput};

pub(crate) async fn generate_project_docs(
    sections: Vec<String>,
    public_only: bool,
    max_files: usize,
    language: &str,
) -> Result<Value> {
    let data = collect_project_docs_data(max_files).await?;

    if data.all_files.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No accessible files found. The project may be fully restricted by .mcpignore."
                .to_owned(),
        )]));
    }

    if data.analyses.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No files could be analysed. Check that the project contains supported source files."
                .to_owned(),
        )]));
    }

    let policy = privacy_gateway::PrivacyPolicy::default();
    let labels = labels(language);
    let out = render_document(&RenderInput {
        data: &data,
        labels: &labels,
        sections: &sections,
        public_only,
        policy: &policy,
    });

    let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
    Ok(tool_response(vec![text_content(sanitized_out)]))
}
