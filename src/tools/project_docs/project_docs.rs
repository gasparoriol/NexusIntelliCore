use anyhow::Result;
use serde_json::Value;

use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

use super::data::{collect_project_docs_data, PaginationMeta};
use super::i18n::labels;
use super::render::{render_document, RenderInput};

pub(crate) async fn generate_project_docs(
    state: &crate::state::ServerState,
    sections: Vec<String>,
    public_only: bool,
    max_files: usize,
    file_offset: usize,
    language: &str,
) -> Result<Value> {
    let data = collect_project_docs_data(state, max_files, file_offset).await?;

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
    let pagination_header = render_pagination_header(max_files, file_offset, data.pagination);
    let doc_body = render_document(&RenderInput {
        data: &data,
        labels: &labels,
        sections: &sections,
        public_only,
        policy: &policy,
    });
    let out = format!("{pagination_header}{doc_body}");

    let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
    Ok(tool_response(vec![text_content(sanitized_out)]))
}

fn render_pagination_header(
    max_files: usize,
    file_offset: usize,
    pagination: PaginationMeta,
) -> String {
    if !(pagination.total_files > max_files || file_offset > 0) {
        return String::new();
    }

    let start = pagination.offset.saturating_add(1);
    let end = pagination.offset.saturating_add(pagination.page_size);
    let next_hint = if pagination.has_next {
        format!(
            "> ▶ To see the next page, call `generate_project_docs` with `file_offset: {}`",
            pagination.offset.saturating_add(pagination.page_size)
        )
    } else {
        "> ✅ All files have been analysed.".to_owned()
    };

    format!(
        "> 📄 **Page**: files {}–{} of {} total\n{}\n\n",
        start, end, pagination.total_files, next_hint
    )
}

#[cfg(test)]
mod tests {
    use super::{render_pagination_header, PaginationMeta};

    #[test]
    fn pagination_header_is_empty_when_all_files_fit_in_one_page() {
        let header = render_pagination_header(
            50,
            0,
            PaginationMeta {
                total_files: 50,
                offset: 0,
                page_size: 50,
                has_next: false,
            },
        );

        assert!(header.is_empty());
    }

    #[test]
    fn pagination_header_contains_next_offset_hint_when_has_next() {
        let header = render_pagination_header(
            50,
            0,
            PaginationMeta {
                total_files: 200,
                offset: 0,
                page_size: 50,
                has_next: true,
            },
        );

        assert!(header.contains("file_offset: 50"));
    }
}
