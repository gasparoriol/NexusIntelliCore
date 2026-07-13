use anyhow::Result;
use std::path::PathBuf;

use crate::analyzer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PaginationMeta {
    pub total_files: usize,
    pub offset: usize,
    pub page_size: usize,
    pub has_next: bool,
}

pub(super) struct ProjectDocsData {
    pub root: PathBuf,
    pub project_name: String,
    pub all_files: Vec<PathBuf>,
    pub selected_files: Vec<PathBuf>,
    pub pagination: PaginationMeta,
    pub analyses: Vec<(PathBuf, analyzer::FileAnalysis)>,
    pub entrypoints: Vec<analyzer::Entrypoint>,
    pub inferred_cases: Vec<analyzer::InferredUseCase>,
}

pub(super) async fn collect_project_docs_data(
    state: &crate::state::ServerState,
    max_files: usize,
    file_offset: usize,
) -> Result<ProjectDocsData> {
    let index = state.index().await?;
    let root = state.root().to_path_buf();
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Project")
        .to_owned();

    let all_files = index.allowed_files.clone();
    drop(index);

    let mut sorted_files = all_files.clone();
    sorted_files.sort_by_key(|path| {
        path.strip_prefix(&root)
            .map(|rel| rel.components().count())
            .unwrap_or(usize::MAX)
    });

    let total_files = sorted_files.len();
    let offset = file_offset.min(total_files);
    let selected_files: Vec<PathBuf> = sorted_files
        .into_iter()
        .skip(offset)
        .take(max_files)
        .collect();
    let page_size = selected_files.len();
    let has_next = offset.saturating_add(page_size) < total_files;

    let mut analyses: Vec<(PathBuf, analyzer::FileAnalysis)> = Vec::new();
    for path in &selected_files {
        if let Ok(analysis) = state.get_analysis(path).await {
            analyses.push((path.clone(), analysis));
        }
    }

    let entrypoints = analyzer::detect_entrypoints(&analyses);
    let inferred_cases = analyzer::infer_use_cases(&analyses);

    Ok(ProjectDocsData {
        root,
        project_name,
        all_files,
        selected_files,
        pagination: PaginationMeta {
            total_files,
            offset,
            page_size,
            has_next,
        },
        analyses,
        entrypoints,
        inferred_cases,
    })
}

#[cfg(test)]
mod tests {
    use super::PaginationMeta;

    #[test]
    fn pagination_meta_has_next_when_more_files_remain() {
        let meta = PaginationMeta {
            total_files: 100,
            offset: 0,
            page_size: 50,
            has_next: true,
        };
        assert!(meta.has_next);
    }

    #[test]
    fn pagination_meta_no_next_on_last_page() {
        let meta = PaginationMeta {
            total_files: 100,
            offset: 50,
            page_size: 50,
            has_next: false,
        };
        assert!(!meta.has_next);
    }
}
