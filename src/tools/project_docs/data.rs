use anyhow::Result;
use std::path::PathBuf;

use crate::analyzer;

pub(super) struct ProjectDocsData {
    pub root: PathBuf,
    pub project_name: String,
    pub all_files: Vec<PathBuf>,
    pub selected_files: Vec<PathBuf>,
    pub analyses: Vec<(PathBuf, analyzer::FileAnalysis)>,
    pub entrypoints: Vec<analyzer::Entrypoint>,
    pub inferred_cases: Vec<analyzer::InferredUseCase>,
}

pub(super) async fn collect_project_docs_data(max_files: usize) -> Result<ProjectDocsData> {
    let state = crate::state::ServerState::get();
    let index = state.index().await?;
    let root = state.root().to_path_buf();
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Project")
        .to_owned();

    let all_files = index.allowed_files.clone();
    drop(index);

    let mut selected_files = all_files.clone();
    selected_files.sort_by_key(|path| {
        path.strip_prefix(&root)
            .map(|rel| rel.components().count())
            .unwrap_or(usize::MAX)
    });
    selected_files.truncate(max_files);

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
        analyses,
        entrypoints,
        inferred_cases,
    })
}
