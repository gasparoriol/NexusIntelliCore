use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use tokio::sync::Semaphore;

use crate::analyzer::FileAnalysis;

use super::level1::run_tree_sitter_checks;
use super::level2::{external_unavailable_notice, run_external};
use super::{LintDiagnostic, LintResult};

#[derive(Clone)]
pub struct LintPool {
    enabled: bool,
    semaphore: Arc<Semaphore>,
    lint_cache: Cache<PathBuf, LintResult>,
    timeout: Duration,
    root: PathBuf,
}

impl LintPool {
    pub fn init(root: &Path) -> Self {
        let enabled = std::env::var("MCP_LINT_ENABLED")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
            .unwrap_or(false);

        let timeout = std::env::var("MCP_LINT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        Self {
            enabled,
            semaphore: Arc::new(Semaphore::new(2)),
            lint_cache: Cache::builder().max_capacity(256).build(),
            timeout,
            root: root.to_path_buf(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn get_or_schedule(&self, path: &Path, analysis: &FileAnalysis) -> LintResult {
        if !self.enabled {
            return self.build_result(path, analysis).await;
        }

        if let Some(cached) = self.lint_cache.get(path).await {
            return cached;
        }

        let result = self.build_result(path, analysis).await;
        self.lint_cache
            .insert(path.to_path_buf(), result.clone())
            .await;
        result
    }

    pub async fn run_sync(&self, path: &Path, analysis: &FileAnalysis) -> LintResult {
        let result = self.build_result(path, analysis).await;
        if self.enabled {
            self.lint_cache
                .insert(path.to_path_buf(), result.clone())
                .await;
        }
        result
    }

    async fn build_result(&self, path: &Path, analysis: &FileAnalysis) -> LintResult {
        let mut diagnostics = run_tree_sitter_checks(path, analysis);
        let mut sources = vec!["tree-sitter".to_string()];
        let mut error = None;

        if self.enabled {
            match self.semaphore.acquire().await {
                Ok(_permit) => {
                    match run_external(path, &self.root, self.timeout, &analysis.language).await {
                        Ok(external) => {
                            diagnostics.extend(external.diagnostics);
                            sources.extend(external.sources);
                            if error.is_none() {
                                error = external.error;
                            }
                        }
                        Err(err) => {
                            error = Some(err.to_string());
                        }
                    }
                }
                Err(_) => {
                    diagnostics.push(external_unavailable_notice());
                }
            }
        }

        diagnostics.sort_by_key(|diag| (diag.line, diag.column, diag.source.clone()));

        LintResult {
            diagnostics,
            sources,
            error,
        }
    }
}

impl From<LintDiagnostic> for LintResult {
    fn from(diagnostic: LintDiagnostic) -> Self {
        Self {
            diagnostics: vec![diagnostic],
            sources: vec!["tree-sitter".to_string()],
            error: None,
        }
    }
}
