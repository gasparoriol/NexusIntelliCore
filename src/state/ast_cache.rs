use crate::analyzer::{FileAnalysis, SharedMarkovPredictor};
use moka::future::Cache;
use std::path::{Path, PathBuf};

/// A Markov-aware AST cache wrapper around `moka::future::Cache`.
///
/// It correlates cached `FileAnalysis` entries with observed Tree-sitter
/// node transitions in `SharedMarkovPredictor`.
#[allow(dead_code)]
#[derive(Clone)]
pub struct MarkovAstCache {
    cache: Cache<PathBuf, FileAnalysis>,
    predictor: SharedMarkovPredictor,
}

#[allow(dead_code)]
impl MarkovAstCache {
    pub fn new(capacity: usize, predictor: SharedMarkovPredictor) -> Self {
        let cache = Cache::builder().max_capacity(capacity as u64).build();
        Self { cache, predictor }
    }

    pub async fn get(&self, path: &Path) -> Option<FileAnalysis> {
        self.cache.get(path).await
    }

    pub async fn insert(&self, path: PathBuf, analysis: FileAnalysis) {
        self.cache.insert(path, analysis).await;
    }

    pub async fn invalidate(&self, path: &Path) {
        self.cache.invalidate(path).await;
    }

    pub fn predictor(&self) -> &SharedMarkovPredictor {
        &self.predictor
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}
