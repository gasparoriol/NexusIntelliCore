use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

use anyhow::{Context, Result};
use tokio::sync::RwLock;

use crate::analyzer;
use crate::indexer::FileIndex;

/// Global server state, initialised once at startup.
static STATE: OnceLock<ServerState> = OnceLock::new();

pub struct CachedAnalysis {
    pub mtime: SystemTime,
    pub analysis: analyzer::FileAnalysis,
}

pub struct ServerState {
    /// Canonical, absolute project root — immutable after init.
    root: PathBuf,
    /// File index, rebuildable on demand.
    index: RwLock<FileIndex>,
    /// Whether the index has been fully built at least once.
    index_ready: AtomicBool,
    /// AST cache, indexed by absolute path.
    ast_cache: RwLock<HashMap<PathBuf, CachedAnalysis>>,
}

impl ServerState {
    /// Initialise global state. Panics if called twice.
    pub fn init(raw_root: &str) -> Result<()> {
        let root = std::fs::canonicalize(raw_root)
            .with_context(|| format!("Cannot resolve root path: {}", raw_root))?;

        anyhow::ensure!(root.is_dir(), "Root path is not a directory: {:?}", root);

        let state = ServerState {
            index: RwLock::new(FileIndex::empty(&root)),
            root,
            index_ready: AtomicBool::new(false),
            ast_cache: RwLock::new(HashMap::new()),
        };

        STATE
            .set(state)
            .map_err(|_| anyhow::anyhow!("ServerState already initialised"))?;

        Ok(())
    }

    /// Get the global state reference.
    pub fn get() -> &'static ServerState {
        STATE
            .get()
            .expect("ServerState not initialised — call init() first")
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn index(&self) -> Result<tokio::sync::RwLockReadGuard<'_, FileIndex>> {
        self.ensure_index_ready().await?;
        Ok(self.index.read().await)
    }

    #[allow(dead_code)]
    pub async fn rebuild_index(&self) -> Result<()> {
        let new_index = FileIndex::build(&self.root)?;
        let mut lock = self.index.write().await;
        *lock = new_index;
        self.index_ready.store(true, Ordering::Release);
        Ok(())
    }

    async fn ensure_index_ready(&self) -> Result<()> {
        if self.index_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        // Serialise the first build behind the write lock.
        let mut lock = self.index.write().await;
        if self.index_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        let root = self.root.clone();
        let built = tokio::task::spawn_blocking(move || FileIndex::build(&root)).await??;
        *lock = built;
        self.index_ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Validate that `requested` is a descendant of the project root.
    /// Returns the canonicalised path or an error.
    pub fn validate_path(&self, requested: &Path) -> Result<PathBuf> {
        let canonical = std::fs::canonicalize(requested)
            .with_context(|| format!("Path does not exist or is inaccessible: {:?}", requested))?;

        anyhow::ensure!(
            canonical.starts_with(&self.root),
            "Access denied: {:?} is outside the project root {:?}",
            requested,
            self.root
        );

        Ok(canonical)
    }

    /// Get a cached analysis or parse fresh if stale/missing.
    pub async fn get_analysis(&self, path: &Path) -> Result<analyzer::FileAnalysis> {
        let metadata = tokio::fs::metadata(path).await?;
        let current_mtime = metadata.modified()?;

        // Check cache
        {
            let cache = self.ast_cache.read().await;
            if let Some(cached) = cache.get(path) {
                if cached.mtime == current_mtime {
                    return Ok(cached.analysis.clone());
                }
            }
        }

        // Cache miss or stale — parse fresh
        let path_clone = path.to_owned();
        let analysis =
            tokio::task::spawn_blocking(move || analyzer::analyze_file(&path_clone)).await??;

        // Store in cache
        {
            let mut cache = self.ast_cache.write().await;
            cache.insert(
                path.to_path_buf(),
                CachedAnalysis {
                    mtime: current_mtime,
                    analysis: analysis.clone(),
                },
            );
        }

        Ok(analysis)
    }
}
