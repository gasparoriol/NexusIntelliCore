use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

use anyhow::{Context, Result};
use lru::LruCache;
use tokio::sync::RwLock;
use tracing::info;

use crate::analyzer;
use crate::indexer::FileIndex;

/// Default maximum number of entries in AST cache.
const DEFAULT_AST_CACHE_ENTRIES: usize = 256;

/// Environment variable to configure AST cache size.
const ENV_AST_CACHE_LIMIT: &str = "MCP_AST_CACHE_ENTRIES";

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
    /// AST cache with LRU eviction, indexed by absolute path.
    ast_cache: RwLock<LruCache<PathBuf, CachedAnalysis>>,
}

impl ServerState {
    /// Initialise global state. Panics if called twice.
    pub fn init(raw_root: &str) -> Result<()> {
        let root = std::fs::canonicalize(raw_root)
            .with_context(|| format!("Cannot resolve root path: {}", raw_root))?;

        anyhow::ensure!(root.is_dir(), "Root path is not a directory: {:?}", root);

        // Load AST cache limit from environment or use default
        let cache_limit = std::env::var(ENV_AST_CACHE_LIMIT)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .and_then(NonZeroUsize::new)
            .unwrap_or(NonZeroUsize::new(DEFAULT_AST_CACHE_ENTRIES).unwrap());

        if let Ok(limit_str) = std::env::var(ENV_AST_CACHE_LIMIT) {
            info!(
                "AST cache limit configured via {} = {}",
                ENV_AST_CACHE_LIMIT, limit_str
            );
        }

        let state = ServerState {
            index: RwLock::new(FileIndex::empty(&root)),
            root,
            index_ready: AtomicBool::new(false),
            ast_cache: RwLock::new(LruCache::new(cache_limit)),
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

        // Check cache — using write lock because LRU::get() updates position
        {
            let mut cache = self.ast_cache.write().await;
            if let Some(cached) = cache.get(path) {
                if cached.mtime == current_mtime {
                    return Ok(cached.analysis.clone());
                } else {
                    // Stale entry — remove it
                    cache.pop(path);
                }
            }
        }

        // Cache miss or stale — parse fresh
        let path_clone = path.to_owned();
        let analysis =
            tokio::task::spawn_blocking(move || analyzer::analyze_file(&path_clone)).await??;

        // Store in cache — LruCache::put() will evict oldest entry if at capacity
        {
            let mut cache = self.ast_cache.write().await;
            cache.put(
                path.to_path_buf(),
                CachedAnalysis {
                    mtime: current_mtime,
                    analysis: analysis.clone(),
                },
            );
        }

        Ok(analysis)
    }

    /// Clear the AST cache and rebuild the FileIndex.
    /// Used by refresh_index() tool.
    pub async fn refresh_index(&self) -> Result<(usize, usize)> {
        // Rebuild index
        let new_index = FileIndex::build(&self.root)?;
        let files_found = new_index.allowed_files.len() + new_index.restricted_files.len();

        // Replace index
        {
            let mut index = self.index.write().await;
            *index = new_index;
            self.index_ready.store(true, Ordering::Release);
        }

        // Clear AST cache
        let cleared_count = {
            let mut cache = self.ast_cache.write().await;
            let count = cache.len();
            cache.clear();
            count
        };

        Ok((files_found, cleared_count))
    }

    /// Get current cache statistics (debug-only).
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.ast_cache.read().await;
        (cache.len(), DEFAULT_AST_CACHE_ENTRIES)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    #[test]
    fn test_lru_cache_capacity() {
        // Verify that LRU cache respects its configured capacity
        let capacity = NonZeroUsize::new(3).unwrap();
        let cache: lru::LruCache<i32, String> = lru::LruCache::new(capacity);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.cap().get(), 3);
    }

    #[test]
    fn test_lru_eviction_on_overflow() {
        // When cache is full, inserting a new item evicts the least recently used
        let capacity = NonZeroUsize::new(3).unwrap();
        let mut cache: lru::LruCache<i32, String> = lru::LruCache::new(capacity);

        // Insert 3 items (fills cache)
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());
        cache.put(3, "three".to_string());

        assert_eq!(cache.len(), 3);

        // Insert 4th item — should evict item 1 (least recently used)
        cache.put(4, "four".to_string());

        assert_eq!(cache.len(), 3); // Still at capacity
        assert!(cache.get(&1).is_none()); // Item 1 was evicted
        assert!(cache.get(&4).is_some()); // Item 4 was inserted
    }

    #[test]
    fn test_lru_access_updates_position() {
        // Accessing an item via .get() makes it "most recently used"
        let capacity = NonZeroUsize::new(3).unwrap();
        let mut cache: lru::LruCache<i32, String> = lru::LruCache::new(capacity);

        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());
        cache.put(3, "three".to_string());

        // Access item 1 (makes it most recently used)
        let _ = cache.get(&1);

        // Insert item 4 — should evict item 2 (now LRU), NOT item 1
        cache.put(4, "four".to_string());

        assert!(cache.get(&1).is_some()); // Item 1 survives
        assert!(cache.get(&2).is_none()); // Item 2 was evicted
    }

    #[test]
    fn test_cached_analysis_struct() {
        // Verify CachedAnalysis can be created and has mtime field
        let mtime = SystemTime::now();
        let analysis = analyzer::FileAnalysis {
            language: "rust".to_string(),
            imports: vec![],
            classes: vec![],
            functions: vec![],
            string_literals: vec![],
            css_rules: None,
            html_elements: None,
        };

        let cached = CachedAnalysis {
            mtime,
            analysis: analysis.clone(),
        };

        assert_eq!(cached.analysis.language, "rust");
    }

    #[test]
    fn test_default_cache_limit_is_reasonable() {
        // DEFAULT_AST_CACHE_ENTRIES should be non-zero and not excessive
        assert!(DEFAULT_AST_CACHE_ENTRIES > 0);
        assert!(DEFAULT_AST_CACHE_ENTRIES <= 1000); // Reasonable upper bound
        assert_eq!(DEFAULT_AST_CACHE_ENTRIES, 256);
    }

    #[test]
    fn test_env_var_parsing() {
        // Verify that NonZeroUsize parsing works correctly
        let val: Option<NonZeroUsize> = "256".parse::<usize>().ok().and_then(NonZeroUsize::new);
        assert_eq!(val.map(|v| v.get()), Some(256));

        let invalid: Option<NonZeroUsize> = "0".parse::<usize>().ok().and_then(NonZeroUsize::new);
        assert!(invalid.is_none()); // Zero is invalid
    }
}
