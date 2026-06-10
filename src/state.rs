use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

use anyhow::{Context, Result};
use lru::LruCache;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::analyzer;
use crate::indexer::FileIndex;

use crate::security::SecurityConfig;

/// Default maximum number of entries in AST cache.
const DEFAULT_AST_CACHE_ENTRIES: usize = 256;

/// Environment variable to configure AST cache size.
const ENV_AST_CACHE_LIMIT: &str = "MCP_AST_CACHE_ENTRIES";

/// Default maximum number of entries in Tool cache.
const DEFAULT_TOOL_CACHE_ENTRIES: usize = 1024;

/// Environment variable to configure Tool cache size.
const ENV_TOOL_CACHE_LIMIT: &str = "MCP_TOOL_CACHE_ENTRIES";

/// Global server state, initialised once at startup.
static STATE: OnceLock<ServerState> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ToolCacheKey {
    pub root_path: PathBuf,
    pub tool_name: String,
    pub canonical_args: String,
}

pub fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| format!("{:?}", s)),
        serde_json::Value::Array(items) => {
            let rendered = items.iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{}]", rendered)
        }
        serde_json::Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let rendered = entries.into_iter()
                .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap_or_else(|_| format!("{:?}", k)), canonicalize_json(v)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{}}}", rendered)
        }
    }
}

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
    /// Tool cache with Moka, mapping ToolCacheKey to the final sanitised serde_json::Value response.
    tool_cache: moka::future::Cache<ToolCacheKey, serde_json::Value>,
    /// True while a watcher-triggered index refresh loop is running.
    watch_refresh_running: AtomicBool,
    /// Set when watcher events require at least one refresh pass.
    watch_refresh_pending: AtomicBool,
    /// Security configuration loaded at startup.
    security_config: SecurityConfig,
    /// Whether the client connection has been authenticated.
    client_authenticated: AtomicBool,
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

        // Load Tool cache limit from environment or use default
        let tool_cache_limit = std::env::var(ENV_TOOL_CACHE_LIMIT)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_TOOL_CACHE_ENTRIES);

        if let Ok(limit_str) = std::env::var(ENV_TOOL_CACHE_LIMIT) {
            info!(
                "Tool cache limit configured via {} = {}",
                ENV_TOOL_CACHE_LIMIT, limit_str
            );
        }

        let tool_cache = moka::future::Cache::builder()
            .max_capacity(tool_cache_limit as u64)
            .build();

        let security_config = SecurityConfig::load();
        let client_authenticated = AtomicBool::new(security_config.auth_token.is_none());

        let state = ServerState {
            index: RwLock::new(FileIndex::empty(&root)),
            root,
            index_ready: AtomicBool::new(false),
            ast_cache: RwLock::new(LruCache::new(cache_limit)),
            tool_cache,
            watch_refresh_running: AtomicBool::new(false),
            watch_refresh_pending: AtomicBool::new(false),
            security_config,
            client_authenticated,
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

    pub fn security_config(&self) -> &SecurityConfig {
        &self.security_config
    }

    pub fn is_authenticated(&self) -> bool {
        self.client_authenticated.load(Ordering::Acquire)
    }

    pub fn authenticate(&self, token: &str) -> bool {
        if let Some(ref expected) = self.security_config.auth_token {
            if crate::security::constant_time_compare(expected, token) {
                self.client_authenticated.store(true, Ordering::Release);
                return true;
            }
        }
        false
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

        // Invalidate tool cache for this project root
        self.invalidate_tool_cache_for_root(&self.root).await;

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

    pub fn make_tool_cache_key(&self, tool_name: &str, args: &serde_json::Value) -> ToolCacheKey {
        ToolCacheKey {
            root_path: self.root.clone(),
            tool_name: tool_name.to_string(),
            canonical_args: canonicalize_json(args),
        }
    }

    pub fn tool_cache(&self) -> &moka::future::Cache<ToolCacheKey, serde_json::Value> {
        &self.tool_cache
    }

    pub async fn invalidate_tool_cache_for_root(&self, root_path: &Path) {
        let canonical_root = match std::fs::canonicalize(root_path) {
            Ok(p) => p,
            Err(_) => root_path.to_path_buf(),
        };
        debug!(root_path = %canonical_root.display(), "Invalidating tool cache for root");
        self.tool_cache
            .invalidate_entries_if(move |key, _| key.root_path == canonical_root);
    }

    /// Rebuild index when requested by the file-system watcher.
    ///
    /// This is the single explicit entry point from watcher-driven events.
    pub async fn refresh_index_from_watcher(&self) -> Result<()> {
        let (files_found, cache_cleared) = self.refresh_index().await?;
        debug!(
            files_found,
            cache_cleared, "Watcher-triggered index refresh completed"
        );
        Ok(())
    }

    /// Request a watcher-driven refresh pass.
    ///
    /// Requests are coalesced while a refresh loop is active.
    pub fn request_watcher_refresh(&'static self) {
        self.watch_refresh_pending.store(true, Ordering::Release);

        if self
            .watch_refresh_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            debug!("Watcher refresh already running; coalescing pending work");
            return;
        }

        tokio::spawn(async move {
            self.run_watcher_refresh_loop().await;
        });
    }

    async fn run_watcher_refresh_loop(&self) {
        loop {
            let should_refresh = self.watch_refresh_pending.swap(false, Ordering::AcqRel);

            if should_refresh {
                if let Err(e) = self.refresh_index_from_watcher().await {
                    warn!("Watcher-triggered index refresh failed: {}", e);
                }
                continue;
            }

            self.watch_refresh_running.store(false, Ordering::Release);

            // Close race: if a new pending request arrives between swap(false)
            // and releasing `watch_refresh_running`, reclaim ownership and run again.
            if self.watch_refresh_pending.load(Ordering::Acquire)
                && self
                    .watch_refresh_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                continue;
            }

            break;
        }
    }

    /// Evict a single path from the AST cache.
    ///
    /// Called by the file watcher on content changes (e.g. modify).
    /// Returns `true` if an entry was present and removed; `false` if not cached.
    pub fn evict_cache_entry(&self, path: &std::path::Path) -> bool {
        // Use `try_write` — if the lock is busy we silently skip eviction.
        // The mtime-check in `get_analysis` will catch the stale entry on the
        // next request anyway.
        if let Ok(mut cache) = self.ast_cache.try_write() {
            cache.pop(path).is_some()
        } else {
            false
        }
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
            module_doc: None,
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

    // --- Watcher coordination flag state-machine -------------------------
    //
    // The tests below verify the AtomicBool protocol that underpins
    // `request_watcher_refresh` / `run_watcher_refresh_loop` without
    // touching the OnceLock singleton.  Each test mirrors an observable
    // execution path in the coordination logic.

    #[test]
    fn coordination_first_caller_claims_running() {
        // When running=false, the first request should succeed its CAS and
        // set running=true; pending should also be visible.
        let running = AtomicBool::new(false);
        let pending = AtomicBool::new(false);

        pending.store(true, Ordering::Release);
        let claimed = running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();

        assert!(claimed, "first caller must claim running");
        assert!(pending.load(Ordering::Acquire), "pending must survive");
        assert!(running.load(Ordering::Acquire), "running must be set");
    }

    #[test]
    fn coordination_second_caller_coalesces_via_pending() {
        // When running=true (loop active), a concurrent request must NOT
        // claim running; it must only set pending so the active loop picks
        // it up.
        let running = AtomicBool::new(true); // already running
        let pending = AtomicBool::new(false);

        pending.store(true, Ordering::Release);
        let claimed = running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();

        assert!(!claimed, "second caller must not claim already-running");
        assert!(
            pending.load(Ordering::Acquire),
            "pending must be visible to loop"
        );
    }

    #[test]
    fn coordination_loop_drains_pending_and_releases_running() {
        // Simulate one pass of run_watcher_refresh_loop: swap pending→false,
        // do work, release running.
        let running = AtomicBool::new(true);
        let pending = AtomicBool::new(true);

        let should_refresh = pending.swap(false, Ordering::AcqRel);
        assert!(should_refresh, "loop must see pending=true on first pass");
        assert!(
            !pending.load(Ordering::Acquire),
            "pending cleared after swap"
        );

        // Simulate: no new pending → release running
        running.store(false, Ordering::Release);
        assert!(
            !running.load(Ordering::Acquire),
            "running released after drain"
        );
    }

    #[test]
    fn coordination_close_race_guard_reclaims_running() {
        // Simulates the close-race scenario: loop releases running, but a
        // new event has set pending=true before the recheck.  The guard
        // must reclaim running so the event is not lost.
        let running = AtomicBool::new(false); // just released by loop
        let pending = AtomicBool::new(true); // new event arrived simultaneously

        // Mirror the guard in run_watcher_refresh_loop
        let reclaimed = pending.load(Ordering::Acquire)
            && running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();

        assert!(reclaimed, "close-race guard must reclaim running");
        assert!(
            running.load(Ordering::Acquire),
            "running must be true after reclaim"
        );
    }

    #[test]
    fn coordination_no_reclaim_when_pending_false() {
        // If pending is false when the guard runs, running stays released.
        let running = AtomicBool::new(false);
        let pending = AtomicBool::new(false);

        let reclaimed = pending.load(Ordering::Acquire)
            && running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();

        assert!(!reclaimed, "guard must not reclaim when nothing pending");
        assert!(!running.load(Ordering::Acquire), "running stays false");
    }

    #[test]
    fn test_canonicalize_json() {
        use serde_json::json;
        let v1 = json!({
            "a": 1,
            "b": [2, {"d": 4, "c": 3}],
            "x": null,
            "y": true
        });
        let v2 = json!({
            "y": true,
            "x": null,
            "b": [2, {"c": 3, "d": 4}],
            "a": 1
        });
        assert_eq!(canonicalize_json(&v1), canonicalize_json(&v2));
    }
}
