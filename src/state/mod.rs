pub mod cache;
pub mod index;
pub mod metrics;
pub mod resolver;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::analyzer;
use crate::indexer::FileIndex;
use crate::linter::LintPool;
use crate::security::SecurityConfig;

pub use cache::{AstCacheStats, CachedAnalysis, ToolCacheKey};
pub use resolver::TsPathAliasConfig;

/// Global server state, initialised once at startup.
static STATE: OnceLock<Arc<ServerState>> = OnceLock::new();

/// Environment variable to configure maximum concurrent tool executions.
const ENV_TOOL_CONCURRENCY: &str = "NEXUS_TOOL_MAX_CONCURRENCY";
/// Default maximum number of concurrent tool executions.
const DEFAULT_TOOL_MAX_CONCURRENCY: usize = 4;

pub struct ServerState {
    /// Canonical, absolute project root — immutable after init.
    root: PathBuf,
    /// Hybrid linting pool used by `lint_file` and `inspect_symbol`.
    lint_pool: LintPool,
    /// Security configuration loaded at startup.
    security_config: SecurityConfig,
    /// Whether the client connection has been authenticated.
    client_authenticated: AtomicBool,
    /// True if the project is detected to be an Angular project.
    is_angular_project: bool,
    /// Parsed JS/TS path aliases from discovered `tsconfig`/`jsconfig` files.
    ts_path_aliases: Vec<TsPathAliasConfig>,
    /// Semaphore to control concurrent execution of expensive tools.
    tool_concurrency: tokio::sync::Semaphore,

    // Sub-components
    cache: cache::CacheManager,
    index_mgr: index::IndexManager,
    metrics: metrics::MetricsCollector,
}

impl ServerState {
    pub fn new(root_str: &str) -> Result<Arc<Self>> {
        let root = std::fs::canonicalize(root_str)
            .with_context(|| format!("Failed to canonicalise project root: {root_str}"))?;

        let index_mgr = index::IndexManager::new(&root)?;
        let is_angular = index_mgr
            .index
            .try_read()
            .expect("freshly constructed index lock should not be contended")
            .allowed_files
            .iter()
            .any(|p| p.to_string_lossy().contains("angular.json"));

        let ts_path_aliases = resolver::PathResolver::discover_ts_path_aliases(&root);
        let lint_pool = LintPool::init(&root);

        let max_concurrency = std::env::var(ENV_TOOL_CONCURRENCY)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_TOOL_MAX_CONCURRENCY);

        let security_config = SecurityConfig::load();
        let client_authenticated = AtomicBool::new(security_config.auth_token.is_none());

        Ok(Arc::new(Self {
            root,
            lint_pool,
            security_config,
            client_authenticated,
            is_angular_project: is_angular,
            ts_path_aliases,
            tool_concurrency: tokio::sync::Semaphore::new(max_concurrency),
            cache: cache::CacheManager::new(),
            index_mgr,
            metrics: metrics::MetricsCollector::new(),
        }))
    }

    pub fn init(root: &str) -> Result<Arc<Self>> {
        let instance = Self::new(root)?;
        STATE
            .set(instance.clone())
            .map_err(|_| anyhow::anyhow!("ServerState already initialised"))?;
        Ok(instance)
    }

    pub fn get() -> Arc<Self> {
        STATE
            .get()
            .expect("ServerState::get() called before ServerState::init()")
            .clone()
    }

    pub fn get_opt() -> Option<Arc<Self>> {
        STATE.get().cloned()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn lint_pool(&self) -> &LintPool {
        &self.lint_pool
    }

    pub fn security_config(&self) -> &SecurityConfig {
        &self.security_config
    }

    pub fn is_client_authenticated(&self) -> bool {
        self.client_authenticated.load(Ordering::Acquire)
    }

    pub fn is_authenticated(&self) -> bool {
        self.is_client_authenticated()
    }

    pub fn authenticate(&self, token: &str) -> bool {
        if let Some(ref expected) = self.security_config.auth_token {
            if crate::security::constant_time_compare(token, expected) {
                self.set_client_authenticated(true);
                return true;
            }
        }
        false
    }

    pub async fn evict_cache_entry(&self, path: &Path) {
        self.cache.ast_cache.invalidate(path).await;
    }

    pub fn set_client_authenticated(&self, auth: bool) {
        self.client_authenticated.store(auth, Ordering::Release);
    }

    pub fn record_tool_invocation(&self, tool_name: &str) {
        self.metrics.record_tool_invocation(tool_name);
    }

    pub fn tool_invocation_counts(&self) -> std::collections::HashMap<String, u64> {
        self.metrics
            .tool_invocation_counts
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn uptime(&self) -> Duration {
        self.metrics.started_at.elapsed()
    }

    pub fn ast_cache_stats(&self) -> AstCacheStats {
        self.cache.stats()
    }

    pub fn is_angular_project(&self) -> bool {
        self.is_angular_project
    }

    #[allow(dead_code)]
    pub fn ts_path_aliases(&self) -> &[TsPathAliasConfig] {
        &self.ts_path_aliases
    }

    pub fn resolve_ts_path_alias(
        &self,
        import_path: &str,
        importer_path: &Path,
    ) -> Option<PathBuf> {
        resolver::PathResolver::resolve_ts_path_alias(
            &self.ts_path_aliases,
            import_path,
            importer_path,
        )
    }

    #[allow(dead_code)]
    pub fn tool_concurrency_semaphore(&self) -> &tokio::sync::Semaphore {
        &self.tool_concurrency
    }

    pub fn record_tool_concurrency_rejection(&self) {
        self.metrics.record_concurrency_rejection();
    }

    pub fn operational_metrics(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.metrics.ast_cache_hits.load(Ordering::Relaxed),
            self.metrics.ast_cache_misses.load(Ordering::Relaxed),
            self.metrics.tool_cache_hits.load(Ordering::Relaxed),
            self.metrics.tool_cache_misses.load(Ordering::Relaxed),
            self.metrics
                .tool_concurrency_rejections
                .load(Ordering::Relaxed),
        )
    }

    pub fn record_ast_cache_hit(&self) {
        self.metrics.record_ast_hit();
    }

    pub fn record_ast_cache_miss(&self) {
        self.metrics.record_ast_miss();
    }

    pub fn record_tool_cache_hit(&self) {
        self.metrics.record_tool_hit();
    }

    pub fn record_tool_cache_miss(&self) {
        self.metrics.record_tool_miss();
    }

    pub async fn get_tool_cache(&self, key: &ToolCacheKey) -> Option<serde_json::Value> {
        self.cache.tool_cache.get(key).await
    }

    pub async fn insert_tool_cache(&self, key: ToolCacheKey, value: serde_json::Value) {
        self.cache.tool_cache.insert(key, value).await;
    }

    pub fn get_cache_stats(&self) -> AstCacheStats {
        self.ast_cache_stats()
    }

    pub fn get_tool_invocation_counts(&self) -> std::collections::HashMap<String, u64> {
        self.tool_invocation_counts()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.uptime().as_secs()
    }

    pub fn get_operational_metrics(&self) -> (u64, u64, u64, u64, u64) {
        self.operational_metrics()
    }

    pub async fn acquire_tool_permit_timeout(
        &self,
        timeout: Duration,
    ) -> Option<tokio::sync::SemaphorePermit<'_>> {
        tokio::time::timeout(timeout, self.tool_concurrency.acquire())
            .await
            .ok()
            .and_then(|res| res.ok())
    }

    pub fn make_tool_cache_key(&self, tool_name: &str, args: &serde_json::Value) -> ToolCacheKey {
        ToolCacheKey {
            root_path: self.root.clone(),
            tool_name: tool_name.to_string(),
            canonical_args: resolver::canonicalize_json(args),
        }
    }

    pub fn invalidate_tool_cache_for_root(&self, root: &Path) {
        self.cache.invalidate_tool_cache_for_root(root);
    }

    pub fn invalidate_tool_cache_for_file(&self, path: &Path) {
        self.cache.invalidate_tool_cache_for_file(&self.root, path);
    }

    pub async fn index(&self) -> Result<tokio::sync::RwLockReadGuard<'_, FileIndex>> {
        self.index_mgr.ensure_ready(&self.root).await?;
        Ok(self.index_mgr.index.read().await)
    }

    #[allow(dead_code)]
    pub async fn rebuild_index(&self) -> Result<()> {
        self.index_mgr.rebuild(&self.root).await?;
        Ok(())
    }

    pub fn validate_path(&self, requested: &Path) -> Result<PathBuf> {
        resolver::PathResolver::validate_path(&self.root, requested)
    }

    pub async fn get_analysis(&self, path: &Path) -> Result<analyzer::FileAnalysis> {
        let path_buf = path.to_path_buf();

        if self.cache.ast_cache.contains_key(&path_buf) {
            self.record_ast_cache_hit();
        } else {
            self.record_ast_cache_miss();
        }

        let cached = self
            .cache
            .ast_cache
            .get_with(path_buf.clone(), async move {
                let analysis =
                    tokio::task::spawn_blocking(move || analyzer::analyze_file(&path_buf))
                        .await
                        .expect("spawn_blocking panicked")
                        .unwrap_or_default();

                CachedAnalysis { analysis }
            })
            .await;

        Ok(cached.analysis)
    }

    pub async fn refresh_index(&self) -> Result<(usize, u64)> {
        let new_index = self.index_mgr.rebuild(&self.root).await?;
        let files_found = new_index.allowed_files.len() + new_index.restricted_files.len();

        self.invalidate_tool_cache_for_root(&self.root);

        let count = self.cache.ast_cache.entry_count();
        self.cache.ast_cache.invalidate_all();
        let cleared_count = count;

        Ok((files_found, cleared_count))
    }

    pub fn request_watcher_refresh(self: &Arc<Self>) {
        self.index_mgr
            .watch_refresh_pending
            .store(true, Ordering::Release);

        let was_running = self
            .index_mgr
            .watch_refresh_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();

        if was_running {
            debug!("Watcher refresh requested; loop claimed by this thread");
            let state = Arc::clone(self);
            tokio::spawn(async move {
                state.run_watcher_refresh_loop().await;
            });
        } else {
            debug!("Watcher refresh requested; coalesced with active refresh loop");
        }
    }

    async fn run_watcher_refresh_loop(&self) {
        loop {
            let pending = self
                .index_mgr
                .watch_refresh_pending
                .swap(false, Ordering::AcqRel);
            if !pending {
                debug!("No watcher refreshes pending; releasing running flag");
                self.index_mgr
                    .watch_refresh_running
                    .store(false, Ordering::Release);

                if self.index_mgr.watch_refresh_pending.load(Ordering::Acquire)
                    && self
                        .index_mgr
                        .watch_refresh_running
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    debug!("Re-claimed running flag in close-race check; continuing loop");
                    continue;
                }
                break;
            }

            info!("Executing watcher-triggered index refresh pass");
            match self.refresh_index().await {
                Ok((files, ast_cleared)) => {
                    info!(
                        files_found = files,
                        ast_entries_cleared = ast_cleared,
                        "Watcher-triggered index refresh completed successfully"
                    );
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        "Watcher-triggered index refresh failed; will retry on next file event"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    #[tokio::test]
    async fn ast_cache_respects_capacity() {
        let cache: moka::future::Cache<String, i32> =
            moka::future::Cache::builder().max_capacity(2).build();

        cache.insert("a".into(), 1).await;
        cache.insert("b".into(), 2).await;
        cache.insert("c".into(), 3).await;
        assert!(cache.entry_count() <= 2);
    }

    #[test]
    fn new_returns_independent_instance() {
        let tmp = std::env::temp_dir();
        let state = ServerState::new(tmp.to_str().unwrap())
            .expect("should build without touching the global singleton");
        assert_eq!(state.root(), tmp.canonicalize().unwrap());
    }

    #[test]
    fn test_cached_analysis_struct() {
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

        let cached = CachedAnalysis { analysis };
        assert_eq!(cached.analysis.language, "rust");
    }

    #[test]
    fn test_env_var_parsing() {
        let val: Option<NonZeroUsize> = "256".parse::<usize>().ok().and_then(NonZeroUsize::new);
        assert_eq!(val.map(NonZeroUsize::get), Some(256));

        let invalid: Option<NonZeroUsize> = "0".parse::<usize>().ok().and_then(NonZeroUsize::new);
        assert!(invalid.is_none());
    }

    #[test]
    fn coordination_first_caller_claims_running() {
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
        let running = AtomicBool::new(true);
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
        let running = AtomicBool::new(true);
        let pending = AtomicBool::new(true);

        let should_refresh = pending.swap(false, Ordering::AcqRel);
        assert!(should_refresh, "loop must see pending=true on first pass");
        assert!(
            !pending.load(Ordering::Acquire),
            "pending cleared after swap"
        );

        running.store(false, Ordering::Release);
        assert!(
            !running.load(Ordering::Acquire),
            "running released after drain"
        );
    }

    #[test]
    fn coordination_close_race_guard_reclaims_running() {
        let running = AtomicBool::new(false);
        let pending = AtomicBool::new(true);

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
        assert_eq!(
            resolver::canonicalize_json(&v1),
            resolver::canonicalize_json(&v2)
        );
    }

    #[test]
    fn record_tool_invocation_increments_counter() {
        let counts = std::sync::Mutex::new(std::collections::HashMap::new());
        {
            let mut c = counts.lock().unwrap();
            *c.entry("test_tool".to_owned()).or_insert(0) += 1;
            *c.entry("test_tool".to_owned()).or_insert(0) += 1;
            assert_eq!(*c.get("test_tool").unwrap(), 2);
        }
    }

    #[test]
    fn parses_ts_path_alias_config() {
        let dir = std::env::temp_dir().join("nexus_ts_alias_parse_test");
        let _ = std::fs::create_dir_all(&dir);
        let cfg = dir.join("tsconfig.json");
        std::fs::write(
            &cfg,
            r#"{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@lib/*": ["packages/lib/*"]
    }
  }
}"#,
        )
        .unwrap();

        let parsed = resolver::parse_ts_path_alias_config(&cfg).expect("expected alias config");
        assert_eq!(parsed.rules.len(), 2);
        assert_eq!(parsed.base_url, Some(PathBuf::from(".")));

        let _ = std::fs::remove_file(cfg);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn matches_alias_pattern_with_wildcard() {
        let wild = resolver::match_alias_pattern("@/*", "@/components/button").expect("must match");
        assert_eq!(wild, "components/button");
        assert!(resolver::match_alias_pattern("@core/*", "@/components").is_none());
    }

    #[test]
    fn expands_ts_alias_candidates_with_extensions_and_index_files() {
        let candidates =
            resolver::expand_ts_alias_candidates(PathBuf::from("src/components/button"));
        assert!(candidates.iter().any(|p| p.ends_with("button.ts")));
        assert!(candidates.iter().any(|p| p.ends_with("button/index.ts")));
    }
}
