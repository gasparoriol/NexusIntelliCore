pub mod cache;
pub mod index;
pub mod metrics;
pub mod project;
pub mod resolver;

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tracing::info;

use crate::analyzer;
use crate::indexer::FileIndex;
use crate::linter::LintPool;
use crate::security::SecurityConfig;

pub use cache::{AstCacheStats, CachedAnalysis, ToolCacheKey};
pub use metrics::OperationalMetrics;
pub use project::ProjectContext;
pub use resolver::TsPathAliasConfig;

/// Global server state, initialised once at startup.
static STATE: OnceLock<Arc<ServerState>> = OnceLock::new();

/// Environment variable to configure maximum concurrent tool executions.
const ENV_TOOL_CONCURRENCY: &str = "NEXUS_TOOL_MAX_CONCURRENCY";
/// Default maximum number of concurrent tool executions.
const DEFAULT_TOOL_MAX_CONCURRENCY: usize = 4;

/// Typed concurrency configuration for tool execution.
#[derive(Debug, Clone)]
pub struct ConcurrencyLimits {
    pub max_tool_concurrency: usize,
}

impl ConcurrencyLimits {
    #[allow(dead_code)]
    pub const fn defaults() -> Self {
        Self {
            max_tool_concurrency: DEFAULT_TOOL_MAX_CONCURRENCY,
        }
    }

    pub fn from_env() -> Self {
        let max = std::env::var(ENV_TOOL_CONCURRENCY)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_TOOL_MAX_CONCURRENCY);
        Self {
            max_tool_concurrency: max,
        }
    }
}

pub struct ServerState {
    /// Registered projects mapped by project ID.
    projects: std::sync::RwLock<HashMap<String, Arc<ProjectContext>>>,
    /// Default project ID used when tool calls don't specify a project.
    default_project_id: std::sync::RwLock<Option<String>>,
    /// Security configuration loaded at startup.
    security_config: SecurityConfig,
    /// Whether the client connection has been authenticated.
    client_authenticated: AtomicBool,
    /// Semaphore to control concurrent execution of expensive tools.
    tool_concurrency: tokio::sync::Semaphore,

    // Sub-components
    cache: cache::CacheManager,
    metrics: metrics::MetricsCollector,
}

impl ServerState {
    pub fn empty() -> Result<Arc<Self>> {
        let concurrency_limits = ConcurrencyLimits::from_env();
        let max_concurrency = concurrency_limits.max_tool_concurrency;
        let security_config = SecurityConfig::load();
        let client_authenticated = AtomicBool::new(security_config.auth_token_hash.is_none());

        Ok(Arc::new(Self {
            projects: std::sync::RwLock::new(HashMap::new()),
            default_project_id: std::sync::RwLock::new(None),
            security_config,
            client_authenticated,
            tool_concurrency: tokio::sync::Semaphore::new(max_concurrency),
            cache: cache::CacheManager::new(),
            metrics: metrics::MetricsCollector::new(),
        }))
    }

    pub fn new(root_str: &str) -> Result<Arc<Self>> {
        let state = Self::empty()?;
        state.register_project(root_str, None)?;
        Ok(state)
    }

    pub fn init(root: &str) -> Result<Arc<Self>> {
        let instance = Self::new(root)?;
        STATE
            .set(instance.clone())
            .map_err(|_| anyhow::anyhow!("ServerState already initialised"))?;
        Ok(instance)
    }

    pub fn init_empty() -> Result<Arc<Self>> {
        let instance = Self::empty()?;
        STATE
            .set(instance.clone())
            .map_err(|_| anyhow::anyhow!("ServerState already initialised"))?;
        Ok(instance)
    }

    /// Returns the global `ServerState` instance. Panics if called before `init()`.
    pub fn get() -> Arc<Self> {
        STATE
            .get()
            .expect("ServerState::get() called before ServerState::init()")
            .clone()
    }

    /// Returns `Some(Arc<ServerState>)` if initialized, or `None` without panicking.
    #[allow(dead_code)]
    pub fn try_get() -> Option<Arc<Self>> {
        STATE.get().cloned()
    }

    /// Returns `Some(Arc<ServerState>)` if initialized, or `None` without panicking.
    pub fn get_opt() -> Option<Arc<Self>> {
        STATE.get().cloned()
    }

    /// Registers a new workspace project in the server state.
    pub fn register_project(
        &self,
        root_str: &str,
        id: Option<String>,
    ) -> Result<Arc<ProjectContext>> {
        let project = ProjectContext::new(root_str, id)?;
        let mut projects = self
            .projects
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        projects.insert(project.id.clone(), project.clone());

        let mut def_lock = self
            .default_project_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if def_lock.is_none() {
            *def_lock = Some(project.id.clone());
        }

        info!(project_id = %project.id, root = %project.root.display(), "Project registered");
        Ok(project)
    }

    pub fn unregister_project(&self, id_or_path: &str) -> Result<bool> {
        let mut projects = self
            .projects
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let target_id = if projects.contains_key(id_or_path) {
            Some(id_or_path.to_string())
        } else if let Ok(canonical) = std::fs::canonicalize(id_or_path) {
            projects
                .iter()
                .find(|(_, p)| p.root == canonical)
                .map(|(k, _)| k.clone())
        } else {
            None
        };

        let Some(id) = target_id else {
            return Ok(false);
        };

        if let Some(removed) = projects.remove(&id) {
            self.invalidate_tool_cache_for_root(&removed.root);
            self.invalidate_ast_cache_for_root(&removed.root);

            let mut def_lock = self
                .default_project_id
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if def_lock.as_deref() == Some(&id) {
                *def_lock = projects.keys().next().cloned();
            }
            info!(project_id = %id, "Project unregistered");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_project(&self, id_or_path: Option<&str>) -> Result<Arc<ProjectContext>> {
        let projects = self
            .projects
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(key) = id_or_path {
            if let Some(proj) = projects.get(key) {
                return Ok(proj.clone());
            }
            if let Ok(canonical) = std::fs::canonicalize(key) {
                if let Some((_, proj)) = projects.iter().find(|(_, p)| p.root == canonical) {
                    return Ok(proj.clone());
                }
            }
            anyhow::bail!("Project '{key}' not found");
        }

        let def_id = self
            .default_project_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(ref id) = *def_id else {
            anyhow::bail!("No project registered in ServerState");
        };

        projects
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Default project '{id}' not found"))
    }

    pub fn resolve_project_for_path(
        &self,
        file_path: &str,
    ) -> Result<(Arc<ProjectContext>, PathBuf)> {
        let requested_path = Path::new(file_path);
        let projects = self
            .projects
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let absolute_candidate = std::fs::canonicalize(requested_path).ok();

        if let Some(ref canonical) = absolute_candidate {
            let mut matched: Vec<&Arc<ProjectContext>> = projects
                .values()
                .filter(|p| canonical.starts_with(&p.root))
                .collect();
            matched.sort_by_key(|p| std::cmp::Reverse(p.root.components().count()));
            if let Some(best) = matched.first() {
                return Ok(((*best).clone(), canonical.clone()));
            }
        }

        drop(projects);
        let default_proj = self.get_project(None)?;
        let validated = default_proj.validate_path(requested_path)?;
        Ok((default_proj, validated))
    }

    pub fn list_projects(&self) -> Vec<(String, PathBuf)> {
        let projects = self
            .projects
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        projects
            .iter()
            .map(|(id, p)| (id.clone(), p.root.clone()))
            .collect()
    }

    pub fn default_project(&self) -> Result<Arc<ProjectContext>> {
        self.get_project(None)
    }

    pub fn root(&self) -> PathBuf {
        self.default_project()
            .map(|p| p.root.clone())
            .unwrap_or_default()
    }

    pub fn lint_pool(&self) -> LintPool {
        self.default_project()
            .map(|p| p.lint_pool.clone())
            .unwrap_or_else(|_| LintPool::init(Path::new(".")))
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
        if let Some(ref expected_hash) = self.security_config.auth_token_hash {
            let provided_hash = crate::security::compute_token_digest(token);
            if crate::security::constant_time_compare_hashes(expected_hash, &provided_hash) {
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
        self.default_project().is_ok_and(|p| p.is_angular_project)
    }

    #[allow(dead_code)]
    pub fn ts_path_aliases(&self) -> Vec<TsPathAliasConfig> {
        self.default_project()
            .map_or_else(|_| vec![], |p| p.ts_path_aliases.clone())
    }

    pub fn resolve_ts_path_alias(
        &self,
        import_path: &str,
        importer_path: &Path,
    ) -> Option<PathBuf> {
        let (proj, _) = self
            .resolve_project_for_path(&importer_path.to_string_lossy())
            .ok()?;
        resolver::PathResolver::resolve_ts_path_alias(
            &proj.ts_path_aliases,
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

    pub fn operational_metrics(&self) -> OperationalMetrics {
        OperationalMetrics {
            ast_cache_hits: self.metrics.ast_cache_hits.load(Ordering::Relaxed),
            ast_cache_misses: self.metrics.ast_cache_misses.load(Ordering::Relaxed),
            tool_cache_hits: self.metrics.tool_cache_hits.load(Ordering::Relaxed),
            tool_cache_misses: self.metrics.tool_cache_misses.load(Ordering::Relaxed),
            tool_concurrency_rejections: self
                .metrics
                .tool_concurrency_rejections
                .load(Ordering::Relaxed),
        }
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

    pub fn get_operational_metrics(&self) -> OperationalMetrics {
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
        let root = if let Some(path_str) = args.get("file_path").and_then(|v| v.as_str()) {
            self.resolve_project_for_path(path_str)
                .map(|(p, _)| p.root.clone())
                .unwrap_or_else(|_| self.root())
        } else {
            self.root()
        };

        ToolCacheKey {
            root_path: root,
            tool_name: tool_name.to_string(),
            canonical_args: resolver::canonicalize_json(args),
        }
    }

    pub fn invalidate_tool_cache_for_root(&self, root: &Path) {
        self.cache.invalidate_tool_cache_for_root(root);
    }

    pub fn invalidate_ast_cache_for_root(&self, root: &Path) -> u64 {
        self.cache.invalidate_ast_cache_for_root(root)
    }

    pub fn invalidate_tool_cache_for_file(&self, path: &Path) {
        let root = self
            .resolve_project_for_path(&path.to_string_lossy())
            .map(|(p, _)| p.root.clone())
            .unwrap_or_else(|_| self.root());
        self.cache.invalidate_tool_cache_for_file(&root, path);
    }

    pub async fn index(&self) -> Result<FileIndex> {
        let proj = self.default_project()?;
        proj.index().await
    }

    pub fn validate_path(&self, requested: &Path) -> Result<PathBuf> {
        let (_proj, validated) = self.resolve_project_for_path(&requested.to_string_lossy())?;
        Ok(validated)
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
        let proj = self.default_project()?;
        proj.refresh_index().await
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

    #[test]
    fn concurrency_limits_defaults_are_positive() {
        let l = super::ConcurrencyLimits::defaults();
        assert!(l.max_tool_concurrency > 0);
    }

    #[test]
    fn concurrency_limits_from_env_reads_override() {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(super::ENV_TOOL_CONCURRENCY, "8");
        let l = super::ConcurrencyLimits::from_env();
        std::env::remove_var(super::ENV_TOOL_CONCURRENCY);
        assert_eq!(l.max_tool_concurrency, 8);
    }

    #[test]
    fn concurrency_limits_from_env_ignores_zero() {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(super::ENV_TOOL_CONCURRENCY, "0");
        let l = super::ConcurrencyLimits::from_env();
        std::env::remove_var(super::ENV_TOOL_CONCURRENCY);
        assert_eq!(l.max_tool_concurrency, super::DEFAULT_TOOL_MAX_CONCURRENCY);
    }

    #[test]
    fn multi_project_registration_and_lookup() {
        let dir1 = std::env::temp_dir().join("nexus_test_proj1");
        let dir2 = std::env::temp_dir().join("nexus_test_proj2");
        let _ = std::fs::create_dir_all(&dir1);
        let _ = std::fs::create_dir_all(&dir2);

        let state = ServerState::empty().unwrap();
        let p1 = state
            .register_project(dir1.to_str().unwrap(), Some("proj1".into()))
            .unwrap();
        let p2 = state
            .register_project(dir2.to_str().unwrap(), Some("proj2".into()))
            .unwrap();

        assert_eq!(state.list_projects().len(), 2);
        assert_eq!(state.get_project(Some("proj1")).unwrap().root, p1.root);
        assert_eq!(state.get_project(Some("proj2")).unwrap().root, p2.root);

        assert!(state.unregister_project("proj1").unwrap());
        assert_eq!(state.list_projects().len(), 1);

        let _ = std::fs::remove_dir_all(dir1);
        let _ = std::fs::remove_dir_all(dir2);
    }
}
