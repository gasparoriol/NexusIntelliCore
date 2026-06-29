use anyhow::{Context, Result};
use ignore::WalkBuilder;
use moka::future::Cache;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::analyzer::{
    self, ClassInfo, CssRuleInfo, FunctionInfo, HtmlElementInfo, ImportInfo, StringLiteral,
};
use crate::indexer::FileIndex;
use crate::linter::LintPool;
use crate::security::SecurityConfig;

use std::num::NonZeroUsize;

/// Default maximum number of entries in AST cache.
const DEFAULT_AST_CACHE_ENTRIES: usize = 256;

/// Environment variable to configure AST cache size.
const ENV_AST_CACHE_LIMIT: &str = "MCP_AST_CACHE_ENTRIES";

/// Default maximum number of entries in Tool cache.
const DEFAULT_TOOL_CACHE_ENTRIES: usize = 100 * 1024 * 1024;

/// Environment variable to configure Tool cache size.
const ENV_TOOL_CACHE_LIMIT: &str = "MCP_TOOL_CACHE_ENTRIES";

/// Global server state, initialised once at startup.
static STATE: OnceLock<ServerState> = OnceLock::new();

/// Environment variable to configure maximum concurrent tool executions.
const ENV_TOOL_CONCURRENCY: &str = "NEXUS_TOOL_MAX_CONCURRENCY";
/// Default maximum number of concurrent tool executions.
const DEFAULT_TOOL_MAX_CONCURRENCY: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ToolCacheKey {
    pub root_path: PathBuf,
    pub tool_name: String,
    pub canonical_args: String,
}

pub struct AstCacheStats {
    pub ast_entries: usize,
    pub ast_max: usize,
    pub tool_entries: usize,
    pub tool_max: usize,
}

#[derive(Clone, Debug)]
pub struct TsPathAliasRule {
    pub pattern: String,
    pub targets: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TsPathAliasConfig {
    pub config_dir: PathBuf,
    pub base_url: Option<PathBuf>,
    pub rules: Vec<TsPathAliasRule>,
}

fn parse_ts_path_alias_config(config_path: &Path) -> Option<TsPathAliasConfig> {
    let raw = std::fs::read_to_string(config_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let compiler = parsed.get("compilerOptions")?.as_object()?;
    let paths = compiler.get("paths")?.as_object()?;

    let mut rules = Vec::new();
    for (pattern, values) in paths {
        let targets = values
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !targets.is_empty() {
            rules.push(TsPathAliasRule {
                pattern: pattern.to_string(),
                targets,
            });
        }
    }

    if rules.is_empty() {
        return None;
    }

    let base_url = compiler
        .get("baseUrl")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    Some(TsPathAliasConfig {
        config_dir: config_path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        base_url,
        rules,
    })
}

fn discover_ts_path_aliases(root: &Path) -> Vec<TsPathAliasConfig> {
    let mut configs = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .build();

    for entry in walker.flatten() {
        let p = entry.path();
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name != "tsconfig.json" && name != "jsconfig.json" {
            continue;
        }

        if let Some(cfg) = parse_ts_path_alias_config(p) {
            configs.push(cfg);
        }
    }

    configs.sort_by_key(|cfg| std::cmp::Reverse(cfg.config_dir.components().count()));
    configs
}

fn match_alias_pattern(pattern: &str, import_path: &str) -> Option<String> {
    if let Some(star) = pattern.find('*') {
        let prefix = &pattern[..star];
        let suffix = &pattern[star + 1..];
        if import_path.starts_with(prefix)
            && import_path.ends_with(suffix)
            && import_path.len() >= prefix.len() + suffix.len()
        {
            return Some(import_path[prefix.len()..import_path.len() - suffix.len()].to_string());
        }
        return None;
    }

    if pattern == import_path {
        Some(String::new())
    } else {
        None
    }
}

fn apply_alias_target(target: &str, wildcard: &str) -> String {
    if target.contains('*') {
        target.replacen('*', wildcard, 1)
    } else {
        target.to_string()
    }
}

fn normalize_relative_path(path: PathBuf) -> PathBuf {
    path.components().fold(PathBuf::new(), |mut acc, comp| {
        match comp {
            std::path::Component::ParentDir => {
                acc.pop();
            }
            std::path::Component::CurDir => {}
            other => acc.push(other),
        }
        acc
    })
}

fn expand_ts_alias_candidates(base: PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if base.extension().is_some() {
        out.push(base);
        return out;
    }

    out.push(base.clone());
    for ext in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
        out.push(base.with_extension(ext));
    }
    for ext in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
        out.push(base.join(format!("index.{}", ext)));
    }
    out
}

pub fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            serde_json::to_string(s).unwrap_or_else(|_| format!("{:?}", s))
        }
        serde_json::Value::Array(items) => {
            let rendered = items
                .iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{}]", rendered)
        }
        serde_json::Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(a, _)| *a);
            let rendered = entries
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| format!("{:?}", k)),
                        canonicalize_json(v)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{}}}", rendered)
        }
    }
}

#[derive(Clone, Debug)]
pub struct CachedAnalysis {
    pub analysis: analyzer::FileAnalysis,
}

pub struct ServerState {
    /// Canonical, absolute project root — immutable after init.
    root: PathBuf,
    /// File index, rebuildable on demand.
    index: RwLock<FileIndex>,
    /// Whether the index has been fully built at least once.
    index_ready: AtomicBool,
    /// AST cache with Moka, mapping PathBuf to CachedAnalysis.
    ast_cache: moka::future::Cache<PathBuf, CachedAnalysis>,
    /// Tool cache with Moka, mapping ToolCacheKey to the final sanitised serde_json::Value response.
    tool_cache: moka::future::Cache<ToolCacheKey, serde_json::Value>,
    /// Hybrid linting pool used by lint_file and inspect_symbol.
    lint_pool: LintPool,
    /// True while a watcher-triggered index refresh loop is running.
    watch_refresh_running: AtomicBool,
    /// Set when watcher events require at least one refresh pass.
    watch_refresh_pending: AtomicBool,
    /// Security configuration loaded at startup.
    security_config: SecurityConfig,
    /// Whether the client connection has been authenticated.
    client_authenticated: AtomicBool,
    /// True if the project is detected to be an Angular project.
    /// True if the project is detected to be an Angular project.
    is_angular_project: bool,
    /// Parsed JS/TS path aliases from discovered tsconfig/jsconfig files.
    ts_path_aliases: Vec<TsPathAliasConfig>,
    /// Configured maximum number of entries in the AST cache.
    ast_cache_limit: usize,
    /// Configured maximum number of entries in the Tool cache.
    tool_cache_limit: usize,
    /// Semaphore to control concurrent execution of expensive tools.
    tool_concurrency: tokio::sync::Semaphore,
    /// Tool invocation counts.
    tool_invocation_counts: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Instant when the server was started.
    started_at: std::time::Instant,
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

        // Load tool concurrency limit from environment or use default
        let tool_max_concurrency = std::env::var(ENV_TOOL_CONCURRENCY)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_TOOL_MAX_CONCURRENCY);

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

        let tool_cache = Cache::builder()
            .max_capacity(tool_cache_limit as u64)
            .build();

        let security_config = SecurityConfig::load();
        let client_authenticated = AtomicBool::new(security_config.auth_token.is_none());

        // Fast discovery of Angular project: check angular.json or packages.json
        let mut is_angular_project = root.join("angular.json").exists();
        if !is_angular_project {
            let package_json_path = root.join("package.json");
            if package_json_path.exists() {
                if let Ok(content) = std::fs::read_to_string(package_json_path) {
                    if content.contains("@angular/") {
                        is_angular_project = true;
                    }
                }
            }
        }

        let lint_root = root.clone();
        let ts_path_aliases = discover_ts_path_aliases(&root);

        let state = ServerState {
            index: RwLock::new(FileIndex::empty(&root)),
            root,
            index_ready: AtomicBool::new(false),
            ast_cache: moka::future::Cache::builder()
                .max_capacity(cache_limit.get() as u64)
                .weigher(|_key: &PathBuf, value: &CachedAnalysis| -> u32 {
                    let analysis = &value.analysis;

                    // struct size
                    let mut weight = std::mem::size_of::<CachedAnalysis>()
                        + std::mem::size_of::<analyzer::FileAnalysis>();

                    // Sum of the capacities of the vectors and strings in FileAnalysis
                    // 1. Vectors of structs
                    weight += analysis.functions.capacity() * std::mem::size_of::<FunctionInfo>();
                    weight += analysis.classes.capacity() * std::mem::size_of::<ClassInfo>();
                    weight += analysis.imports.capacity() * std::mem::size_of::<ImportInfo>();
                    weight +=
                        analysis.string_literals.capacity() * std::mem::size_of::<StringLiteral>();

                    // 3. Types with Option
                    if let Some(ref rules) = analysis.css_rules {
                        weight += rules.capacity() * std::mem::size_of::<CssRuleInfo>();
                    }
                    if let Some(ref elements) = analysis.html_elements {
                        weight += elements.capacity() * std::mem::size_of::<HtmlElementInfo>();
                    }

                    // 4. Dynamic strings (this is an estimate, as String stores data on the heap)
                    weight += analysis.language.capacity();
                    if let Some(ref doc) = analysis.module_doc {
                        weight += doc.capacity();
                    }

                    weight.try_into().unwrap_or(u32::MAX)
                })
                .time_to_live(Duration::from_secs(3600))
                .build(),
            tool_cache,
            lint_pool: LintPool::init(&lint_root),
            ast_cache_limit: cache_limit.get(),
            tool_cache_limit,
            watch_refresh_running: AtomicBool::new(false),
            watch_refresh_pending: AtomicBool::new(false),
            security_config,
            client_authenticated,
            is_angular_project,
            ts_path_aliases,
            tool_concurrency: tokio::sync::Semaphore::new(tool_max_concurrency),
            tool_invocation_counts: std::sync::Mutex::new(std::collections::HashMap::new()),
            started_at: std::time::Instant::now(),
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

    /// Try to get the global state reference, returning None if not initialised.
    pub fn get_opt() -> Option<&'static ServerState> {
        STATE.get()
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

    pub fn is_angular_project(&self) -> bool {
        self.is_angular_project
    }

    pub fn resolve_ts_path_alias(&self, from_file: &Path, import_path: &str) -> Option<PathBuf> {
        let mut configs: Vec<&TsPathAliasConfig> = self
            .ts_path_aliases
            .iter()
            .filter(|cfg| from_file.starts_with(&cfg.config_dir))
            .collect();

        if configs.is_empty() {
            return None;
        }

        configs.sort_by_key(|cfg| std::cmp::Reverse(cfg.config_dir.components().count()));

        for cfg in configs {
            let mut fallback_candidate: Option<PathBuf> = None;
            for rule in &cfg.rules {
                let Some(wildcard) = match_alias_pattern(&rule.pattern, import_path) else {
                    continue;
                };

                let base_dir = cfg
                    .base_url
                    .as_ref()
                    .map(|b| cfg.config_dir.join(b))
                    .unwrap_or_else(|| cfg.config_dir.clone());

                for target in &rule.targets {
                    let candidate = normalize_relative_path(
                        base_dir.join(apply_alias_target(target, &wildcard)),
                    );
                    for expanded in expand_ts_alias_candidates(candidate.clone()) {
                        if expanded.exists() {
                            return Some(expanded);
                        }
                        if fallback_candidate.is_none() {
                            fallback_candidate = Some(expanded);
                        }
                    }
                }
            }

            if fallback_candidate.is_some() {
                return fallback_candidate;
            }
        }

        None
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
        let path_buf = path.to_path_buf();

        let cached = self
            .ast_cache
            .get_with(path_buf.clone(), async move {
                // We only reach here if the cache is empty or was invalidated by the watcher
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

    /// Clear the AST cache and rebuild the FileIndex.
    /// Used by refresh_index() tool.
    pub async fn refresh_index(&self) -> Result<(usize, u64)> {
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
        let count = self.ast_cache.entry_count();
        self.ast_cache.invalidate_all();
        let cleared_count = count;

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

    pub fn lint_pool(&self) -> &LintPool {
        &self.lint_pool
    }

    pub async fn invalidate_tool_cache_for_file(&self, path: &Path) {
        let canonical_path = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => path.to_path_buf(),
        };

        let canonical_text = canonical_path.to_string_lossy().to_string();
        let _ = self
            .tool_cache
            .invalidate_entries_if(move |key, _| key.canonical_args.contains(&canonical_text));
    }

    pub async fn invalidate_tool_cache_for_root(&self, root_path: &Path) {
        let canonical_root = match std::fs::canonicalize(root_path) {
            Ok(p) => p,
            Err(_) => root_path.to_path_buf(),
        };
        debug!(root_path = %canonical_root.display(), "Invalidating tool cache for root");
        let _ = self
            .tool_cache
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
    pub async fn evict_cache_entry(&self, path: &std::path::Path) -> bool {
        let existed = self.ast_cache.remove(path).await.is_some();
        existed
    }

    /// Get current cache statistics (debug-only).
    pub async fn get_cache_stats(&self) -> AstCacheStats {
        AstCacheStats {
            ast_entries: self.ast_cache.entry_count() as usize,
            ast_max: self.ast_cache_limit,
            tool_entries: self.tool_cache.entry_count() as usize,
            tool_max: self.tool_cache_limit,
        }
    }

    /// Acquire a permit to run a heavy tool, waiting if necessary (with timeout).
    pub async fn acquire_tool_permit_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Option<tokio::sync::SemaphorePermit<'_>> {
        tokio::time::timeout(timeout, self.tool_concurrency.acquire())
            .await
            .ok()
            .and_then(|r| r.ok())
    }

    pub fn record_tool_invocation(&self, tool_name: &str) {
        if let Ok(mut counts) = self.tool_invocation_counts.lock() {
            *counts.entry(tool_name.to_owned()).or_insert(0) += 1;
        }
    }

    pub fn get_tool_invocation_counts(&self) -> std::collections::HashMap<String, u64> {
        self.tool_invocation_counts
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    #[tokio::test]
    async fn ast_cache_respects_capacity() {
        // Construir un cache con capacidad 2
        let cache: moka::future::Cache<String, u32> =
            moka::future::Cache::builder().max_capacity(2).build();
        cache.insert("a".into(), 1).await;
        cache.insert("b".into(), 2).await;
        cache.insert("c".into(), 3).await; // Debe evictar uno de a, b
                                           // No asegurar exactamente cuál fue evictado (moka es probabilístico),
                                           // pero el total debe ser ≤ 2
        assert!(cache.entry_count() <= 2);
    }

    #[test]
    fn test_cached_analysis_struct() {
        // Verify CachedAnalysis can be created.
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
            analysis: analysis.clone(),
        };

        assert_eq!(cached.analysis.language, "rust");
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

    #[test]
    fn record_tool_invocation_increments_counter() {
        let counts = std::sync::Mutex::new(std::collections::HashMap::new());
        let mut c = counts.lock().unwrap();
        *c.entry("test_tool".to_owned()).or_insert(0) += 1;
        *c.entry("test_tool".to_owned()).or_insert(0) += 1;
        assert_eq!(*c.get("test_tool").unwrap(), 2);
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

        let parsed = parse_ts_path_alias_config(&cfg).expect("expected alias config");
        assert_eq!(parsed.rules.len(), 2);
        assert_eq!(parsed.base_url, Some(PathBuf::from(".")));

        let _ = std::fs::remove_file(cfg);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn matches_alias_pattern_with_wildcard() {
        let wild = match_alias_pattern("@/*", "@/components/button").expect("must match");
        assert_eq!(wild, "components/button");
        assert!(match_alias_pattern("@core/*", "@/components").is_none());
    }

    #[test]
    fn expands_ts_alias_candidates_with_extensions_and_index_files() {
        let candidates = expand_ts_alias_candidates(PathBuf::from("src/components/button"));
        assert!(candidates.iter().any(|p| p.ends_with("button.ts")));
        assert!(candidates.iter().any(|p| p.ends_with("button/index.ts")));
    }
}
