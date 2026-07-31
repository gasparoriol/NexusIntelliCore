use crate::analyzer::FileAnalysis;
use moka::future::Cache;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

/// Environment variable to configure AST cache size.
pub const ENV_AST_CACHE_LIMIT: &str = "MCP_AST_CACHE_ENTRIES";
/// Default maximum number of entries in AST cache.
pub const DEFAULT_AST_CACHE_ENTRIES: usize = 256;

/// Environment variable to configure Tool cache size.
pub const ENV_TOOL_CACHE_LIMIT: &str = "MCP_TOOL_CACHE_ENTRIES";
/// Default maximum number of entries in Tool cache.
pub const DEFAULT_TOOL_CACHE_ENTRIES: usize = 100 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct CachedAnalysis {
    pub analysis: FileAnalysis,
}

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

pub struct CacheManager {
    pub ast_cache: Cache<PathBuf, CachedAnalysis>,
    pub tool_cache: Cache<ToolCacheKey, serde_json::Value>,
    pub ast_cache_limit: usize,
    pub tool_cache_limit: usize,
}

impl CacheManager {
    pub fn new() -> Self {
        let ast_limit = std::env::var(ENV_AST_CACHE_LIMIT)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .and_then(NonZeroUsize::new)
            .map(|n| n.get())
            .unwrap_or(DEFAULT_AST_CACHE_ENTRIES);

        let ast_cache = Cache::builder().max_capacity(ast_limit as u64).build();

        let tool_limit = std::env::var(ENV_TOOL_CACHE_LIMIT)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .and_then(NonZeroUsize::new)
            .map(|n| n.get())
            .unwrap_or(DEFAULT_TOOL_CACHE_ENTRIES);

        let tool_cache = Cache::builder()
            .max_capacity(tool_limit as u64)
            .support_invalidation_closures()
            .build();

        Self {
            ast_cache,
            tool_cache,
            ast_cache_limit: ast_limit,
            tool_cache_limit: tool_limit,
        }
    }

    pub fn stats(&self) -> AstCacheStats {
        AstCacheStats {
            ast_entries: self.ast_cache.entry_count() as usize,
            ast_max: self.ast_cache_limit,
            tool_entries: self.tool_cache.entry_count() as usize,
            tool_max: self.tool_cache_limit,
        }
    }

    #[allow(dead_code)]
    pub async fn get_analysis(&self, path: &Path) -> Option<FileAnalysis> {
        let path_buf = path.to_path_buf();
        self.ast_cache.get(&path_buf).await.map(|c| c.analysis)
    }

    #[allow(dead_code)]
    pub async fn insert_analysis(&self, path: PathBuf, analysis: FileAnalysis) {
        self.ast_cache
            .insert(path, CachedAnalysis { analysis })
            .await;
    }

    pub fn invalidate_tool_cache_for_file(&self, root: &Path, path: &Path) {
        let absolute = path.to_string_lossy().into_owned();
        let relative = path
            .strip_prefix(root)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let _ = self.tool_cache.invalidate_entries_if(move |key, _value| {
            let Ok(args) = serde_json::from_str::<serde_json::Value>(&key.canonical_args) else {
                return false;
            };

            json_contains_path(&args, &absolute, relative.as_deref())
        });
    }

    pub fn invalidate_tool_cache_for_root(&self, _root: &Path) {
        self.tool_cache.invalidate_all();
    }
}

fn json_contains_path(value: &serde_json::Value, absolute: &str, relative: Option<&str>) -> bool {
    match value {
        serde_json::Value::String(s) => s == absolute || relative.is_some_and(|rel| s == rel),
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| json_contains_path(item, absolute, relative)),
        serde_json::Value::Object(map) => map
            .values()
            .any(|item| json_contains_path(item, absolute, relative)),
        _ => false,
    }
}
