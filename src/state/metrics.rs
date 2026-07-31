use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

pub struct MetricsCollector {
    pub started_at: Instant,
    pub ast_cache_hits: AtomicU64,
    pub ast_cache_misses: AtomicU64,
    pub tool_cache_hits: AtomicU64,
    pub tool_cache_misses: AtomicU64,
    pub tool_concurrency_rejections: AtomicU64,
    pub tool_invocation_counts: Mutex<HashMap<String, u64>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            ast_cache_hits: AtomicU64::new(0),
            ast_cache_misses: AtomicU64::new(0),
            tool_cache_hits: AtomicU64::new(0),
            tool_cache_misses: AtomicU64::new(0),
            tool_concurrency_rejections: AtomicU64::new(0),
            tool_invocation_counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_tool_invocation(&self, tool_name: &str) {
        if let Ok(mut map) = self.tool_invocation_counts.lock() {
            *map.entry(tool_name.to_owned()).or_insert(0) += 1;
        }
    }

    pub fn record_ast_hit(&self) {
        self.ast_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ast_miss(&self) {
        self.ast_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tool_hit(&self) {
        self.tool_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tool_miss(&self) {
        self.tool_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_concurrency_rejection(&self) {
        self.tool_concurrency_rejections.fetch_add(1, Ordering::Relaxed);
    }
}
