use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::indexer::FileIndex;
use crate::linter::LintPool;
use crate::state::index::IndexManager;
use crate::state::resolver::{self, TsPathAliasConfig};

/// Encapsulates all state belonging to a single project.
pub struct ProjectContext {
    pub id: String,
    pub root: PathBuf,
    pub lint_pool: LintPool,
    pub is_angular_project: bool,
    pub ts_path_aliases: Vec<TsPathAliasConfig>,
    pub index_mgr: IndexManager,
}

impl ProjectContext {
    pub fn new(root_str: &str, id: Option<String>) -> Result<Arc<Self>> {
        let root = std::fs::canonicalize(root_str)
            .with_context(|| format!("Failed to canonicalise project root: {root_str}"))?;

        let project_id = id.unwrap_or_else(|| {
            root.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(root_str)
                .to_string()
        });

        let index_mgr = IndexManager::new(&root)?;
        let is_angular = index_mgr
            .index
            .try_read()
            .expect("freshly constructed index lock should not be contended")
            .allowed_files
            .iter()
            .any(|p| p.to_string_lossy().contains("angular.json"));

        let ts_path_aliases = resolver::PathResolver::discover_ts_path_aliases(&root);
        let lint_pool = LintPool::init(&root);

        Ok(Arc::new(Self {
            id: project_id,
            root,
            lint_pool,
            is_angular_project: is_angular,
            ts_path_aliases,
            index_mgr,
        }))
    }

    #[allow(dead_code)]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn validate_path(&self, requested: &Path) -> Result<PathBuf> {
        resolver::PathResolver::validate_path(&self.root, requested)
    }

    pub async fn index(&self) -> Result<FileIndex> {
        self.index_mgr.file_index(&self.root).await
    }

    pub async fn refresh_index(&self) -> Result<(usize, u64)> {
        let new_index = self.index_mgr.rebuild(&self.root).await?;
        let files_found = new_index.allowed_files.len() + new_index.restricted_files.len();

        let state = crate::state::ServerState::get();
        state.invalidate_tool_cache_for_root(&self.root);
        let cleared_count = state.invalidate_ast_cache_for_root(&self.root);

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
            debug!(project = %self.id, "Watcher refresh requested; loop claimed by this thread");
            let project = Arc::clone(self);
            tokio::spawn(async move {
                project.run_watcher_refresh_loop().await;
            });
        } else {
            debug!(project = %self.id, "Watcher refresh requested; coalesced with active refresh loop");
        }
    }

    async fn run_watcher_refresh_loop(&self) {
        loop {
            let pending = self
                .index_mgr
                .watch_refresh_pending
                .swap(false, Ordering::AcqRel);
            if !pending {
                debug!(project = %self.id, "No watcher refreshes pending; releasing running flag");
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
                    debug!(project = %self.id, "Re-claimed running flag in close-race check; continuing loop");
                    continue;
                }
                break;
            }

            info!(project = %self.id, "Executing watcher-triggered index refresh pass");
            match self.refresh_index().await {
                Ok((files, ast_cleared)) => {
                    info!(
                        project = %self.id,
                        files_found = files,
                        ast_entries_cleared = ast_cleared,
                        "Watcher-triggered index refresh completed successfully"
                    );
                }
                Err(err) => {
                    warn!(
                        project = %self.id,
                        error = %err,
                        "Watcher-triggered index refresh failed; will retry on next file event"
                    );
                }
            }
        }
    }
}
