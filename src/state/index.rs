use anyhow::Result;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;

use crate::indexer::FileIndex;

pub struct IndexManager {
    pub index: RwLock<FileIndex>,
    pub index_ready: AtomicBool,
    pub watch_refresh_running: AtomicBool,
    pub watch_refresh_pending: AtomicBool,
}

impl IndexManager {
    pub fn new(root: &Path) -> Result<Self> {
        let index = FileIndex::build(root)?;
        Ok(Self {
            index: RwLock::new(index),
            index_ready: AtomicBool::new(true),
            watch_refresh_running: AtomicBool::new(false),
            watch_refresh_pending: AtomicBool::new(false),
        })
    }

    pub async fn ensure_ready(&self, root: &Path) -> Result<()> {
        if self.index_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut lock = self.index.write().await;
        if self.index_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        let root_clone = root.to_path_buf();
        let built = tokio::task::spawn_blocking(move || FileIndex::build(&root_clone)).await??;
        *lock = built;
        self.index_ready.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn rebuild(&self, root: &Path) -> Result<FileIndex> {
        let new_index = FileIndex::build(root)?;
        let mut lock = self.index.write().await;
        *lock = new_index.clone();
        self.index_ready.store(true, Ordering::Release);
        Ok(new_index)
    }

    pub async fn file_index(&self, root: &Path) -> Result<FileIndex> {
        self.ensure_ready(root).await?;
        Ok(self.index.read().await.clone())
    }
}
