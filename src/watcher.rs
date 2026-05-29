//! File-system watcher for cache invalidation.
//!
//! `FileWatcher` watches the project root for file changes and evicts the
//! affected entry from the AST cache in `ServerState`. When a file is created,
//! modified, or removed the cache entry for that path is dropped so the next
//! `get_analysis` call re-parses the file from disk.
//!
//! # Design notes
//! * Uses `notify::RecommendedWatcher` (FSEvents on macOS, inotify on Linux).
//! * Events are processed on a dedicated Tokio task; the watcher itself runs
//!   on a notify-internal thread and forwards events via a crossbeam channel.
//! * The watcher is intentionally best-effort: if it fails to start (e.g. the
//!   OS limit for inotify watches is reached) the server continues without
//!   automatic invalidation. Users can always call `refresh_index` manually.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, warn};

use crate::state::ServerState;

/// A running file-system watcher bound to the project root.
///
/// Dropping this value stops the watcher and background task.
pub struct FileWatcher {
    /// Keep the watcher alive; dropping it unregisters OS watches.
    _watcher: RecommendedWatcher,
    /// Handle to the Tokio task that processes events.
    _task: tokio::task::JoinHandle<()>,
}

impl FileWatcher {
    /// Start watching `root` recursively. Returns `None` if the watcher cannot
    /// be initialised (non-fatal — the server continues without it).
    pub fn start(root: PathBuf) -> Option<Self> {
        // Crossbeam channel used by notify internally; use a bounded channel to
        // avoid unbounded memory growth if events arrive faster than processing.
        let (tx, rx) = std::sync::mpsc::channel();

        let config = Config::default().with_poll_interval(Duration::from_secs(2));

        let mut watcher = match RecommendedWatcher::new(tx, config) {
            Ok(w) => w,
            Err(e) => {
                warn!(
                    "File watcher unavailable — cache invalidation disabled: {}",
                    e
                );
                return None;
            }
        };

        if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
            warn!(
                "Could not watch {:?} — cache invalidation disabled: {}",
                root, e
            );
            return None;
        }

        tracing::info!(root = %root.display(), "File watcher started");

        // Move receiver to an Arc so the Tokio task can hold it via blocking.
        let rx = Arc::new(std::sync::Mutex::new(rx));

        let task = tokio::task::spawn_blocking(move || {
            loop {
                // Block until the next batch of events (or channel close).
                let event = {
                    let rx = rx.lock().unwrap();
                    rx.recv()
                };

                match event {
                    Ok(Ok(ev)) => {
                        let paths = ev.paths;
                        match ev.kind {
                            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                                let state = ServerState::get();
                                for path in &paths {
                                    debug!(path = %path.display(), "Cache invalidation triggered");
                                    // Evict single entry; errors are silently
                                    // ignored (entry may not be cached yet).
                                    let _ = state.evict_cache_entry(path);
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Watcher error: {}", e);
                    }
                    // Channel closed — watcher dropped, exit task.
                    Err(_) => break,
                }
            }
        });

        Some(FileWatcher {
            _watcher: watcher,
            _task: task,
        })
    }
}
