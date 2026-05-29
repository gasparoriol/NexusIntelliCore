//! File-system watcher for cache invalidation.
//!
//! `FileWatcher` watches the project root and routes events to `ServerState`:
//! content changes invalidate AST cache entries and topological changes
//! (create/remove/rename) request an index refresh.
//!
//! # Design notes
//! * Uses `notify::RecommendedWatcher` (FSEvents on macOS, inotify on Linux).
//! * Events are processed on a dedicated Tokio task; the watcher itself runs
//!   on a notify-internal thread and forwards events via a standard channel.
//! * The watcher is intentionally best-effort: if it fails to start (e.g. the
//!   OS limit for inotify watches is reached) the server continues without
//!   automatic invalidation. Users can always call `refresh_index` manually.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use notify::event::ModifyKind;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, warn};

use crate::state::ServerState;

/// Debounce window for topological file-system changes.
const INDEX_REFRESH_DEBOUNCE: Duration = Duration::from_millis(500);

enum WatchAction {
    Ignore,
    InvalidateCache(Vec<PathBuf>),
    ScheduleIndexRefresh,
}

fn is_rename_modify_kind(kind: &ModifyKind) -> bool {
    matches!(kind, ModifyKind::Name(_))
}

fn classify_event(event: &Event) -> WatchAction {
    match &event.kind {
        EventKind::Modify(kind) if is_rename_modify_kind(kind) => WatchAction::ScheduleIndexRefresh,
        EventKind::Modify(_) => WatchAction::InvalidateCache(event.paths.clone()),
        EventKind::Create(_) | EventKind::Remove(_) => WatchAction::ScheduleIndexRefresh,
        _ => WatchAction::Ignore,
    }
}

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
        // Notify emits events via the callback channel. We read them in a
        // blocking loop and forward actions to server state.
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
        let refresh_debounce_active = Arc::new(AtomicBool::new(false));

        let task = tokio::task::spawn_blocking(move || {
            let rt_handle = tokio::runtime::Handle::current();
            loop {
                // Block until the next batch of events (or channel close).
                let event = {
                    let rx = rx.lock().unwrap();
                    rx.recv()
                };

                match event {
                    Ok(Ok(ev)) => {
                        match classify_event(&ev) {
                            WatchAction::InvalidateCache(paths) => {
                                let state = ServerState::get();
                                for path in &paths {
                                    debug!(path = %path.display(), "Cache invalidation triggered");
                                    // Evict single entry; errors are silently
                                    // ignored (entry may not be cached yet).
                                    let _ = state.evict_cache_entry(path);
                                }
                            }
                            WatchAction::ScheduleIndexRefresh => {
                                if refresh_debounce_active
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                                {
                                    let refresh_debounce_active =
                                        Arc::clone(&refresh_debounce_active);
                                    rt_handle.spawn(async move {
                                        tokio::time::sleep(INDEX_REFRESH_DEBOUNCE).await;

                                        ServerState::get().request_watcher_refresh();

                                        refresh_debounce_active.store(false, Ordering::Release);
                                    });
                                } else {
                                    debug!("Index refresh already scheduled, coalescing event");
                                }
                            }
                            WatchAction::Ignore => {}
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
