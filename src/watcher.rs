//! File-system watcher for cache invalidation.
//!
//! `FileWatcher` watches the project root and routes events to `ServerState`:
//! content changes invalidate AST cache entries and topological changes
//! (create/remove/rename) request an index refresh.
//!
//! # Design notes
//! * Uses `notify::RecommendedWatcher` (`FSEvents` on macOS, `inotify` on Linux).
//! * Events are processed on a dedicated Tokio task; the watcher itself runs
//!   on a notify-internal thread and forwards events via a standard channel.
//! * The watcher is intentionally best-effort: if it fails to start (e.g. the
//!   OS limit for inotify watches is reached) the server continues without
//!   automatic invalidation. Users can always call `refresh_index` manually.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use notify::event::ModifyKind;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, warn};

use crate::state::ServerState;

/// Debounce window for topological file-system changes.
const INDEX_REFRESH_DEBOUNCE: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub(crate) enum WatchAction {
    Ignore,
    InvalidateCache(Vec<PathBuf>),
    ScheduleIndexRefresh,
}

pub(crate) fn is_rename_modify_kind(kind: ModifyKind) -> bool {
    matches!(kind, ModifyKind::Name(_))
}

pub(crate) fn classify_event(event: &Event) -> WatchAction {
    match &event.kind {
        EventKind::Modify(kind) if is_rename_modify_kind(*kind) => {
            WatchAction::ScheduleIndexRefresh
        }
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
    pub fn start(root: &Path) -> Option<Self> {
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

        if let Err(e) = watcher.watch(root, RecursiveMode::Recursive) {
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
                                let root = state.root().to_owned();
                                rt_handle.spawn(async move {
                                    ServerState::get().invalidate_tool_cache_for_root(&root);
                                });
                                for path in &paths {
                                    debug!(path = %path.display(), "Cache invalidation triggered");
                                    // Evict single entry; errors are silently
                                    // ignored (entry may not be cached yet).
                                    rt_handle.block_on(state.evict_cache_entry(path));
                                }
                            }
                            WatchAction::ScheduleIndexRefresh => {
                                let state = ServerState::get();
                                let root = state.root().to_owned();
                                rt_handle.spawn(async move {
                                    ServerState::get().invalidate_tool_cache_for_root(&root);
                                });
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

                                        // Clear the debounce flag BEFORE signalling state.
                                        // Any topological event that arrives in this narrow
                                        // window will then succeed its CAS and arm a fresh
                                        // debounce timer rather than being silently coalesced
                                        // with no pending request outstanding.
                                        refresh_debounce_active.store(false, Ordering::Release);
                                        ServerState::get().request_watcher_refresh();
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, DataChange, EventAttributes, RemoveKind, RenameMode};

    fn ev(kind: EventKind) -> Event {
        Event {
            kind,
            paths: vec![],
            attrs: EventAttributes::default(),
        }
    }

    fn ev_with_paths(kind: EventKind, paths: Vec<PathBuf>) -> Event {
        Event {
            kind,
            paths,
            attrs: EventAttributes::default(),
        }
    }

    // --- classify_event --------------------------------------------------

    #[test]
    fn create_file_schedules_refresh() {
        assert!(matches!(
            classify_event(&ev(EventKind::Create(CreateKind::File))),
            WatchAction::ScheduleIndexRefresh
        ));
    }

    #[test]
    fn create_folder_schedules_refresh() {
        assert!(matches!(
            classify_event(&ev(EventKind::Create(CreateKind::Folder))),
            WatchAction::ScheduleIndexRefresh
        ));
    }

    #[test]
    fn remove_file_schedules_refresh() {
        assert!(matches!(
            classify_event(&ev(EventKind::Remove(RemoveKind::File))),
            WatchAction::ScheduleIndexRefresh
        ));
    }

    #[test]
    fn remove_folder_schedules_refresh() {
        assert!(matches!(
            classify_event(&ev(EventKind::Remove(RemoveKind::Folder))),
            WatchAction::ScheduleIndexRefresh
        ));
    }

    #[test]
    fn rename_modify_schedules_refresh() {
        let ev = ev(EventKind::Modify(ModifyKind::Name(RenameMode::Both)));
        assert!(matches!(
            classify_event(&ev),
            WatchAction::ScheduleIndexRefresh
        ));
    }

    #[test]
    fn data_modify_invalidates_cache_with_paths() {
        let path = PathBuf::from("/tmp/foo.rs");
        let ev = ev_with_paths(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            vec![path.clone()],
        );
        let result = classify_event(&ev);
        assert!(
            matches!(result, WatchAction::InvalidateCache(_)),
            "expected InvalidateCache, but got: {result:?}"
        );
        if let WatchAction::InvalidateCache(paths) = result {
            assert_eq!(paths, vec![path]);
        }
    }

    #[test]
    fn data_modify_any_invalidates_cache() {
        let ev = ev(EventKind::Modify(ModifyKind::Data(DataChange::Any)));
        assert!(matches!(
            classify_event(&ev),
            WatchAction::InvalidateCache(_)
        ));
    }

    #[test]
    fn access_event_is_ignored() {
        use notify::event::{AccessKind, AccessMode};
        let ev = ev(EventKind::Access(AccessKind::Open(AccessMode::Read)));
        assert!(matches!(classify_event(&ev), WatchAction::Ignore));
    }

    #[test]
    fn other_event_is_ignored() {
        let ev = ev(EventKind::Other);
        assert!(matches!(classify_event(&ev), WatchAction::Ignore));
    }

    // --- is_rename_modify_kind -------------------------------------------

    #[test]
    fn rename_mode_both_is_rename() {
        assert!(is_rename_modify_kind(ModifyKind::Name(RenameMode::Both)));
    }

    #[test]
    fn rename_mode_from_is_rename() {
        assert!(is_rename_modify_kind(ModifyKind::Name(RenameMode::From)));
    }

    #[test]
    fn rename_mode_to_is_rename() {
        assert!(is_rename_modify_kind(ModifyKind::Name(RenameMode::To)));
    }

    #[test]
    fn data_change_is_not_rename() {
        assert!(!is_rename_modify_kind(ModifyKind::Data(
            DataChange::Content
        )));
    }

    #[test]
    fn modify_any_is_not_rename() {
        assert!(!is_rename_modify_kind(ModifyKind::Any));
    }
}
