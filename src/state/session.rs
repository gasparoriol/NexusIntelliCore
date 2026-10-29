use std::sync::{Arc, PoisonError, RwLock};

/// Per-connection state. One `Session` is created for each MCP transport, so two
/// clients connected to the same registry never overwrite each other's active project.
#[derive(Default)]
pub struct Session {
    active_project_id: RwLock<Option<String>>,
}

impl Session {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn active_project_id(&self) -> Option<String> {
        self.active_project_id
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_active_project_id(&self, id: String) {
        *self
            .active_project_id
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(id);
    }
}
