use anyhow::Result;
use serde_json::{json, Value};

use crate::protocol::{error_response, text_content, tool_response};
use crate::state::ServerState;

pub(super) async fn list_projects(state: &ServerState) -> Result<Value> {
    let projects = state.list_projects();
    let mut project_list = Vec::new();

    for (id, root) in projects {
        let stats = if let Ok(proj) = state.get_project(Some(&id)) {
            if let Ok(idx) = proj.index().await {
                json!({
                    "id": id,
                    "root": root.to_string_lossy(),
                    "allowed_files": idx.allowed_files.len(),
                    "restricted_files": idx.restricted_files.len(),
                    "is_angular": proj.is_angular_project,
                })
            } else {
                json!({
                    "id": id,
                    "root": root.to_string_lossy(),
                    "status": "indexing_pending"
                })
            }
        } else {
            json!({
                "id": id,
                "root": root.to_string_lossy()
            })
        };
        project_list.push(stats);
    }

    Ok(tool_response(vec![text_content(
        serde_json::to_string_pretty(&json!({
            "count": project_list.len(),
            "projects": project_list
        }))?,
    )]))
}

pub(super) async fn register_project(state: &ServerState, args: &Value) -> Result<Value> {
    let path = args
        .get("path")
        .or_else(|| args.get("root"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: path"))?;

    let project_id = args
        .get("project_id")
        .or_else(|| args.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    match state.register_project(path, project_id) {
        Ok(proj) => Ok(tool_response(vec![text_content(format!(
            "Successfully registered project '{}' at root: {}",
            proj.id,
            proj.root.display()
        ))])),
        Err(e) => Ok(error_response(format!("Failed to register project: {e}"))),
    }
}

pub(super) async fn unregister_project(state: &ServerState, args: &Value) -> Result<Value> {
    let id_or_path = args
        .get("project_id")
        .or_else(|| args.get("id"))
        .or_else(|| args.get("path"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: project_id or path"))?;

    match state.unregister_project(id_or_path) {
        Ok(true) => Ok(tool_response(vec![text_content(format!(
            "Successfully unregistered project: {id_or_path}"
        ))])),
        Ok(false) => Ok(error_response(format!("Project not found: {id_or_path}"))),
        Err(e) => Ok(error_response(format!("Failed to unregister project: {e}"))),
    }
}
