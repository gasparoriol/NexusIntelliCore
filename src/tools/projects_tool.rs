use anyhow::Result;
use serde_json::{json, Value};

use crate::protocol::{error_response, text_content, tool_response};
use crate::state::{ServerState, Session};

pub(super) async fn list_projects(state: &ServerState, session: &Session) -> Result<Value> {
    let mut projects = state.list_projects();
    projects.sort_by(|a, b| a.0.cmp(&b.0));
    let active_id = state.active_project_id(session);
    let mut project_list = Vec::new();

    for (id, root) in projects {
        let active = active_id.as_deref() == Some(id.as_str());
        let stats = if let Ok(proj) = state.get_project(Some(&id)) {
            if let Ok(idx) = proj.index().await {
                json!({
                    "id": id,
                    "root": root.to_string_lossy(),
                    "active": active,
                    "allowed_files": idx.allowed_files.len(),
                    "restricted_files": idx.restricted_files.len(),
                    "is_angular": proj.is_angular_project,
                })
            } else {
                json!({
                    "id": id,
                    "root": root.to_string_lossy(),
                    "active": active,
                    "status": "indexing_pending"
                })
            }
        } else {
            json!({
                "id": id,
                "root": root.to_string_lossy(),
                "active": active
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

pub(super) async fn register_project(
    state: &ServerState,
    session: &Session,
    args: &Value,
) -> Result<Value> {
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
    let set_active = args
        .get("set_active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let index = args.get("index").and_then(Value::as_bool).unwrap_or(true);

    let proj = match state.register_project(path, project_id) {
        Ok(proj) => proj,
        Err(e) => return Ok(error_response(format!("Failed to register project: {e}"))),
    };

    let mut message = format!(
        "Successfully registered project '{}' at root: {}",
        proj.id,
        proj.root.display()
    );
    if set_active {
        session.set_active_project_id(proj.id.clone());
        message.push_str("\nActive project for this session: true");
    }
    if index {
        match proj.index().await {
            Ok(idx) => message.push_str(&format!(
                "\nFiles indexed: {}",
                idx.allowed_files.len() + idx.restricted_files.len()
            )),
            Err(e) => {
                return Ok(error_response(format!(
                    "Project registered but indexing failed: {e}"
                )))
            }
        }
    }
    Ok(tool_response(vec![text_content(message)]))
}

pub(super) async fn set_active_project(
    state: &ServerState,
    session: &Session,
    args: &Value,
) -> Result<Value> {
    let key = args
        .get("project_id")
        .or_else(|| args.get("root_path"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: project_id"))?;

    let proj = match state.get_project(Some(key)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(e.to_string())),
    };
    let idx = match proj.index().await {
        Ok(idx) => idx,
        Err(e) => return Ok(error_response(format!("Failed to index project: {e}"))),
    };
    session.set_active_project_id(proj.id.clone());

    Ok(tool_response(vec![text_content(
        serde_json::to_string_pretty(&json!({
            "active_project_id": proj.id,
            "root": proj.root.display().to_string(),
            "files_indexed": idx.allowed_files.len() + idx.restricted_files.len(),
        }))?,
    )]))
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
