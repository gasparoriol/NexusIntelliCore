use anyhow::Result;
use serde_json::json;
use serde_json::Value;
use std::path::Path;

use crate::protocol::{error_response, text_content, tool_response};
use crate::sanitizer;

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB, matches analyzer::parse::analyze_file

pub(super) async fn read_config_file(
    state: &crate::state::ServerState,
    file_path: &str,
) -> Result<Value> {
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {e}"))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied: {file_path} is protected by .mcpignore."
        ))]));
    }
    drop(index);

    if !sanitizer::is_config_file(&path) {
        return Ok(error_response(format!(
            "read_config_file only supports configuration files (.properties, .yaml, .yml, .toml, .env): {file_path}"
        )));
    }

    let path_for_read = path.clone();
    let source = match tokio::task::spawn_blocking(move || {
        let metadata = std::fs::metadata(&path_for_read)?;
        if metadata.len() > MAX_FILE_SIZE {
            anyhow::bail!(
                "File exceeds maximum size ({} bytes > {MAX_FILE_SIZE} bytes)",
                metadata.len()
            );
        }
        std::fs::read_to_string(&path_for_read).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(Ok(content)) => content,
        Ok(Err(e)) => return Ok(error_response(format!("Cannot read file: {e}"))),
        Err(e) => return Ok(error_response(format!("Cannot read file: {e}"))),
    };

    let (sanitized_content, redactions) = sanitizer::sanitize_config_text(&source);

    let payload = json!({
        "status": "ok",
        "file_path": file_path,
        "content": sanitized_content,
        "redactions": redactions,
    });

    Ok(tool_response(vec![text_content(payload.to_string())]))
}
