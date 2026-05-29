use anyhow::Result;
use serde_json::{json, Value};

use crate::protocol::{error_response, text_content, tool_response};

/// Rebuilds the project file index from disk and clears the AST cache.
/// Use this when files are added/removed or to free memory.
pub(super) async fn refresh_index() -> Result<Value> {
    let state = crate::state::ServerState::get();

    // Rebuild index and clear cache
    let (files_found, cache_cleared) = match state.refresh_index().await {
        Ok((files, cleared)) => (files, cleared),
        Err(e) => return Ok(error_response(format!("Index rebuild failed: {}", e))),
    };

    let msg = format!(
        "Index refreshed successfully:\n\
         • Files indexed: {}\n\
         • AST cache entries cleared: {}\n\
         \n\
         The project index and AST cache are now up-to-date with the current filesystem state.",
        files_found, cache_cleared
    );

    Ok(tool_response(vec![text_content(msg)]))
}

/// Returns server statistics: cache size, index metadata, uptime.
/// Debug-only tool (requires RUST_LOG=debug).
pub(super) async fn get_server_stats() -> Result<Value> {
    // Check if debug logging is enabled
    if std::env::var("RUST_LOG")
        .ok()
        .map(|s| !s.contains("debug"))
        .unwrap_or(true)
    {
        return Ok(tool_response(vec![text_content(
            "⚠ get_server_stats is only available in debug mode.\n\
             Enable with: RUST_LOG=debug or higher (trace)"
                .to_string(),
        )]));
    }

    let state = crate::state::ServerState::get();
    let (cache_entries, cache_max) = state.get_cache_stats().await;
    let index = state.index().await?;

    let stats_json = json!({
        "cache": {
            "entries": cache_entries,
            "max_entries": cache_max,
            "utilization_percent": if cache_max > 0 { (cache_entries * 100) / cache_max } else { 0 }
        },
        "index": {
            "allowed_files": index.allowed_files.len(),
            "restricted_files": index.restricted_files.len(),
            "total_files": index.allowed_files.len() + index.restricted_files.len()
        },
        "root": state.root().display().to_string()
    });

    let msg = format!(
        "## Server Statistics\n\n\
         ### AST Cache\n\
         - Entries: {}/{} ({:.1}% full)\n\
         \n\
         ### Project Index\n\
         - Allowed files: {}\n\
         - Restricted files: {}\n\
         - Total files: {}\n\
         \n\
         ### Configuration\n\
         - Root: {}\n\
         \n\
         **Raw JSON:**\n\
         ```json\n\
         {}\n\
         ```",
        cache_entries,
        cache_max,
        if cache_max > 0 {
            (cache_entries as f64 / cache_max as f64) * 100.0
        } else {
            0.0
        },
        index.allowed_files.len(),
        index.restricted_files.len(),
        index.allowed_files.len() + index.restricted_files.len(),
        state.root().display(),
        serde_json::to_string_pretty(&stats_json)?
    );

    Ok(tool_response(vec![text_content(msg)]))
}
