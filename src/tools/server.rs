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
    let stats = state.get_cache_stats().await;
    let index = state.index().await?;

    let stats_json = json!({
        "ast_cache": {
            "entries": stats.ast_entries,
            "max_entries": stats.ast_max,
            "utilization_percent": utilization(stats.ast_entries, stats.ast_max)
        },
        "tool_cache": {
            "entries": stats.tool_entries,
            "max_entries": stats.tool_max,
            "utilization_percent": utilization(stats.tool_entries, stats.tool_max)
        },
        // ...
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
        stats.ast_entries,
        stats.ast_max,
        utilization(stats.ast_entries, stats.ast_max),
        index.allowed_files.len(),
        index.restricted_files.len(),
        index.allowed_files.len() + index.restricted_files.len(),
        state.root().display(),
        serde_json::to_string_pretty(&stats_json)?
    );

    Ok(tool_response(vec![text_content(msg)]))
}

fn utilization(entries: usize, max_entries: usize) -> f64 {
    if max_entries == 0 {
        0.0
    } else {
        (entries as f64 / max_entries as f64) * 100.0
    }
}
