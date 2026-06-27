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

/// Returns server statistics: AST and tool cache utilization, file index metadata, and runtime configuration.
pub(super) async fn get_server_stats() -> Result<Value> {
    let state = crate::state::ServerState::get();
    let stats = state.get_cache_stats().await;
    let index = state.index().await?;
    let invocation_counts = state.get_tool_invocation_counts();
    let uptime_secs = state.uptime_seconds();

    let stats_json = json!({
        "uptime_seconds": uptime_secs,
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
        "index": {
            "allowed_files": index.allowed_files.len(),
            "restricted_files": index.restricted_files.len(),
        },
        "tool_invocations": invocation_counts,
        "root": state.root().display().to_string()
    });

    let msg = format!(
        "## Server Statistics\n\n\
         **Uptime**: {} seconds\n\n\
         ### AST Cache\n\
         - Entries: {}/{} ({:.1}% full)\n\n\
         ### Tool Cache\n\
         - Entries: {}/{} ({:.1}% full)\n\n\
         ### Project Index\n\
         - Allowed files: {}\n\
         - Restricted files: {}\n\n\
         ### Tool Invocations (this session)\n\
         {}\n\n\
         **Raw JSON:**\n```json\n{}\n```",
        uptime_secs,
        stats.ast_entries,
        stats.ast_max,
        utilization_f64(stats.ast_entries, stats.ast_max),
        stats.tool_entries,
        stats.tool_max,
        utilization_f64(stats.tool_entries, stats.tool_max),
        index.allowed_files.len(),
        index.restricted_files.len(),
        format_invocation_table(&invocation_counts),
        serde_json::to_string_pretty(&stats_json)?
    );

    Ok(tool_response(vec![text_content(msg)]))
}

fn format_invocation_table(counts: &std::collections::HashMap<String, u64>) -> String {
    if counts.is_empty() {
        return "No tools invoked yet in this session.".to_string();
    }
    let mut entries: Vec<_> = counts.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0))); // sort by count desc, then name asc
    entries
        .iter()
        .map(|(name, count)| format!("- `{}`: {} calls", name, count))
        .collect::<Vec<_>>()
        .join("\n")
}

fn utilization(entries: usize, max_entries: usize) -> usize {
    entries
        .checked_mul(100)
        .and_then(|v| v.checked_div(max_entries))
        .unwrap_or(0)
}

fn utilization_f64(entries: usize, max_entries: usize) -> f64 {
    if max_entries == 0 {
        0.0
    } else {
        (entries as f64 / max_entries as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_invocation_table_sorts_by_frequency() {
        use std::collections::HashMap;
        let mut counts = HashMap::new();
        counts.insert("get_file_outline".to_owned(), 5u64);
        counts.insert("inspect_symbol".to_owned(), 10u64);
        let table = format_invocation_table(&counts);
        // inspect_symbol (10) must appear before get_file_outline (5)
        assert!(table.find("inspect_symbol").unwrap() < table.find("get_file_outline").unwrap());
    }
}
