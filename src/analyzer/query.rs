use anyhow::{Context, Result};
use tree_sitter::{Language, Query, QueryCursor};

/// Run a named tree-sitter query and map each match through `f`.
/// `f` receives `(match_index, Vec<(capture_name, Node, text)>)`.
pub(crate) fn run_named_query<T>(
    language: &Language,
    query_str: &str,
    root: tree_sitter::Node<'_>,
    source: &str,
    mut f: impl FnMut(usize, Vec<(String, tree_sitter::Node<'_>, String)>) -> Option<T>,
) -> Result<Vec<T>> {
    let query = Query::new(language, query_str)
        .with_context(|| format!("Failed to compile tree-sitter query: {query_str}"))?;

    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, root, source.as_bytes());

    let mut results = Vec::new();

    for m in matches {
        let mut caps = Vec::new();
        for cap in m.captures {
            let node = cap.node;
            let name = query.capture_names()[cap.index as usize].to_owned();
            let text = source[node.byte_range()].to_owned();
            caps.push((name, node, text));
        }

        if let Some(res) = f(m.pattern_index, caps) {
            results.push(res);
        }
    }

    Ok(results)
}
