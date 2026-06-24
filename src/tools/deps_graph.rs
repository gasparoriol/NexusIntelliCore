use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashSet;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

/// Default and maximum limits for get_dependencies_graph
const DEFAULT_MAX_NODES: usize = 100;
const MAX_EDGES_PER_NODE: usize = 50;
const MAX_RESPONSE_BYTES: usize = 25 * 1024; // 25 KB for summary mode

/// Extract parameters from tool arguments with sensible defaults
fn extract_params(args: &Value) -> (String, usize, usize) {
    let mode = args
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("summary")
        .to_string();

    let max_nodes = args
        .get("max_nodes")
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).min(200))
        .unwrap_or(DEFAULT_MAX_NODES);

    let max_edges = args
        .get("max_edges_per_node")
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).min(100))
        .unwrap_or(MAX_EDGES_PER_NODE);

    (mode, max_nodes, max_edges)
}

/// Deduplicate dependency vectors, converting to sets and back
fn deduplicate_deps(deps: Vec<String>) -> Vec<String> {
    let mut set: HashSet<String> = deps.into_iter().collect();
    let mut result: Vec<String> = set.drain().collect();
    result.sort();
    result
}

/// Generate a summary of the full dependency graph
fn generate_summary(file_deps: &serde_json::Map<String, Value>, max_nodes: usize) -> Value {
    let mut total_internal = 0;
    let mut total_restricted = 0;
    let mut total_external: HashSet<String> = HashSet::new();
    let mut total_unresolved = 0;
    let mut fanout_counts: Vec<(String, usize)> = Vec::new();

    for (file, deps_obj) in file_deps.iter().take(max_nodes) {
        if let Some(obj) = deps_obj.as_object() {
            let internal_count = obj
                .get("internal")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let restricted_count = obj
                .get("restricted")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let external_count = obj
                .get("external")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let unresolved_count = obj
                .get("unresolved")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);

            total_internal += internal_count;
            total_restricted += restricted_count;
            total_unresolved += unresolved_count;

            let fanout = internal_count + restricted_count + external_count + unresolved_count;
            if fanout > 0 {
                fanout_counts.push((file.clone(), fanout));
            }

            // Collect unique external libraries
            if let Some(external_arr) = obj.get("external").and_then(|v| v.as_array()) {
                for ext_dep in external_arr {
                    if let Some(s) = ext_dep.as_str() {
                        total_external.insert(s.to_string());
                    }
                }
            }
        }
    }

    // Sort by fanout (descending) to find hotspots
    fanout_counts.sort_by(|a, b| b.1.cmp(&a.1));
    let top_hotspots: Vec<_> = fanout_counts.iter().take(10).collect();

    json!({
        "type": "summary",
        "statistics": {
            "total_files_analyzed": file_deps.len(),
            "total_internal_deps": total_internal,
            "total_restricted_deps": total_restricted,
            "total_external_libs": total_external.len(),
            "total_unresolved": total_unresolved,
        },
        "top_hotspots": top_hotspots
            .iter()
            .map(|(f, c)| json!({ "file": f, "fanout": c }))
            .collect::<Vec<_>>(),
        "applied_limits": {
            "mode": "summary",
            "max_nodes": max_nodes,
            "files_shown": file_deps.len().min(max_nodes),
        },
        "truncated": file_deps.len() > max_nodes,
    })
}

pub(super) async fn get_dependencies_graph(args: &Value) -> Result<Value> {
    let (mode, max_nodes, max_edges) = extract_params(args);

    let state = crate::state::ServerState::get();
    let index = state.index().await?;
    let allowed_files = index.allowed_files.clone();
    let restricted_files = index.restricted_files.clone();
    drop(index);

    // Build a per-file classified dependency map:
    // relative_path → { internal, restricted, external, unresolved }
    let mut file_deps: serde_json::Map<String, Value> = serde_json::Map::new();

    for file in allowed_files.iter().take(max_nodes * 2) {
        let path = match state.validate_path(file) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        let analysis = match state.get_analysis(&path).await {
            Ok(a) => a,
            Err(_) => continue,
        };

        let mut internal: Vec<String> = Vec::new();
        let mut restricted: Vec<String> = Vec::new();
        let mut external: Vec<String> = Vec::new();
        let mut unresolved_list: Vec<String> = Vec::new();

        for imp in &analysis.imports {
            let (resolved_str, kind, _) =
                resolve_import_path(imp, &path, &allowed_files, &restricted_files);
            match kind {
                analyzer::ImportKind::InternalLocal => internal.push(resolved_str),
                analyzer::ImportKind::InternalRestricted => restricted.push(resolved_str),
                analyzer::ImportKind::ExternalLibrary => external.push(imp.path.clone()),
                analyzer::ImportKind::Unresolved => unresolved_list.push(imp.path.clone()),
            }
        }

        // Apply deduplication and truncation per edge type
        internal = deduplicate_deps(internal);
        restricted = deduplicate_deps(restricted);
        external = deduplicate_deps(external);
        unresolved_list = deduplicate_deps(unresolved_list);

        // Truncate edges per node if needed
        internal.truncate(max_edges);
        restricted.truncate(max_edges);
        external.truncate(max_edges);
        unresolved_list.truncate(max_edges);

        file_deps.insert(
            rel,
            json!({
                "internal":   internal,
                "restricted": restricted,
                "external":   external,
                "unresolved": unresolved_list,
            }),
        );

        if file_deps.len() >= max_nodes {
            break;
        }
    }

    // Generate output based on mode
    let output = if mode == "full" {
        Value::Object(file_deps)
    } else {
        generate_summary(&file_deps, max_nodes)
    };

    // Sanitize through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_graph, _redactions) =
        privacy_gateway::sanitize_dependency_graph(&output, &policy);

    // Serialize in compact form (not pretty-print) to reduce output size
    let graph_json_compact =
        serde_json::to_string(&sanitized_graph).unwrap_or_else(|_| "{}".to_string());

    let response_text = if mode == "summary" {
        format!(
            "[Dependency analysis in summary mode (focused on hotspots and metrics)]\n{}",
            graph_json_compact
        )
    } else {
        format!(
            "[Full dependency graph (use summary mode to reduce output)]\n{}",
            graph_json_compact
        )
    };

    Ok(tool_response(vec![text_content(response_text)]))
}

/// Resolve an import to a project-relative path and classify its kind.
///
/// Resolution rules:
/// - `ExternalLibrary` imports are returned as-is (no file lookup).
/// - Relative paths (`./`, `../`) are resolved against `from_file`'s parent
///   directory; we try common source extensions if no extension is present.
/// - Rust `crate::`/`self::`/`super::` and Python/Java dot-notation are
///   normalised and looked up by suffix in the allowed/restricted file lists.
fn resolve_import_path(
    imp: &analyzer::ImportInfo,
    from_file: &std::path::Path,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    // External libraries never resolve to a project file.
    if imp.kind == ImportKind::ExternalLibrary {
        return (imp.path.clone(), ImportKind::ExternalLibrary, None);
    }

    let path = &imp.path;

    // Relative paths — resolve against the importing file's parent directory.
    if path.starts_with("./") || path.starts_with("../") {
        let base = from_file.parent().unwrap_or(std::path::Path::new("/"));
        let candidate = base.join(path);
        for ext in &["", "rs", "ts", "tsx", "js", "py", "java"] {
            let with_ext = if ext.is_empty() {
                candidate.clone()
            } else {
                candidate.with_extension(ext)
            };
            let canon = with_ext
                .components()
                .fold(std::path::PathBuf::new(), |mut acc, c| {
                    match c {
                        std::path::Component::ParentDir => {
                            acc.pop();
                        }
                        std::path::Component::CurDir => {}
                        other => acc.push(other),
                    }
                    acc
                });
            if allowed_files.contains(&canon) {
                let rel = canon.to_string_lossy().into_owned();
                return (rel, ImportKind::InternalLocal, Some(canon));
            }
            if restricted_files.contains(&canon) {
                let rel = canon.to_string_lossy().into_owned();
                return (rel, ImportKind::InternalRestricted, Some(canon));
            }
        }
        return (path.to_owned(), ImportKind::Unresolved, None);
    }

    // Non-relative internal references: normalise separator and search by suffix.
    let normalised = if path.contains("::") {
        path.replace("::", "/")
    } else if path.contains('.') && !path.contains('/') {
        path.replace('.', "/")
    } else {
        path.to_owned()
    };
    let mut normalised = normalised.trim_matches('/').to_owned();

    if normalised.starts_with("crate/") {
        normalised = normalised["crate/".len()..].to_owned();
    } else if normalised.starts_with("self/") {
        normalised = normalised["self/".len()..].to_owned();
    }
    while normalised.starts_with("super/") {
        normalised = normalised["super/".len()..].to_owned();
    }

    for file in allowed_files {
        let file_str = file.to_string_lossy();
        let stem = file_str
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");
        if stem.ends_with(&normalised) || file_str.contains(&normalised) {
            let rel = file_str.into_owned();
            return (rel, ImportKind::InternalLocal, Some(file.clone()));
        }
    }
    for file in restricted_files {
        let file_str = file.to_string_lossy();
        let stem = file_str
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");
        if stem.ends_with(&normalised) || file_str.contains(&normalised) {
            let rel = file_str.into_owned();
            return (rel, ImportKind::InternalRestricted, Some(file.clone()));
        }
    }

    (normalised, ImportKind::Unresolved, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{ImportInfo, ImportKind};
    use std::path::{Path, PathBuf};

    #[test]
    fn test_resolve_import_path_rust_crate() {
        let allowed = vec![
            PathBuf::from("src/main.rs"),
            PathBuf::from("src/analyzer.rs"),
            PathBuf::from("src/tools/deps_graph.rs"),
        ];
        let restricted = vec![];

        let imp = ImportInfo {
            raw: "use crate::analyzer;".to_owned(),
            path: "crate::analyzer".to_owned(),
            kind: ImportKind::InternalLocal,
            resolved_path: None,
        };

        let (resolved, kind, path_opt) =
            resolve_import_path(&imp, Path::new("src/main.rs"), &allowed, &restricted);

        assert_eq!(kind, ImportKind::InternalLocal);
        assert_eq!(resolved, "src/analyzer.rs");
        assert_eq!(path_opt, Some(PathBuf::from("src/analyzer.rs")));
    }

    #[test]
    fn test_resolve_import_path_rust_super() {
        let allowed = vec![
            PathBuf::from("src/main.rs"),
            PathBuf::from("src/state.rs"),
            PathBuf::from("src/tools/deps_graph.rs"),
        ];
        let restricted = vec![];

        let imp = ImportInfo {
            raw: "use super::super::state;".to_owned(),
            path: "super::super::state".to_owned(),
            kind: ImportKind::InternalLocal,
            resolved_path: None,
        };

        let (resolved, kind, path_opt) = resolve_import_path(
            &imp,
            Path::new("src/tools/deps_graph.rs"),
            &allowed,
            &restricted,
        );

        assert_eq!(kind, ImportKind::InternalLocal);
        assert_eq!(resolved, "src/state.rs");
        assert_eq!(path_opt, Some(PathBuf::from("src/state.rs")));
    }

    #[test]
    fn test_resolve_import_path_external() {
        let allowed = vec![];
        let restricted = vec![];

        let imp = ImportInfo {
            raw: "use serde_json::Value;".to_owned(),
            path: "serde_json::Value".to_owned(),
            kind: ImportKind::ExternalLibrary,
            resolved_path: None,
        };

        let (resolved, kind, path_opt) =
            resolve_import_path(&imp, Path::new("src/main.rs"), &allowed, &restricted);

        assert_eq!(kind, ImportKind::ExternalLibrary);
        assert_eq!(resolved, "serde_json::Value");
        assert!(path_opt.is_none());
    }

    // Phase 0: Tests for contention mitigation
    #[test]
    fn test_extract_params_defaults() {
        let args = serde_json::json!({});
        let (mode, max_nodes, max_edges) = extract_params(&args);

        assert_eq!(mode, "summary");
        assert_eq!(max_nodes, DEFAULT_MAX_NODES);
        assert_eq!(max_edges, MAX_EDGES_PER_NODE);
    }

    #[test]
    fn test_extract_params_custom_values() {
        let args = serde_json::json!({
            "mode": "full",
            "max_nodes": 50,
            "max_edges_per_node": 30
        });
        let (mode, max_nodes, max_edges) = extract_params(&args);

        assert_eq!(mode, "full");
        assert_eq!(max_nodes, 50);
        assert_eq!(max_edges, 30);
    }

    #[test]
    fn test_extract_params_clamps_max_values() {
        let args = serde_json::json!({
            "max_nodes": 1000,
            "max_edges_per_node": 500
        });
        let (_mode, max_nodes, max_edges) = extract_params(&args);

        assert!(max_nodes <= 200, "max_nodes should be clamped to 200");
        assert!(max_edges <= 100, "max_edges should be clamped to 100");
    }

    #[test]
    fn test_deduplicate_deps_removes_duplicates() {
        let input = vec![
            "tokio".to_string(),
            "serde".to_string(),
            "tokio".to_string(),
            "serde_json".to_string(),
            "serde".to_string(),
        ];
        let result = deduplicate_deps(input);

        assert_eq!(result.len(), 3);
        assert!(result.contains(&"tokio".to_string()));
        assert!(result.contains(&"serde".to_string()));
        assert!(result.contains(&"serde_json".to_string()));
    }

    #[test]
    fn test_deduplicate_deps_sorts_output() {
        let input = vec![
            "z_lib".to_string(),
            "a_lib".to_string(),
            "m_lib".to_string(),
        ];
        let result = deduplicate_deps(input);

        assert_eq!(result[0], "a_lib");
        assert_eq!(result[1], "m_lib");
        assert_eq!(result[2], "z_lib");
    }

    #[test]
    fn test_generate_summary_structure() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        file_deps.insert(
            "file1.rs".to_string(),
            json!({
                "internal": ["mod1", "mod2"],
                "restricted": ["priv1"],
                "external": ["tokio"],
                "unresolved": []
            }),
        );
        file_deps.insert(
            "file2.rs".to_string(),
            json!({
                "internal": ["mod1"],
                "restricted": [],
                "external": ["serde", "tokio"],
                "unresolved": ["unknown"]
            }),
        );

        let summary = generate_summary(&file_deps, 10);

        // Verify summary has required fields
        assert_eq!(
            summary.get("type").and_then(|v| v.as_str()),
            Some("summary")
        );
        assert!(summary.get("statistics").is_some());
        assert!(summary.get("top_hotspots").is_some());
        assert!(summary.get("applied_limits").is_some());
        assert!(summary.get("truncated").is_some());

        // Verify statistics
        let stats = summary
            .get("statistics")
            .and_then(|v| v.as_object())
            .unwrap();
        assert_eq!(
            stats.get("total_files_analyzed").and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(
            stats.get("total_internal_deps").and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(
            stats.get("total_external_libs").and_then(|v| v.as_u64()),
            Some(2)
        ); // tokio, serde
        assert_eq!(
            stats.get("total_unresolved").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[test]
    fn test_generate_summary_truncation_flag() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for i in 0..5 {
            file_deps.insert(
                format!("file{}.rs", i),
                json!({
                    "internal": [],
                    "restricted": [],
                    "external": [],
                    "unresolved": []
                }),
            );
        }

        let summary = generate_summary(&file_deps, 3);
        let truncated = summary.get("truncated").and_then(|v| v.as_bool());

        assert_eq!(
            truncated,
            Some(true),
            "Should mark as truncated when files > max_nodes"
        );
    }
}
