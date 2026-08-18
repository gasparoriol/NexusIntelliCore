use anyhow::Result;
use serde_json::{json, Value};
use std::time::Instant;

use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

mod builder;
mod cycles;
mod imports;
mod render;

/// Default and maximum limits for `get_dependencies_graph`
const DEFAULT_MAX_NODES: usize = 100;
const MAX_EDGES_PER_NODE: usize = 50;
const MAX_RESPONSE_BYTES: usize = 25 * 1024;
const MAX_GRAPH_RESPONSE_BYTES: usize = 50 * 1024;

/// Extract parameters from tool arguments with sensible defaults
#[derive(Debug, Clone)]
pub(crate) struct QueryParams {
    mode: String,
    scope_path: Option<String>,
    depth: Option<usize>,
    direction: String,
    include_external: bool,
    include_unresolved: bool,
    max_nodes: usize,
    max_edges_per_node: usize,
    sort_by: String,
    limit_adjustments: Vec<String>,
}

impl QueryParams {
    fn from_args(args: &Value) -> Self {
        let mut limit_adjustments = Vec::new();
        let max_nodes = bounded_limit(
            args,
            "max_nodes",
            DEFAULT_MAX_NODES,
            200,
            &mut limit_adjustments,
        );
        let max_edges_per_node = bounded_limit(
            args,
            "max_edges_per_node",
            MAX_EDGES_PER_NODE,
            100,
            &mut limit_adjustments,
        );

        Self {
            mode: args
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("summary")
                .to_string(),
            scope_path: args
                .get("scope_path")
                .and_then(Value::as_str)
                .map(String::from),
            depth: args
                .get("depth")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .map(|n| n.min(5)),
            direction: args
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("outbound")
                .to_string(),
            include_external: args
                .get("include_external")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            include_unresolved: args
                .get("include_unresolved")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            max_nodes,
            max_edges_per_node,
            sort_by: args
                .get("sort_by")
                .and_then(Value::as_str)
                .unwrap_or("fanout")
                .to_string(),
            limit_adjustments,
        }
    }
}

fn bounded_limit(
    args: &Value,
    field: &str,
    default: usize,
    maximum: usize,
    adjustments: &mut Vec<String>,
) -> usize {
    let Some(value) = args.get(field) else {
        return default;
    };
    let Some(raw) = value.as_u64() else {
        adjustments.push(format!("{field}: invalid value; using default {default}"));
        return default;
    };
    let Ok(requested) = usize::try_from(raw) else {
        adjustments.push(format!("{field}: overflow; using default {default}"));
        return default;
    };
    if requested > maximum {
        adjustments.push(format!("{field}: clamped from {requested} to {maximum}"));
        maximum
    } else {
        requested
    }
}

pub(super) async fn get_dependencies_graph(
    state: &crate::state::ServerState,
    args: &Value,
) -> Result<Value> {
    let start = Instant::now();
    let params = QueryParams::from_args(args);

    let index = state.index().await?;
    let allowed_files =
        builder::filter_by_scope(index.allowed_files.clone(), params.scope_path.as_deref());
    let restricted_files =
        builder::filter_by_scope(index.restricted_files.clone(), params.scope_path.as_deref());
    drop(index);

    let mut file_deps =
        builder::build_file_dependencies(state, &allowed_files, &restricted_files, &params).await?;
    builder::apply_dependency_type_filters(&mut file_deps, &params);

    let file_deps = match params.direction.as_str() {
        "inbound" => builder::reverse_dependencies(&file_deps),
        "both" => builder::merge_with_reverse_dependencies(file_deps),
        _ => file_deps,
    };

    let file_deps = builder::apply_depth_limit(&file_deps, &params);
    let dependency_cycles = cycles::detect_dependency_cycles(&file_deps);

    let summary = render::generate_summary(&file_deps, &params);
    let summary_mode = params.mode == "summary";
    let (nodes, edges) = render::graph_to_nodes_edges(&file_deps, summary_mode);
    let cycle_count = dependency_cycles.len();
    let cycle_sizes: Vec<usize> = dependency_cycles.iter().map(std::vec::Vec::len).collect();

    let output = json!({
        "nodes": nodes,
        "edges": edges,
        "dependency_cycles": dependency_cycles
            .iter()
            .map(|files| json!({ "files": files, "size": files.len() }))
            .collect::<Vec<_>>(),
        "meta": {
            "format": "nodes_edges_meta",
            "applied_filters": {
                "mode": &params.mode,
                "scope_path": &params.scope_path,
                "depth": params.depth,
                "direction": &params.direction,
                "include_external": params.include_external,
                "include_unresolved": params.include_unresolved,
                "sort_by": &params.sort_by,
            },
            "applied_limits": {
                "max_nodes": params.max_nodes,
                "max_edges_per_node": params.max_edges_per_node,
                "adjustments": &params.limit_adjustments,
                "response_budget_bytes": if summary_mode { MAX_RESPONSE_BYTES } else { MAX_GRAPH_RESPONSE_BYTES },
            },
            "summary": summary,
            "alerts": {
                "dependency_cycles_detected": cycle_count,
                "cycle_sizes": cycle_sizes,
            },
            "truncated": false,
            "truncation_reason": Value::Null,
        }
    });

    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_graph, _redactions) =
        privacy_gateway::sanitize_dependency_graph(&output, &policy);

    let budget = if summary_mode {
        MAX_RESPONSE_BYTES
    } else {
        MAX_GRAPH_RESPONSE_BYTES
    };
    let (mut budgeted_graph, response_bytes, was_truncated, truncation_reason) =
        render::ensure_budget(sanitized_graph, budget);

    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let nodes_returned = budgeted_graph
        .get("nodes")
        .and_then(Value::as_array)
        .map_or(0, std::vec::Vec::len);
    let edges_returned = budgeted_graph
        .get("edges")
        .and_then(Value::as_array)
        .map_or(0, std::vec::Vec::len);

    if let Some(meta) = budgeted_graph
        .get_mut("meta")
        .and_then(|v| v.as_object_mut())
    {
        meta.insert("truncated".to_string(), Value::Bool(was_truncated));
        meta.insert(
            "truncation_reason".to_string(),
            truncation_reason.map_or(Value::Null, Value::String),
        );
        meta.insert(
            "metrics".to_string(),
            json!({
                "graph_nodes_returned": nodes_returned,
                "graph_edges_returned": edges_returned,
                "response_bytes": response_bytes,
                "truncated": was_truncated,
                "duration_ms": duration_ms,
            }),
        );
    }

    let graph_json_compact =
        serde_json::to_string(&budgeted_graph).unwrap_or_else(|_| "{}".to_string());
    let response_text = if params.mode == "summary" {
        format!("[Dependency analysis in summary mode (focused on hotspots and metrics)]\n{graph_json_compact}")
    } else {
        format!("[Full dependency graph (use summary mode to reduce output)]\n{graph_json_compact}")
    };

    Ok(tool_response(vec![text_content(response_text)]))
}

#[cfg(test)]
mod tests {
    use super::{
        builder, cycles, imports, render, QueryParams, DEFAULT_MAX_NODES, MAX_EDGES_PER_NODE,
    };
    use crate::analyzer::{ImportInfo, ImportKind};
    use serde_json::{json, Value};
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

        let (resolved, kind, path_opt) = imports::resolve_import_path(
            &imp,
            Path::new("src/main.rs"),
            "rust",
            None,
            &allowed,
            &restricted,
        );

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

        let (resolved, kind, path_opt) = imports::resolve_import_path(
            &imp,
            Path::new("src/tools/deps_graph.rs"),
            "rust",
            None,
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

        let (resolved, kind, path_opt) = imports::resolve_import_path(
            &imp,
            Path::new("src/main.rs"),
            "rust",
            None,
            &allowed,
            &restricted,
        );

        assert_eq!(kind, ImportKind::ExternalLibrary);
        assert_eq!(resolved, "serde_json::Value");
        assert!(path_opt.is_none());
    }

    #[test]
    fn test_unresolved_reason_is_stable() {
        assert_eq!(
            imports::unresolved_reason("crate::missing"),
            "destination_not_found"
        );
        assert_eq!(imports::unresolved_reason(""), "unsupported_syntax");
    }

    #[test]
    fn test_find_matching_file_strictness() {
        let files = vec![
            PathBuf::from("src/state.rs"),
            PathBuf::from("src/state_helper.rs"),
            PathBuf::from("src/statement.rs"),
        ];

        let matched = imports::find_matching_file("state", &files);
        assert_eq!(matched, Some(PathBuf::from("src/state.rs")));

        let matched_none = imports::find_matching_file("stat", &files);
        assert_eq!(matched_none, None);
    }

    #[test]
    fn test_extract_params_defaults() {
        let args = serde_json::json!({});
        let params = QueryParams::from_args(&args);

        assert_eq!(params.mode, "summary");
        assert_eq!(params.max_nodes, DEFAULT_MAX_NODES);
        assert_eq!(params.max_edges_per_node, MAX_EDGES_PER_NODE);
    }

    #[test]
    fn test_extract_params_custom_values() {
        let args = serde_json::json!({
            "mode": "full",
            "max_nodes": 50,
            "max_edges_per_node": 30
        });
        let params = QueryParams::from_args(&args);

        assert_eq!(params.mode, "full");
        assert_eq!(params.max_nodes, 50);
        assert_eq!(params.max_edges_per_node, 30);
    }

    #[test]
    fn test_extract_params_clamps_max_values() {
        let args = serde_json::json!({
            "max_nodes": 1000,
            "max_edges_per_node": 500
        });
        let params = QueryParams::from_args(&args);

        assert!(
            params.max_nodes <= 200,
            "max_nodes should be clamped to 200"
        );
        assert!(
            params.max_edges_per_node <= 100,
            "max_edges should be clamped to 100"
        );
        assert_eq!(params.limit_adjustments.len(), 2);
        assert!(params.limit_adjustments[0].contains("max_nodes: clamped"));
        assert!(params.limit_adjustments[1].contains("max_edges_per_node: clamped"));
    }

    #[test]
    fn test_extract_params_reports_invalid_limits() {
        let params = QueryParams::from_args(&json!({
            "max_nodes": -1,
            "max_edges_per_node": "many"
        }));

        assert_eq!(params.max_nodes, DEFAULT_MAX_NODES);
        assert_eq!(params.max_edges_per_node, MAX_EDGES_PER_NODE);
        assert_eq!(params.limit_adjustments.len(), 2);
        assert!(params.limit_adjustments[0].contains("max_nodes: invalid value"));
        assert!(params.limit_adjustments[1].contains("max_edges_per_node: invalid value"));
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
        let result = render::deduplicate_deps(input);

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
        let result = render::deduplicate_deps(input);

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
                "imports_total": 4,
                "resolved_internal": 2,
                "unresolved_actionable": 0,
                "internal": ["mod1", "mod2"],
                "restricted": ["priv1"],
                "external": ["tokio"],
                "unresolved": [],
                "unresolved_details": []
            }),
        );
        file_deps.insert(
            "file2.rs".to_string(),
            json!({
                "imports_total": 4,
                "resolved_internal": 1,
                "unresolved_actionable": 1,
                "internal": ["mod1"],
                "restricted": [],
                "external": ["serde", "tokio"],
                "unresolved": ["unknown"],
                "unresolved_details": [{
                    "import": "unknown",
                    "reason": "destination_not_found"
                }]
            }),
        );

        let summary = render::generate_summary(
            &file_deps,
            &QueryParams {
                mode: "summary".to_string(),
                scope_path: None,
                depth: None,
                direction: "outbound".to_string(),
                include_external: true,
                include_unresolved: true,
                max_nodes: 10,
                max_edges_per_node: 5,
                sort_by: "fanout".to_string(),
                limit_adjustments: vec![],
            },
        );

        assert_eq!(
            summary.get("type").and_then(|v| v.as_str()),
            Some("summary")
        );
        assert!(summary.get("statistics").is_some());
        assert!(summary.get("top_hotspots").is_some());
        assert!(summary.get("applied_limits").is_some());
        assert!(summary.get("truncated").is_some());

        let stats = summary
            .get("statistics")
            .and_then(|v| v.as_object())
            .unwrap();
        assert_eq!(
            stats.get("total_files_analyzed").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            stats.get("total_internal_deps").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            stats.get("total_external_libs").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            stats.get("total_unresolved").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(stats.get("imports_total").and_then(Value::as_u64), Some(8));
        assert_eq!(
            stats.get("resolved_internal").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            stats.get("unresolved_actionable").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            stats.get("resolution_coverage").and_then(Value::as_f64),
            Some(0.75)
        );
    }

    #[test]
    fn test_generate_summary_truncation_flag() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for i in 0..5 {
            file_deps.insert(
                format!("file{i}.rs"),
                json!({
                    "internal": [],
                    "restricted": [],
                    "external": [],
                    "unresolved": []
                }),
            );
        }

        let summary = render::generate_summary(
            &file_deps,
            &QueryParams {
                mode: "summary".to_string(),
                scope_path: None,
                depth: None,
                direction: "outbound".to_string(),
                include_external: true,
                include_unresolved: true,
                max_nodes: 3,
                max_edges_per_node: 5,
                sort_by: "fanout".to_string(),
                limit_adjustments: vec![],
            },
        );
        let truncated = summary.get("truncated").and_then(Value::as_bool);

        assert_eq!(
            truncated,
            Some(true),
            "Should mark as truncated when files > max_nodes"
        );
    }

    #[test]
    fn test_reverse_dependencies_is_used_for_inbound_shape() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        file_deps.insert(
            "a.rs".to_string(),
            json!({
                "internal": ["b.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );

        let reversed = builder::reverse_dependencies(&file_deps);
        let dependents = reversed
            .get("b.rs")
            .and_then(|v| v.get("dependents"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        assert_eq!(dependents, vec![Value::String("a.rs".to_string())]);
    }

    #[test]
    fn test_merge_with_reverse_dependencies_adds_dependents_field() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        file_deps.insert(
            "a.rs".to_string(),
            json!({
                "internal": ["b.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );

        let merged = builder::merge_with_reverse_dependencies(file_deps);
        let dependents = merged
            .get("b.rs")
            .and_then(|v| v.get("dependents"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        assert_eq!(dependents, vec![Value::String("a.rs".to_string())]);
    }

    #[test]
    fn test_apply_depth_limit_reduces_transitive_scope() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        file_deps.insert(
            "a.rs".to_string(),
            json!({
                "internal": ["b.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );
        file_deps.insert(
            "b.rs".to_string(),
            json!({
                "internal": ["c.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );
        file_deps.insert(
            "c.rs".to_string(),
            json!({
                "internal": [],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );

        let params = QueryParams {
            mode: "graph".to_string(),
            scope_path: Some("a.rs".to_string()),
            depth: Some(1),
            direction: "outbound".to_string(),
            include_external: false,
            include_unresolved: false,
            max_nodes: 100,
            max_edges_per_node: 50,
            sort_by: "fanout".to_string(),
            limit_adjustments: vec![],
        };

        let limited = builder::apply_depth_limit(&file_deps, &params);
        assert!(limited.contains_key("a.rs"));
        assert!(limited.contains_key("b.rs"));
        assert!(!limited.contains_key("c.rs"));
    }

    #[test]
    fn test_ensure_budget_truncates_when_too_large() {
        let graph = json!({
            "nodes": [
                {"id": "a", "label": "a", "kind": "file"},
                {"id": "b", "label": "b", "kind": "file"}
            ],
            "edges": [
                {"source": "a", "target": "b", "label": "internal"},
                {"source": "b", "target": "a", "label": "internal"}
            ],
            "meta": {}
        });

        let (_trimmed, bytes, truncated, reason) = render::ensure_budget(graph, 120);
        assert!(truncated);
        assert!(bytes <= 120);
        assert!(reason.is_some());
    }

    #[test]
    fn test_detect_dependency_cycles_finds_two_node_cycle() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        file_deps.insert(
            "a.rs".to_string(),
            json!({
                "internal": ["b.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );
        file_deps.insert(
            "b.rs".to_string(),
            json!({
                "internal": ["a.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );

        let cycles = cycles::detect_dependency_cycles(&file_deps);
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0], vec!["a.rs".to_string(), "b.rs".to_string()]);
    }

    #[test]
    fn test_detect_dependency_cycles_ignores_acyclic_graph() {
        let mut file_deps: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        file_deps.insert(
            "a.rs".to_string(),
            json!({
                "internal": ["b.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );
        file_deps.insert(
            "b.rs".to_string(),
            json!({
                "internal": ["c.rs"],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );
        file_deps.insert(
            "c.rs".to_string(),
            json!({
                "internal": [],
                "restricted": [],
                "external": [],
                "unresolved": []
            }),
        );

        let cycles = cycles::detect_dependency_cycles(&file_deps);
        assert!(cycles.is_empty());
    }
}
