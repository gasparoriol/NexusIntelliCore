use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

/// Default and maximum limits for `get_dependencies_graph`
const DEFAULT_MAX_NODES: usize = 100;
const MAX_EDGES_PER_NODE: usize = 50;
const MAX_RESPONSE_BYTES: usize = 25 * 1024; // 25 KB for summary mode
const MAX_GRAPH_RESPONSE_BYTES: usize = 50 * 1024; // 50 KB for graph mode

/// Extract parameters from tool arguments with sensible defaults
#[derive(Debug, Clone)]
struct QueryParams {
    mode: String,
    scope_path: Option<String>,
    depth: Option<usize>,
    direction: String,
    include_external: bool,
    include_unresolved: bool,
    max_nodes: usize,
    max_edges_per_node: usize,
    sort_by: String,
}

impl QueryParams {
    fn from_args(args: &Value) -> Self {
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
            max_nodes: args
                .get("max_nodes")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .map_or(DEFAULT_MAX_NODES, |n| n.min(200)),
            max_edges_per_node: args
                .get("max_edges_per_node")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .map_or(MAX_EDGES_PER_NODE, |n| n.min(100)),
            sort_by: args
                .get("sort_by")
                .and_then(Value::as_str)
                .unwrap_or("fanout")
                .to_string(),
        }
    }
}

/// Deduplicate dependency vectors, converting to sets and back
fn deduplicate_deps(deps: Vec<String>) -> Vec<String> {
    let mut set: HashSet<String> = deps.into_iter().collect();
    let mut result: Vec<String> = set.drain().collect();
    result.sort();
    result
}

/// Generate a summary of the full dependency graph
fn generate_summary(file_deps: &serde_json::Map<String, Value>, params: &QueryParams) -> Value {
    let mut total_internal = 0;
    let mut total_restricted = 0;
    let mut total_external: HashSet<String> = HashSet::new();
    let mut total_unresolved = 0;
    let mut hotspot_counts: Vec<(String, usize, usize)> = Vec::new();

    for (file, deps_obj) in file_deps.iter().take(params.max_nodes) {
        if let Some(obj) = deps_obj.as_object() {
            let internal_count = obj
                .get("internal")
                .and_then(Value::as_array)
                .map_or(0, std::vec::Vec::len);
            let restricted_count = obj
                .get("restricted")
                .and_then(Value::as_array)
                .map_or(0, std::vec::Vec::len);
            let external_count = obj
                .get("external")
                .and_then(Value::as_array)
                .map_or(0, std::vec::Vec::len);
            let unresolved_count = obj
                .get("unresolved")
                .and_then(Value::as_array)
                .map_or(0, std::vec::Vec::len);
            let dependents_count = obj
                .get("dependents")
                .and_then(Value::as_array)
                .map_or(0, std::vec::Vec::len);

            total_internal += internal_count;
            total_restricted += restricted_count;
            total_unresolved += unresolved_count;

            let fanout = internal_count + restricted_count + external_count + unresolved_count;
            if fanout > 0 || dependents_count > 0 {
                hotspot_counts.push((file.clone(), fanout, dependents_count));
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

    // Sort hotspots using selected strategy. For inbound mode, `fanout`
    // effectively maps to `fanin` to keep useful defaults.
    let effective_sort = if params.direction == "inbound" && params.sort_by == "fanout" {
        "fanin"
    } else {
        params.sort_by.as_str()
    };

    match effective_sort {
        "name" => hotspot_counts.sort_by(|a, b| a.0.cmp(&b.0)),
        "fanin" => hotspot_counts.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0))),
        _ => hotspot_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))),
    }
    let top_hotspots: Vec<_> = hotspot_counts.iter().take(params.max_nodes).collect();

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
            .map(|(f, fanout, fanin)| json!({ "file": f, "fanout": fanout, "fanin": fanin }))
            .collect::<Vec<_>>(),
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
            "mode": "summary",
            "max_nodes": params.max_nodes,
            "files_shown": file_deps.len().min(params.max_nodes),
        },
        "truncated": file_deps.len() > params.max_nodes,
    })
}

fn compact_external_namespace(dep: &str) -> String {
    let mut split = dep
        .split([':', '/', '.'])
        .filter(|s| !s.is_empty() && *s != "crate" && *s != "self" && *s != "super");
    split.next().unwrap_or(dep).to_string()
}

fn collect_neighbors(
    node: &str,
    file_deps: &serde_json::Map<String, Value>,
    params: &QueryParams,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(obj) = file_deps.get(node).and_then(|v| v.as_object()) {
        let mut push_from = |key: &str| {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        };

        match params.direction.as_str() {
            "inbound" => {
                push_from("dependents");
            }
            "both" => {
                push_from("internal");
                push_from("restricted");
                if params.include_external {
                    push_from("external");
                }
                if params.include_unresolved {
                    push_from("unresolved");
                }
                push_from("dependents");
            }
            _ => {
                push_from("internal");
                push_from("restricted");
                if params.include_external {
                    push_from("external");
                }
                if params.include_unresolved {
                    push_from("unresolved");
                }
            }
        }
    }
    out
}

fn apply_depth_limit(
    file_deps: &serde_json::Map<String, Value>,
    params: &QueryParams,
) -> serde_json::Map<String, Value> {
    let Some(max_depth) = params.depth else {
        return file_deps.clone();
    };

    let mut roots: Vec<String> = if let Some(scope) = params.scope_path.as_deref() {
        file_deps
            .keys()
            .filter(|k| k.contains(scope))
            .cloned()
            .collect()
    } else {
        file_deps.keys().cloned().collect()
    };

    if roots.is_empty() {
        roots = file_deps.keys().cloned().collect();
    }

    let mut visited: HashSet<String> = HashSet::new();
    let mut q: VecDeque<(String, usize)> = VecDeque::new();
    for root in roots {
        if visited.insert(root.clone()) {
            q.push_back((root, 0));
        }
    }

    while let Some((node, d)) = q.pop_front() {
        if d >= max_depth {
            continue;
        }
        for neigh in collect_neighbors(&node, file_deps, params) {
            if file_deps.contains_key(&neigh) && visited.insert(neigh.clone()) {
                q.push_back((neigh, d + 1));
            }
        }
    }

    file_deps
        .iter()
        .filter_map(|(k, v)| {
            if visited.contains(k) {
                Some((k.clone(), v.clone()))
            } else {
                None
            }
        })
        .collect()
}

fn graph_to_nodes_edges(
    file_deps: &serde_json::Map<String, Value>,
    summary_mode: bool,
) -> (Vec<Value>, Vec<Value>) {
    let mut node_kinds: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut edge_seen: HashSet<(String, String, String)> = HashSet::new();
    let mut edges: Vec<Value> = Vec::new();

    for (source, deps_obj) in file_deps {
        node_kinds.insert(source.clone(), Value::String("file".to_string()));

        if let Some(obj) = deps_obj.as_object() {
            let mut push_edges = |key: &str, kind: &str| {
                if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                    for dep in arr {
                        if let Some(dep_str) = dep.as_str() {
                            let target = if kind == "external" && summary_mode {
                                compact_external_namespace(dep_str)
                            } else {
                                dep_str.to_string()
                            };
                            if edge_seen.insert((source.clone(), target.clone(), kind.to_string()))
                            {
                                edges.push(json!({
                                    "source": source,
                                    "target": target,
                                    "label": kind,
                                }));
                            }
                            let node_kind = if file_deps.contains_key(dep_str) {
                                "file"
                            } else {
                                kind
                            };
                            node_kinds
                                .entry(if kind == "external" && summary_mode {
                                    compact_external_namespace(dep_str)
                                } else {
                                    dep_str.to_string()
                                })
                                .or_insert_with(|| Value::String(node_kind.to_string()));
                        }
                    }
                }
            };

            push_edges("internal", "internal");
            push_edges("restricted", "restricted");
            push_edges("external", "external");
            push_edges("unresolved", "unresolved");

            if let Some(arr) = obj.get("dependents").and_then(|v| v.as_array()) {
                for dep in arr {
                    if let Some(dep_str) = dep.as_str() {
                        if edge_seen.insert((
                            dep_str.to_string(),
                            source.clone(),
                            "inbound".to_string(),
                        )) {
                            edges.push(json!({
                                "source": dep_str,
                                "target": source,
                                "label": "inbound",
                            }));
                        }
                        node_kinds
                            .entry(dep_str.to_string())
                            .or_insert_with(|| Value::String("file".to_string()));
                    }
                }
            }
        }
    }

    let mut nodes: Vec<Value> = node_kinds
        .into_iter()
        .map(|(id, kind)| {
            json!({
                "id": id,
                "label": id,
                "kind": kind,
            })
        })
        .collect();

    nodes.sort_by(|a, b| {
        a.get("id")
            .and_then(|v| v.as_str())
            .cmp(&b.get("id").and_then(|v| v.as_str()))
    });
    edges.sort_by(|a, b| {
        let a_key = (
            a.get("source").and_then(|v| v.as_str()).unwrap_or(""),
            a.get("target").and_then(|v| v.as_str()).unwrap_or(""),
            a.get("label").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let b_key = (
            b.get("source").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("target").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("label").and_then(|v| v.as_str()).unwrap_or(""),
        );
        a_key.cmp(&b_key)
    });

    (nodes, edges)
}

fn ensure_budget(mut graph: Value, max_bytes: usize) -> (Value, usize, bool, Option<String>) {
    let mut bytes = serde_json::to_string(&graph)
        .ok()
        .as_deref()
        .map_or(0, str::len);
    if bytes <= max_bytes {
        return (graph, bytes, false, None);
    }

    let mut reason = "response_bytes_limit".to_string();

    loop {
        bytes = serde_json::to_string(&graph)
            .ok()
            .as_deref()
            .map_or(0, str::len);
        if bytes <= max_bytes {
            return (graph, bytes, true, Some(reason));
        }

        let removed_edge = graph
            .get_mut("edges")
            .and_then(|v| v.as_array_mut())
            .and_then(std::vec::Vec::pop)
            .is_some();
        if removed_edge {
            continue;
        }

        reason = "response_nodes_trimmed".to_string();
        let removed_node = graph
            .get_mut("nodes")
            .and_then(|v| v.as_array_mut())
            .and_then(std::vec::Vec::pop)
            .is_some();
        if removed_node {
            continue;
        }

        bytes = serde_json::to_string(&graph)
            .ok()
            .as_deref()
            .map_or(0, str::len);
        return (graph, bytes, true, Some(reason));
    }
}

async fn build_file_dependencies(
    state: &crate::state::ServerState,
    allowed_files: &[PathBuf],
    restricted_files: &[PathBuf],
    params: &QueryParams,
) -> Result<serde_json::Map<String, Value>> {
    let mut file_deps: serde_json::Map<String, Value> = serde_json::Map::new();

    for file in allowed_files.iter().take(params.max_nodes * 2) {
        let Ok(path) = state.validate_path(file) else {
            continue;
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        let Ok(analysis) = state.get_analysis(&path).await else {
            continue;
        };

        let mut internal: Vec<String> = Vec::new();
        let mut restricted: Vec<String> = Vec::new();
        let mut external: Vec<String> = Vec::new();
        let mut unresolved_list: Vec<String> = Vec::new();

        for imp in &analysis.imports {
            let (resolved_str, kind, _) = resolve_import_path(
                imp,
                &path,
                &analysis.language,
                Some(state),
                allowed_files,
                restricted_files,
            );
            match kind {
                analyzer::ImportKind::InternalLocal => internal.push(resolved_str),
                analyzer::ImportKind::InternalRestricted => restricted.push(resolved_str),
                analyzer::ImportKind::ExternalLibrary => external.push(imp.path.clone()),
                analyzer::ImportKind::Unresolved => unresolved_list.push(imp.path.clone()),
            }
        }

        internal = deduplicate_deps(internal);
        restricted = deduplicate_deps(restricted);
        external = deduplicate_deps(external);
        unresolved_list = deduplicate_deps(unresolved_list);

        internal.truncate(params.max_edges_per_node);
        restricted.truncate(params.max_edges_per_node);
        external.truncate(params.max_edges_per_node);
        unresolved_list.truncate(params.max_edges_per_node);

        file_deps.insert(
            rel,
            json!({
                "internal":   internal,
                "restricted": restricted,
                "external":   external,
                "unresolved": unresolved_list,
            }),
        );

        if file_deps.len() >= params.max_nodes {
            break;
        }
    }

    Ok(file_deps)
}

pub(super) async fn get_dependencies_graph(state: &crate::state::ServerState, args: &Value) -> Result<Value> {
    let start = Instant::now();
    let params = QueryParams::from_args(args);

    let index = state.index().await?;
    let allowed_files = filter_by_scope(index.allowed_files.clone(), params.scope_path.as_deref());
    let restricted_files =
        filter_by_scope(index.restricted_files.clone(), params.scope_path.as_deref());
    drop(index);

    // Build a per-file classified dependency map:
    // relative_path -> { internal, restricted, external, unresolved }
    let mut file_deps =
        build_file_dependencies(state, &allowed_files, &restricted_files, &params).await?;

    apply_dependency_type_filters(&mut file_deps, &params);

    // Apply direction to the graph (outbound, inbound, both).
    let file_deps = match params.direction.as_str() {
        "inbound" => reverse_dependencies(&file_deps),
        "both" => merge_with_reverse_dependencies(file_deps),
        _ => file_deps,
    };

    let file_deps = apply_depth_limit(&file_deps, &params);

    let summary = generate_summary(&file_deps, &params);
    let summary_mode = params.mode == "summary";
    let (nodes, edges) = graph_to_nodes_edges(&file_deps, summary_mode);

    let output = json!({
        "nodes": nodes,
        "edges": edges,
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
                "response_budget_bytes": if summary_mode { MAX_RESPONSE_BYTES } else { MAX_GRAPH_RESPONSE_BYTES },
            },
            "summary": summary,
            "truncated": false,
            "truncation_reason": Value::Null,
        }
    });

    // Sanitize through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_graph, _redactions) =
        privacy_gateway::sanitize_dependency_graph(&output, &policy);

    let budget = if summary_mode {
        MAX_RESPONSE_BYTES
    } else {
        MAX_GRAPH_RESPONSE_BYTES
    };
    let (mut budgeted_graph, response_bytes, was_truncated, truncation_reason) =
        ensure_budget(sanitized_graph, budget);

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

    // Serialize in compact form (not pretty-print) to reduce output size
    let graph_json_compact =
        serde_json::to_string(&budgeted_graph).unwrap_or_else(|_| "{}".to_string());

    let response_text = if params.mode == "summary" {
        format!(
            "[Dependency analysis in summary mode (focused on hotspots and metrics)]\n{graph_json_compact}"
        )
    } else {
        format!("[Full dependency graph (use summary mode to reduce output)]\n{graph_json_compact}")
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
    source_language: &str,
    state: Option<&crate::state::ServerState>,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    let path = &imp.path;

    // JS/TS aliases from nearest tsconfig/jsconfig: e.g. '@/x' -> 'src/x'.
    if let Some(resolved) = resolve_ts_alias_import(
        source_language,
        path,
        from_file,
        state,
        allowed_files,
        restricted_files,
    ) {
        return resolved;
    }

    // External libraries never resolve to a project file.
    if imp.kind == ImportKind::ExternalLibrary {
        return (imp.path.clone(), ImportKind::ExternalLibrary, None);
    }

    // Relative paths — resolve against the importing file's parent directory.
    if path.starts_with("./") || path.starts_with("../") {
        return resolve_relative_import_path(path, from_file, allowed_files, restricted_files);
    }

    resolve_non_relative_import_path(path, allowed_files, restricted_files)
}

fn resolve_ts_alias_import(
    source_language: &str,
    path: &str,
    from_file: &std::path::Path,
    state: Option<&crate::state::ServerState>,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> Option<(String, analyzer::ImportKind, Option<std::path::PathBuf>)> {
    use analyzer::ImportKind;

    if !matches!(source_language, "javascript" | "typescript" | "tsx")
        || path.starts_with("./")
        || path.starts_with("../")
    {
        return None;
    }

    let alias_target = state.and_then(|s| s.resolve_ts_path_alias(from_file, path))?;
    if let Some((rel, kind, resolved)) =
        classify_project_path(&alias_target, allowed_files, restricted_files)
    {
        return Some((rel, kind, Some(resolved)));
    }

    if let Ok(canon) = std::fs::canonicalize(&alias_target) {
        if let Some((rel, kind, resolved)) =
            classify_project_path(&canon, allowed_files, restricted_files)
        {
            return Some((rel, kind, Some(resolved)));
        }
    }

    Some((path.to_owned(), ImportKind::Unresolved, None))
}

fn classify_project_path(
    candidate: &std::path::Path,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> Option<(String, analyzer::ImportKind, std::path::PathBuf)> {
    use analyzer::ImportKind;

    if allowed_files.contains(&candidate.to_path_buf()) {
        let rel = candidate.to_string_lossy().into_owned();
        return Some((rel, ImportKind::InternalLocal, candidate.to_path_buf()));
    }
    if restricted_files.contains(&candidate.to_path_buf()) {
        let rel = candidate.to_string_lossy().into_owned();
        return Some((rel, ImportKind::InternalRestricted, candidate.to_path_buf()));
    }

    None
}

fn resolve_relative_import_path(
    path: &str,
    from_file: &std::path::Path,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    let base = from_file.parent().unwrap_or(std::path::Path::new("/"));
    let candidate = base.join(path);
    for ext in &["", "rs", "ts", "tsx", "js", "py", "java"] {
        let with_ext = if ext.is_empty() {
            candidate.clone()
        } else {
            candidate.with_extension(ext)
        };
        let normalised = normalise_path(&with_ext);
        if let Some((rel, kind, resolved)) =
            classify_project_path(&normalised, allowed_files, restricted_files)
        {
            return (rel, kind, Some(resolved));
        }
    }

    (path.to_owned(), ImportKind::Unresolved, None)
}

fn normalise_path(path: &std::path::Path) -> std::path::PathBuf {
    path.components()
        .fold(std::path::PathBuf::new(), |mut acc, component| {
            match component {
                std::path::Component::ParentDir => {
                    acc.pop();
                }
                std::path::Component::CurDir => {}
                other => acc.push(other),
            }
            acc
        })
}

fn resolve_non_relative_import_path(
    path: &str,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    let normalised = normalise_internal_reference(path);

    if let Some(matched) = find_matching_file(&normalised, allowed_files) {
        let rel = matched.to_string_lossy().into_owned();
        return (rel, ImportKind::InternalLocal, Some(matched));
    }
    if let Some(matched) = find_matching_file(&normalised, restricted_files) {
        let rel = matched.to_string_lossy().into_owned();
        return (rel, ImportKind::InternalRestricted, Some(matched));
    }

    (normalised, ImportKind::Unresolved, None)
}

fn normalise_internal_reference(path: &str) -> String {
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

    normalised
}

fn find_matching_file(
    normalised: &str,
    files: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    for file in files {
        let file_str = file.to_string_lossy();
        let stem = file_str
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");
        if stem.ends_with(normalised) || file_str.contains(normalised) {
            return Some(file.clone());
        }
    }

    None
}

/// Filter files based on `scope_path`.
fn filter_by_scope(files: Vec<PathBuf>, scope: Option<&str>) -> Vec<PathBuf> {
    if let Some(scope_path) = scope {
        files
            .into_iter()
            .filter(|f| f.to_string_lossy().contains(scope_path))
            .collect()
    } else {
        files
    }
}

/// Apply dependency-type flags to graph entries.
fn apply_dependency_type_filters(
    file_deps: &mut serde_json::Map<String, Value>,
    params: &QueryParams,
) {
    for deps_obj in file_deps.values_mut() {
        if let Some(obj) = deps_obj.as_object_mut() {
            if !params.include_external {
                obj.insert("external".to_string(), Value::Array(Vec::new()));
            }
            if !params.include_unresolved {
                obj.insert("unresolved".to_string(), Value::Array(Vec::new()));
            }
        }
    }
}

/// Merge outbound dependencies with computed inbound dependents.
fn merge_with_reverse_dependencies(
    mut graph: serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    let reversed = reverse_dependencies(&graph);
    for (dep, dependents_obj) in reversed {
        let dependents = dependents_obj
            .get("dependents")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if let Some(m) = graph
            .entry(dep)
            .or_insert_with(|| {
                json!({
                    "internal": [],
                    "restricted": [],
                    "external": [],
                    "unresolved": []
                })
            })
            .as_object_mut()
        {
            m.insert("dependents".to_string(), Value::Array(dependents));
        }
    }
    graph
}

/// Reverse a dependency graph (for inbound queries)
fn reverse_dependencies(graph: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    let mut reversed = serde_json::Map::new();

    for (file, deps_obj) in graph {
        if let Some(obj) = deps_obj.as_object() {
            // For each dependency of this file, add this file as dependent
            for key in &["internal", "restricted"] {
                if let Some(arr) = obj.get(*key).and_then(|v| v.as_array()) {
                    for dep in arr {
                        if let Some(dep_str) = dep.as_str() {
                            if let Some(arr) = reversed
                                .entry(dep_str.to_string())
                                .or_insert_with(|| json!({"dependents": []}))
                                .as_object_mut()
                                .and_then(|m| m.get_mut("dependents"))
                                .and_then(|v| v.as_array_mut())
                            {
                                arr.push(Value::String(file.clone()));
                            }
                        }
                    }
                }
            }
        }
    }
    reversed
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

        let (resolved, kind, path_opt) = resolve_import_path(
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

        let (resolved, kind, path_opt) = resolve_import_path(
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

        let (resolved, kind, path_opt) = resolve_import_path(
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

    // Phase 0: Tests for contention mitigation
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

        let summary = generate_summary(
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
            },
        );

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
        ); // tokio, serde
        assert_eq!(
            stats.get("total_unresolved").and_then(Value::as_u64),
            Some(1)
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

        let summary = generate_summary(
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

        let reversed = reverse_dependencies(&file_deps);
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

        let merged = merge_with_reverse_dependencies(file_deps);
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
        };

        let limited = apply_depth_limit(&file_deps, &params);
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

        let (_trimmed, bytes, truncated, reason) = ensure_budget(graph, 120);
        assert!(truncated);
        assert!(bytes <= 120);
        assert!(reason.is_some());
    }
}
