use serde_json::{json, Value};
use std::collections::HashSet;

use super::QueryParams;

pub(crate) fn deduplicate_deps(deps: Vec<String>) -> Vec<String> {
    let mut set: HashSet<String> = deps.into_iter().collect();
    let mut result: Vec<String> = set.drain().collect();
    result.sort();
    result
}

pub(crate) fn generate_summary(
    file_deps: &serde_json::Map<String, Value>,
    params: &QueryParams,
) -> Value {
    let mut total_internal = 0;
    let mut total_restricted = 0;
    let mut total_external: HashSet<String> = HashSet::new();
    let mut total_unresolved = 0;
    let mut imports_total = 0;
    let mut resolved_internal = 0;
    let mut unresolved_actionable = 0;
    let mut hotspot_counts: Vec<(String, usize, usize)> = Vec::new();

    for (file, deps_obj) in file_deps.iter().take(params.max_nodes) {
        if let Some(obj) = deps_obj.as_object() {
            imports_total += obj
                .get("imports_total")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            resolved_internal += obj
                .get("resolved_internal")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
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
            unresolved_actionable += obj
                .get("unresolved_actionable")
                .and_then(Value::as_u64)
                .map_or_else(
                    || {
                        obj.get("unresolved_details")
                            .and_then(Value::as_array)
                            .map_or(0, std::vec::Vec::len) as u64
                    },
                    |count| count,
                ) as usize;

            let fanout = internal_count + restricted_count + external_count + unresolved_count;
            if fanout > 0 || dependents_count > 0 {
                hotspot_counts.push((file.clone(), fanout, dependents_count));
            }

            if let Some(external_arr) = obj.get("external").and_then(|v| v.as_array()) {
                for ext_dep in external_arr {
                    if let Some(s) = ext_dep.as_str() {
                        total_external.insert(s.to_string());
                    }
                }
            }
        }
    }

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
            "imports_total": imports_total,
            "resolved_internal": resolved_internal,
            "unresolved_actionable": unresolved_actionable,
            "resolution_coverage": if resolved_internal + unresolved_actionable == 0 {
                1.0
            } else {
                resolved_internal as f64 / (resolved_internal + unresolved_actionable) as f64
            },
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

pub(crate) fn compact_external_namespace(dep: &str) -> String {
    let mut split = dep
        .split([':', '/', '.'])
        .filter(|s| !s.is_empty() && *s != "crate" && *s != "self" && *s != "super");
    split.next().unwrap_or(dep).to_string()
}

pub(crate) fn graph_to_nodes_edges(
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

pub(crate) fn ensure_budget(
    mut graph: Value,
    max_bytes: usize,
) -> (Value, usize, bool, Option<String>) {
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
