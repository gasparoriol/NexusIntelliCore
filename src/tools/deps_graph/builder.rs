use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

use crate::analyzer;

use super::imports::resolve_import_path;
use super::render::deduplicate_deps;
use super::QueryParams;

pub(crate) fn filter_by_scope(files: Vec<PathBuf>, scope: Option<&str>) -> Vec<PathBuf> {
    if let Some(scope_path) = scope {
        files
            .into_iter()
            .filter(|f| f.to_string_lossy().contains(scope_path))
            .collect()
    } else {
        files
    }
}

pub(crate) fn apply_dependency_type_filters(
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
                obj.insert("unresolved_details".to_string(), Value::Array(Vec::new()));
            }
        }
    }
}

pub(crate) async fn build_file_dependencies(
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
        let language = analysis.language.clone();

        let mut internal: Vec<String> = Vec::new();
        let mut restricted: Vec<String> = Vec::new();
        let mut external: Vec<String> = Vec::new();
        let mut unresolved_list: Vec<String> = Vec::new();
        let mut unresolved_details: Vec<Value> = Vec::new();

        for imp in &analysis.imports {
            let (resolved_str, kind, _) = resolve_import_path(
                imp,
                &path,
                &language,
                Some(state),
                allowed_files,
                restricted_files,
            );
            match kind {
                analyzer::ImportKind::InternalLocal => internal.push(resolved_str),
                analyzer::ImportKind::InternalRestricted => restricted.push(resolved_str),
                analyzer::ImportKind::ExternalLibrary => external.push(imp.path.clone()),
                analyzer::ImportKind::Unresolved => {
                    unresolved_list.push(imp.path.clone());
                    unresolved_details.push(json!({
                        "import": imp.path,
                        "reason": super::imports::unresolved_reason(&imp.path),
                    }));
                }
            }
        }

        internal = deduplicate_deps(internal);
        restricted = deduplicate_deps(restricted);
        external = deduplicate_deps(external);
        unresolved_list = deduplicate_deps(unresolved_list);
        let resolved_internal = internal.len();
        let unresolved_actionable = unresolved_details.len();

        internal.truncate(params.max_edges_per_node);
        restricted.truncate(params.max_edges_per_node);
        external.truncate(params.max_edges_per_node);
        unresolved_list.truncate(params.max_edges_per_node);
        unresolved_details.truncate(params.max_edges_per_node);

        file_deps.insert(
            rel,
            json!({
                "imports_total": analysis.imports.len(),
                "resolved_internal": resolved_internal,
                "unresolved_actionable": unresolved_actionable,
                "internal": internal,
                "restricted": restricted,
                "external": external,
                "unresolved": unresolved_list,
                "unresolved_details": unresolved_details,
            }),
        );

        if file_deps.len() >= params.max_nodes {
            break;
        }
    }

    Ok(file_deps)
}

pub(crate) fn apply_depth_limit(
    file_deps: &serde_json::Map<String, Value>,
    params: &QueryParams,
) -> serde_json::Map<String, Value> {
    let Some(max_depth) = params.depth else {
        return file_deps.clone();
    };

    let mut roots: Vec<String> = params.scope_path.as_deref().map_or_else(
        || file_deps.keys().cloned().collect(),
        |scope| {
            file_deps
                .keys()
                .filter(|k| k.contains(scope))
                .cloned()
                .collect()
        },
    );

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
            "inbound" => push_from("dependents"),
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

pub(crate) fn merge_with_reverse_dependencies(
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

pub(crate) fn reverse_dependencies(
    graph: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    let mut reversed = serde_json::Map::new();

    for (file, deps_obj) in graph {
        if let Some(obj) = deps_obj.as_object() {
            for key in ["internal", "restricted"] {
                if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
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
