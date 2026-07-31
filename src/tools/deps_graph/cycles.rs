use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use serde_json::Value;
use std::collections::HashMap;

pub(crate) fn detect_dependency_cycles(
    file_deps: &serde_json::Map<String, Value>,
) -> Vec<Vec<String>> {
    let mut graph: DiGraph<String, ()> = DiGraph::new();
    let mut node_by_file: HashMap<String, NodeIndex> = HashMap::new();

    for file in file_deps.keys() {
        let node = graph.add_node(file.clone());
        node_by_file.insert(file.clone(), node);
    }

    for (source, deps_obj) in file_deps {
        let Some(&source_node) = node_by_file.get(source) else {
            continue;
        };

        if let Some(obj) = deps_obj.as_object() {
            for key in ["internal", "restricted"] {
                if let Some(arr) = obj.get(key).and_then(Value::as_array) {
                    for dep in arr {
                        let Some(dep_file) = dep.as_str() else {
                            continue;
                        };
                        if let Some(&target_node) = node_by_file.get(dep_file) {
                            graph.add_edge(source_node, target_node, ());
                        }
                    }
                }
            }
        }
    }

    let mut cycles: Vec<Vec<String>> = Vec::new();

    for component in kosaraju_scc(&graph) {
        if component.len() > 1 {
            let mut files: Vec<String> = component.iter().map(|idx| graph[*idx].clone()).collect();
            files.sort();
            cycles.push(files);
            continue;
        }

        if let Some(node) = component.first() {
            if graph.contains_edge(*node, *node) {
                cycles.push(vec![graph[*node].clone()]);
            }
        }
    }

    cycles.sort();
    cycles
}
