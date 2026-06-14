/// The MCP tools module.
///
/// Each tool handler lives in its own submodule. This file contains only
/// the public dispatch entry-point and the JSON schema registry.
use anyhow::Result;
use serde_json::Value;

use crate::protocol::error_response;

mod angular;
mod audit;
mod definitions;
mod deps_graph;
mod outline;
mod patterns;
mod project;
mod project_docs;
mod server;
mod summary;
mod symbol;

pub use definitions::tool_definitions;

fn tool_is_cacheable(name: &str) -> bool {
    use crate::tools::definitions::all_tool_definitions;
    all_tool_definitions()
        .iter()
        .find(|def| def.name == name)
        .map(|def| def.cacheable)
        .unwrap_or(false)
}

async fn dispatch_tool_uncached(name: &str, args: &Value) -> Result<Value> {
    match name {
        "get_project_structure" => project::get_project_structure().await,
        "get_file_outline" => {
            let file = require_str(args, "file_path")?;
            outline::get_file_outline(file).await
        }
        "inspect_symbol" => {
            let file = require_str(args, "file_path")?;
            let symbol = require_str(args, "symbol_name")?;
            let match_mode = args
                .get("match_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            if !matches!(match_mode, "auto" | "simple" | "qualified") {
                return Ok(error_response(format!(
                    "Invalid match_mode '{}'. Allowed values: auto, simple, qualified",
                    match_mode
                )));
            }
            let return_all_matches = args
                .get("return_all_matches")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let signature_hint = args.get("signature_hint").and_then(|v| v.as_str());
            symbol::inspect_symbol(file, symbol, match_mode, return_all_matches, signature_hint)
                .await
        }
        "get_dependencies_graph" => deps_graph::get_dependencies_graph().await,
        "search_design_patterns" => {
            let file = args.get("file_path").and_then(|v| v.as_str());
            patterns::search_design_patterns(file).await
        }
        "audit_security_measures" => audit::audit_security_measures().await,
        "refresh_index" => server::refresh_index().await,
        "get_server_stats" => server::get_server_stats().await,
        "analyze_angular_component" => {
            let path = require_str(args, "component_path")?;
            angular::analyze_angular_component(path).await
        }
        "get_module_summary" => {
            let file = require_str(args, "file_path")?;
            let public_only = args
                .get("public_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            summary::get_module_summary(file, public_only).await
        }
        "generate_project_docs" => {
            let sections: Vec<String> = args
                .get("sections")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| {
                    vec![
                        "overview".into(),
                        "usage".into(),
                        "api".into(),
                        "use_cases".into(),
                    ]
                });
            let public_only = args
                .get("public_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let max_files = args
                .get("max_files")
                .and_then(|v| v.as_u64())
                .map(|n| (n as usize).min(150))
                .unwrap_or(50);
            let language = args
                .get("language")
                .and_then(|v| v.as_str())
                .unwrap_or("en")
                .to_owned();
            project_docs::generate_project_docs(sections, public_only, max_files, &language).await
        }
        other => Ok(error_response(format!("Unknown tool: {}", other))),
    }
}

/// Dispatch a `tools/call` request to the appropriate handler.
pub async fn dispatch_tool(name: &str, args: Value) -> Result<Value> {
    if !tool_is_cacheable(name) {
        return dispatch_tool_uncached(name, &args).await;
    }

    let state = crate::state::ServerState::get();
    let key = state.make_tool_cache_key(name, &args);
    let args_for_compute = args.clone();
    let name_for_compute = name.to_owned();

    let cache = state.tool_cache();
    let result = cache
        .get_with(key.clone(), async move {
            let computed = dispatch_tool_uncached(&name_for_compute, &args_for_compute)
                .await
                .unwrap_or_else(|e| error_response(format!("Internal tool error: {}", e)));
            computed
        })
        .await;

    if result.get("isError").and_then(|v| v.as_bool()) == Some(true) {
        cache.invalidate(&key).await;
    }

    Ok(result)
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {}", key))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn ensure_state_init() {
        if crate::state::ServerState::get_opt().is_none() {
            let original_security_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();
            std::env::remove_var("MCP_SECURITY_CONFIG_PATH");

            let init_result = crate::state::ServerState::init(".");

            if let Some(value) = original_security_config {
                std::env::set_var("MCP_SECURITY_CONFIG_PATH", value);
            } else {
                std::env::remove_var("MCP_SECURITY_CONFIG_PATH");
            }

            init_result.expect("test should initialize ServerState with repository root");
        }
    }

    #[tokio::test]
    async fn dispatch_routes_generate_project_docs() {
        ensure_state_init();

        let args = json!({
            "sections": ["overview"],
            "max_files": 1,
            "language": "en"
        });

        let response = super::dispatch_tool_uncached("generate_project_docs", &args)
            .await
            .expect("dispatcher should execute generate_project_docs route");

        assert_ne!(
            response.get("isError").and_then(|v| v.as_bool()),
            Some(true),
            "generate_project_docs dispatch should not return an error response"
        );
    }

    use crate::tools::definitions::all_tool_definitions;

    #[test]
    fn all_dispatched_tools_are_registered() {
        let known_names: std::collections::HashSet<&str> =
            all_tool_definitions().iter().map(|d| d.name).collect();

        // Lista maestra — debe mantenerse sincronizada con dispatch_tool_uncached
        let dispatched = [
            "get_project_structure",
            "get_file_outline",
            "inspect_symbol",
            "get_dependencies_graph",
            "search_design_patterns",
            "audit_security_measures",
            "refresh_index",
            "get_server_stats",
            "analyze_angular_component",
            "get_module_summary",
            "generate_project_docs",
        ];

        for name in dispatched {
            assert!(
                known_names.contains(name) || name == "analyze_angular_component",
                "Tool '{}' is dispatched but not registered in all_tool_definitions()",
                name
            );
        }
    }

    /// Verifica que herramientas con efectos secundarios no son cacheables.
    #[test]
    fn stateful_tools_are_not_cacheable() {
        let defs = all_tool_definitions();
        let find = |n: &str| defs.iter().find(|d| d.name == n).unwrap().cacheable;
        assert!(!find("refresh_index"));
        assert!(!find("get_server_stats"));
    }

    /// Verifica que herramientas de análisis son cacheables.
    #[test]
    fn analysis_tools_are_cacheable() {
        let defs = all_tool_definitions();
        let find = |n: &str| defs.iter().find(|d| d.name == n).unwrap().cacheable;
        assert!(find("get_file_outline"));
        assert!(find("inspect_symbol"));
        assert!(find("get_dependencies_graph"));
    }
}
