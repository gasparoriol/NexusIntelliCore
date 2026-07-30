/// The MCP tools module.
///
/// Each tool handler lives in its own submodule. This file contains only
/// the public dispatch entry-point and the JSON schema registry.
use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;

use crate::protocol::error_response;

mod angular;
mod audit;
mod config_file;
mod definitions;
mod deps_graph;
mod lint;
mod outline;
mod patterns;
mod project;
mod project_docs;
mod query_ast;
mod server;
mod summary;
mod symbol;

pub use definitions::tool_definitions;

#[derive(Deserialize, Debug)]
struct FilePathArgs {
    #[serde(alias = "FilePath", alias = "filepath", alias = "file-path")]
    file_path: Option<String>,
    #[serde(
        alias = "ComponentPath",
        alias = "componentPath",
        alias = "component-path"
    )]
    component_path: Option<String>,
}

fn tool_is_cacheable(name: &str) -> bool {
    use crate::tools::definitions::{all_tool_definitions, angular_tool_definitions};
    all_tool_definitions()
        .into_iter()
        .chain(std::iter::once(angular_tool_definitions()))
        .find(|def| def.name == name)
        .is_some_and(|def| def.cacheable)
}

#[allow(clippy::too_many_lines)] // Routing match table; splitting by sub-groups would only add indirection
async fn dispatch_tool_uncached(
    state: &crate::state::ServerState,
    name: &str,
    args: &Value,
) -> Result<Value> {
    match name {
        "get_project_structure" => project::get_project_structure(state).await,
        "get_file_outline" => {
            let file = require_file_path(args)?;
            outline::get_file_outline(state, &file).await
        }
        "inspect_symbol" => {
            let file = require_file_path(args)?;
            let symbol = require_str(args, "symbol_name")?;
            let match_mode = args
                .get("match_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            if !matches!(match_mode, "auto" | "simple" | "qualified") {
                return Ok(error_response(format!(
                    "Invalid match_mode '{match_mode}'. Allowed values: auto, simple, qualified"
                )));
            }
            let return_all_matches = args
                .get("return_all_matches")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let signature_hint = args.get("signature_hint").and_then(|v| v.as_str());
            symbol::inspect_symbol(
                state,
                &file,
                symbol,
                match_mode,
                return_all_matches,
                signature_hint,
            )
            .await
        }
        "lint_file" => {
            let file = require_file_path(args)?;
            lint::lint_file(state, &file).await
        }
        "get_dependencies_graph" => deps_graph::get_dependencies_graph(state, args).await,
        "query_ast" => {
            let file = require_file_path(args)?;
            let query_source = require_str(args, "query")?;
            query_ast::query_ast(state, &file, query_source).await
        }
        "read_config_file" => {
            let file = require_file_path(args)?;
            config_file::read_config_file(state, &file).await
        }
        "search_design_patterns" => patterns::search_design_patterns(state, args).await,
        "audit_security_measures" => audit::audit_security_measures(state).await,
        "refresh_index" => server::refresh_index(state).await,
        "get_server_stats" => server::get_server_stats(state).await,
        "analyze_angular_component" => {
            let path = require_file_path_or_component_path(args)?;
            angular::analyze_angular_component(state, &path).await
        }
        "get_module_summary" => {
            let file = require_file_path(args)?;
            let public_only = args
                .get("public_only")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            summary::get_module_summary(state, &file, public_only).await
        }
        "generate_project_docs" => {
            let sections: Vec<String> = args.get("sections").and_then(Value::as_array).map_or_else(
                || {
                    vec![
                        "overview".into(),
                        "usage".into(),
                        "api".into(),
                        "use_cases".into(),
                    ]
                },
                |arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                },
            );
            let public_only = args
                .get("public_only")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let max_files = args
                .get("max_files")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .map_or(50, |n| n.min(150));
            let file_offset = args
                .get("file_offset")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(0);
            let language = args
                .get("language")
                .and_then(Value::as_str)
                .unwrap_or("en")
                .to_owned();
            project_docs::generate_project_docs(
                state,
                sections,
                public_only,
                max_files,
                file_offset,
                &language,
            )
            .await
        }
        other => Ok(error_response(format!("Unknown tool: {other}"))),
    }
}

/// Dispatch a `tools/call` request to the appropriate handler.
pub async fn dispatch_tool(name: &str, args: Value) -> Result<Value> {
    let state = crate::state::ServerState::get();
    state.record_tool_invocation(name);

    // Concurrency guard for heavy tools
    let _permit = if is_expensive_tool(name) {
        if let Some(permit) = state
            .acquire_tool_permit_timeout(std::time::Duration::from_secs(30))
            .await
        {
            Some(permit)
        } else {
            state.record_tool_concurrency_rejection();
            tracing::warn!(tool = %name, "Tool rejected: concurrency limit exceeded");
            return Ok(error_response(format!(
                "Tool '{name}' is temporarily unavailable: server is processing too many \
                 concurrent requests. Please retry in a few seconds."
            )));
        }
    } else {
        None
    };
    // automatically release the permit at the final of the function

    if !tool_is_cacheable(name) {
        return dispatch_tool_uncached(state, name, &args).await;
    }

    let key = state.make_tool_cache_key(name, &args);
    let args_for_compute = args.clone();
    let name_for_compute = name.to_owned();

    let cache = state.tool_cache();
    if cache.contains_key(&key) {
        state.record_tool_cache_hit();
    } else {
        state.record_tool_cache_miss();
    }

    let result = cache
        .get_with(key.clone(), async move {
            // Inside the cache closure we still need state — re-acquire it here.
            // This is the one remaining call to get() that cannot be avoided because
            // the Moka closure is 'static and cannot capture a borrowed &ServerState.
            let s = crate::state::ServerState::get();
            dispatch_tool_uncached(s, &name_for_compute, &args_for_compute)
                .await
                .unwrap_or_else(|e| error_response(format!("Internal tool error: {e}")))
        })
        .await;

    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        cache.invalidate(&key).await;
    }

    Ok(result)
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {key}"))
}

fn require_file_path(args: &Value) -> Result<String> {
    let parsed: FilePathArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("Invalid argument format for file_path: {e}"))?;
    parsed.file_path.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing required argument: file_path (aliases: FilePath, filepath, file-path)"
        )
    })
}

fn require_file_path_or_component_path(args: &Value) -> Result<String> {
    let parsed: FilePathArgs = serde_json::from_value(args.clone()).map_err(|e| {
        anyhow::anyhow!("Invalid argument format for file_path/component_path: {e}")
    })?;
    parsed.file_path.or(parsed.component_path).ok_or_else(|| {
        anyhow::anyhow!(
            "Missing required argument: file_path (aliases: FilePath, filepath, file-path) or legacy component_path"
        )
    })
}

fn is_expensive_tool(name: &str) -> bool {
    use crate::tools::definitions::{all_tool_definitions, angular_tool_definitions};
    all_tool_definitions()
        .into_iter()
        .chain(std::iter::once(angular_tool_definitions()))
        .find(|def| def.name == name)
        .is_some_and(|def| def.expensive)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn ensure_state_init() {
        // Acquire the shared lock BEFORE the get_opt check to prevent a race
        // where test_load_from_corrupted_json_panics sets MCP_SECURITY_CONFIG_PATH
        // (and deletes the file) between ensure_state_init's remove_var and
        // ServerState::init, causing a "No such file" panic inside SecurityConfig::load.
        let _env_guard = crate::security::SECURITY_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if crate::state::ServerState::get_opt().is_none() {
            let original_security_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();
            std::env::remove_var("MCP_SECURITY_CONFIG_PATH");

            let init_result = crate::state::ServerState::init(".");

            if let Some(value) = original_security_config {
                std::env::set_var("MCP_SECURITY_CONFIG_PATH", value);
            } else {
                std::env::remove_var("MCP_SECURITY_CONFIG_PATH");
            }

            if let Err(err) = init_result {
                let msg = err.to_string();
                assert!(
                    msg.contains("already initialised"),
                    "test should initialize ServerState with repository root: {msg}"
                );
            }
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

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "generate_project_docs", &args)
            .await
            .expect("dispatcher should execute generate_project_docs route");

        assert_ne!(
            response.get("isError").and_then(serde_json::Value::as_bool),
            Some(true),
            "generate_project_docs dispatch should not return an error response"
        );
    }

    #[tokio::test]
    async fn analyze_angular_component_accepts_file_path_argument() {
        ensure_state_init();

        let args = json!({
            "file_path": "/definitely/not/found.component.ts"
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "analyze_angular_component", &args)
            .await
            .expect("dispatcher should execute analyze_angular_component route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        assert!(
            !text.contains("Missing required argument"),
            "analyze_angular_component should accept file_path without argument errors"
        );
    }

    #[tokio::test]
    async fn analyze_angular_component_accepts_legacy_component_path_argument() {
        ensure_state_init();

        let args = json!({
            "component_path": "/definitely/not/found.component.ts"
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "analyze_angular_component", &args)
            .await
            .expect("dispatcher should execute analyze_angular_component route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        assert!(
            !text.contains("Missing required argument"),
            "analyze_angular_component should keep supporting component_path for compatibility"
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
            "lint_file",
            "get_dependencies_graph",
            "query_ast",
            "read_config_file",
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
                "Tool '{name}' is dispatched but not registered in all_tool_definitions()"
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
        assert!(find("query_ast"));
        assert!(find("read_config_file"));
    }

    #[tokio::test]
    async fn query_ast_route_executes_and_sanitizes_captures() {
        ensure_state_init();

        let root = env!("CARGO_MANIFEST_DIR");
        let file = std::path::Path::new(root).join("tests/fixtures/query_ast_route_test.rs");
        std::fs::create_dir_all(file.parent().expect("fixtures parent should exist"))
            .expect("fixtures directory should exist");
        std::fs::write(
            &file,
            r#"fn main() {
    println!("sk-abcdefghijklmnopqrstuvwxyz123456");
}"#,
        )
        .expect("fixture file should be written");

        let args = json!({
            "file_path": file.to_string_lossy(),
            "query": "(macro_invocation) @call"
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "query_ast", &args)
            .await
            .expect("dispatcher should execute query_ast route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let payload: serde_json::Value =
            serde_json::from_str(text).expect("query_ast should return JSON payload");
        let captures = payload
            .get("captures")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();

        assert!(
            !captures.is_empty(),
            "query_ast should return at least one capture"
        );

        let flattened = captures
            .iter()
            .filter_map(|c| c.get("text").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            flattened.contains("[REDACTED_BY_MCP]"),
            "captured source should be sanitized by Privacy Gateway"
        );

        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn read_config_file_route_redacts_secrets() {
        ensure_state_init();

        let root = env!("CARGO_MANIFEST_DIR");
        let file = std::path::Path::new(root)
            .join("tests/fixtures/read_config_file_route_test.properties");
        std::fs::create_dir_all(file.parent().expect("fixtures parent should exist"))
            .expect("fixtures directory should exist");
        std::fs::write(
            &file,
            "server.port=8080\nspring.datasource.password=hunter2\nserver.host=8.8.8.8\n",
        )
        .expect("fixture file should be written");

        let args = json!({
            "file_path": file.to_string_lossy()
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "read_config_file", &args)
            .await
            .expect("dispatcher should execute read_config_file route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let payload: serde_json::Value =
            serde_json::from_str(text).expect("read_config_file should return JSON payload");
        let content = payload
            .get("content")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        assert!(content.contains("server.port=8080"));
        assert!(!content.contains("hunter2"));
        assert!(!content.contains("8.8.8.8"));
        assert!(content.contains("[REDACTED_BY_MCP]"));

        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn lint_file_route_is_dispatchable() {
        ensure_state_init();

        let args = json!({
            "file_path": "/definitely/not/found.rs"
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "lint_file", &args)
            .await
            .expect("dispatcher should execute lint_file route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        assert!(
            !text.contains("Missing required argument"),
            "lint_file should accept file_path without argument errors"
        );
    }

    #[tokio::test]
    async fn lint_file_accepts_filepath_alias() {
        ensure_state_init();

        let args = json!({
            "file-path": "/definitely/not/found.rs"
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "lint_file", &args)
            .await
            .expect("dispatcher should execute lint_file route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        assert!(
            !text.contains("Missing required argument"),
            "lint_file should accept file-path alias without argument errors"
        );
    }

    #[tokio::test]
    async fn get_file_outline_accepts_filepath_alias() {
        ensure_state_init();

        let args = json!({
            "FilePath": "/definitely/not/found.rs"
        });

        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(state, "get_file_outline", &args)
            .await
            .expect("dispatcher should execute get_file_outline route");

        let text = response
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        assert!(
            !text.contains("Missing required argument"),
            "get_file_outline should accept FilePath alias without argument errors"
        );
    }
}
