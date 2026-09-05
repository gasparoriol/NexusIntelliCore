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
mod projects_tool;
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
    definitions::registered_tool_definitions()
        .into_iter()
        .find(|def| def.name == name)
        .is_some_and(|def| def.cacheable)
}

#[allow(clippy::too_many_lines)] // Routing match table; splitting by sub-groups would only add indirection
async fn dispatch_tool_uncached(
    state: &std::sync::Arc<crate::state::ServerState>,
    name: &str,
    args: &Value,
) -> Result<Value> {
    let raw = match name {
        "get_project_structure" => project::get_project_structure(state, args).await,
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
        "list_projects" => projects_tool::list_projects(state).await,
        "register_project" => projects_tool::register_project(state, args).await,
        "unregister_project" => projects_tool::unregister_project(state, args).await,
        other => Ok(error_response(format!("Unknown tool: {other}"))),
    };
    // Single output boundary: every tool result passes through the privacy gateway
    // regardless of whether the handler applied its own specialised sanitiser.
    raw.map(apply_final_privacy_pass)
}

/// Applies a defensive privacy pass to the full JSON tool result. Handlers may
/// apply domain-specific sanitizers first, but this is the final boundary gate
/// before a result is inserted into cache or returned to the client.
fn apply_final_privacy_pass(result: Value) -> Value {
    let policy = crate::privacy_gateway::PrivacyPolicy::default();
    crate::privacy_gateway::sanitize_json_args(&result, &policy)
}

fn get_tool_timeout_duration() -> std::time::Duration {
    let secs = std::env::var("MCP_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

/// Dispatch a `tools/call` request to the appropriate handler.
pub async fn dispatch_tool(name: &str, args: Value) -> Result<Value> {
    let timeout_duration = get_tool_timeout_duration();
    match tokio::time::timeout(timeout_duration, dispatch_tool_internal(name, args)).await {
        Ok(res) => res,
        Err(_) => Ok(apply_final_privacy_pass(error_response(format!(
            "Tool '{name}' timed out after {} seconds. Operation cancelled to preserve server responsiveness.",
            timeout_duration.as_secs()
        )))),
    }
}

async fn dispatch_tool_internal(name: &str, args: Value) -> Result<Value> {
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
            return Ok(apply_final_privacy_pass(error_response(format!(
                "Tool '{name}' is temporarily unavailable: server is processing too many \
                 concurrent requests. Please retry in a few seconds."
            ))));
        }
    } else {
        None
    };
    // automatically release the permit at the final of the function

    if !tool_is_cacheable(name) {
        return dispatch_tool_uncached(&state, name, &args).await;
    }

    let key = state.make_tool_cache_key(name, &args);
    let args_for_compute = args.clone();
    let name_for_compute = name.to_owned();

    if state.get_tool_cache(&key).await.is_some() {
        state.record_tool_cache_hit();
    } else {
        state.record_tool_cache_miss();
    }

    let result = if let Some(cached) = state.get_tool_cache(&key).await {
        cached
    } else {
        let computed = dispatch_tool_uncached(&state, &name_for_compute, &args_for_compute)
            .await
            // error text from anyhow may contain paths/values; sanitize before surfacing
            .unwrap_or_else(|e| {
                let policy = crate::privacy_gateway::PrivacyPolicy::default();
                let sanitized_msg =
                    crate::privacy_gateway::sanitize_output_text(&e.to_string(), &policy).0;
                apply_final_privacy_pass(error_response(format!(
                    "Internal tool error: {sanitized_msg}"
                )))
            });

        if computed.get("isError").and_then(Value::as_bool) != Some(true) {
            state.insert_tool_cache(key.clone(), computed.clone()).await;
        }

        computed
    };

    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        state.invalidate_tool_cache_for_file(&state.root());
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
    definitions::registered_tool_definitions()
        .into_iter()
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
        let response = super::dispatch_tool_uncached(&state, "generate_project_docs", &args)
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
        let response = super::dispatch_tool_uncached(&state, "analyze_angular_component", &args)
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
        let response = super::dispatch_tool_uncached(&state, "analyze_angular_component", &args)
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
            "list_projects",
            "register_project",
            "unregister_project",
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

    #[test]
    fn final_privacy_pass_redacts_nested_payloads_and_errors() {
        let payload = json!({
            "content": [{
                "type": "text",
                "text": "visible note; token=ghp_1234567890abcdef"
            }],
            "isError": true,
            "error": {
                "message": "db password=secret123",
                "details": {
                    "api_key": "sk-abcdefghijklmnopqrstuvwxyz123456",
                    "nested": ["private IP 10.0.0.5", "safe value"]
                }
            }
        });

        let sanitized = super::apply_final_privacy_pass(payload);
        let rendered = sanitized.to_string();

        assert!(!rendered.contains("ghp_1234567890abcdef"));
        assert!(!rendered.contains("secret123"));
        assert!(!rendered.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!rendered.contains("10.0.0.5"));
        assert!(rendered.contains("[REDACTED") || rendered.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn final_privacy_pass_is_idempotent() {
        let payload = json!({
            "content": [{ "type": "text", "text": "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz123456" }],
            "metadata": { "token": "ghp_1234567890abcdef" }
        });

        let once = super::apply_final_privacy_pass(payload);
        let twice = super::apply_final_privacy_pass(once.clone());
        assert_eq!(once, twice);
        let rendered = once.to_string();
        assert!(!rendered.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!rendered.contains("ghp_1234567890abcdef"));
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
        let response = super::dispatch_tool_uncached(&state, "query_ast", &args)
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
        let response = super::dispatch_tool_uncached(&state, "read_config_file", &args)
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
        let response = super::dispatch_tool_uncached(&state, "lint_file", &args)
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
        let response = super::dispatch_tool_uncached(&state, "lint_file", &args)
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
        let response = super::dispatch_tool_uncached(&state, "get_file_outline", &args)
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

    // -----------------------------------------------------------------------
    // A1 — error paths must not leak unsanitized values
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn error_paths_do_not_leak_secrets() {
        ensure_state_init();

        // A tool name that triggers the "unknown tool" error path; the sentinel
        // value must not survive as-is in the response text.
        let sentinel = "sk-proj-FAKEOPENAIKEY12345abcdefghijklmnop";
        let args = json!({ "file_path": format!("/tmp/{sentinel}.rs") });
        let state = crate::state::ServerState::get();
        let response = super::dispatch_tool_uncached(&state, "unknown_tool_for_test", &args)
            .await
            .expect("dispatch should not propagate Err for unknown tools");

        let rendered = response.to_string();
        assert!(
            !rendered.contains(sentinel),
            "Unknown-tool error must not echo raw argument values: {rendered}"
        );

        // The "argument error" path: require_str propagates Err directly.
        // apply_final_privacy_pass must be applied on the Ok path; Err values
        // are plain anyhow errors whose to_string() does not contain the sentinel.
        let args2 = json!({ "file_path": format!("/tmp/{sentinel}.rs") });
        let result2 = super::dispatch_tool_uncached(&state, "inspect_symbol", &args2).await;
        match result2 {
            Ok(response2) => {
                let rendered2 = response2.to_string();
                assert!(
                    !rendered2.contains(sentinel),
                    "Argument-error path must not leak sentinel from file_path: {rendered2}"
                );
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains(sentinel),
                    "Propagated Err must not contain sentinel: {msg}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // A2 — extensibility gate: every registered tool output crosses the boundary
    // -----------------------------------------------------------------------

    #[test]
    fn all_registered_tools_are_covered_by_sentinel_gate() {
        use crate::tools::definitions::{all_tool_definitions, angular_tool_definitions};
        // This test freezes the set of tool names that exist in the registry.
        // If a new tool is added, the developer must also add a sentinel test
        // in tests/privacy_adversarial.rs and update this baseline.
        let mut names: Vec<&str> = all_tool_definitions()
            .iter()
            .map(|d| d.name)
            .chain(std::iter::once(angular_tool_definitions().name))
            .collect();
        names.sort_unstable();

        // Baseline — must be updated when the registry changes.
        let mut expected = vec![
            "analyze_angular_component",
            "audit_security_measures",
            "generate_project_docs",
            "get_dependencies_graph",
            "get_file_outline",
            "get_module_summary",
            "get_project_structure",
            "get_server_stats",
            "inspect_symbol",
            "lint_file",
            "list_projects",
            "query_ast",
            "read_config_file",
            "refresh_index",
            "register_project",
            "search_design_patterns",
            "unregister_project",
        ];
        expected.sort_unstable();

        assert_eq!(
            names, expected,
            "Registry changed — update the sentinel baseline and add a privacy test for new tools"
        );
    }

    // -----------------------------------------------------------------------
    // Overhead p95 of the final privacy pass (mitigación 02, métrica)
    // -----------------------------------------------------------------------

    /// Baseline captured 2026-08-18 on Apple Silicon (debug build). Purely
    /// informational — regression is flagged only if p95 exceeds 10× baseline.
    const PRIVACY_PASS_P95_BASELINE_US: u128 = 500;

    #[test]
    fn benchmark_final_privacy_pass_p95_stays_within_budget() {
        let payload = json!({
            "content": [
                { "type": "text", "text": "hello token=abc IP=10.0.0.1" },
                { "type": "text", "text": "safe body without secrets" },
            ],
            "meta": {
                "nested": {
                    "note": "no sensitive material here",
                    "list": ["a", "b", "c", "d", "e"]
                }
            }
        });

        let iterations = 200usize;
        let mut samples_us: Vec<u128> = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            let _ = super::apply_final_privacy_pass(payload.clone());
            samples_us.push(start.elapsed().as_micros());
        }
        samples_us.sort_unstable();
        let p95_index = (iterations * 95) / 100;
        let p95 = samples_us[p95_index];

        // 10× the baseline gives generous headroom for CI machines while still
        // catching any 100× regression.
        let ceiling = PRIVACY_PASS_P95_BASELINE_US * 10;
        assert!(
            p95 <= ceiling,
            "privacy pass p95 regression: {p95} µs > ceiling {ceiling} µs (baseline {} µs)",
            PRIVACY_PASS_P95_BASELINE_US
        );
    }
}
