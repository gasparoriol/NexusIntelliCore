use crate::privacy_gateway;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::{security, state, tools};
use serde_json::{json, Value};
use tracing::{error, info, warn};

pub async fn handle_request(req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);

    let state = state::ServerState::get();
    if !state.is_authenticated() && req.method != "initialize" {
        security::log_audit_event(
            "auth_failure",
            json!({
                "method": req.method,
                "reason": "unauthenticated request received before initialization"
            }),
        );
        return Some(JsonRpcResponse::error(
            id,
            -32001,
            "Unauthorized: client must authenticate during initialization".to_string(),
        ));
    }

    match req.method.as_str() {
        "initialize" => Some(handle_initialize(id, &req.params)),
        "notifications/initialized" => None,
        m if m.starts_with("notifications/") => None,
        "tools/list" => Some(handle_tools_list(id)),
        "tools/call" => Some(handle_tool_call(id, req.params).await),
        "ping" => Some(JsonRpcResponse::success(id, json!({}))),
        other => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {other}"),
        )),
    }
}

fn handle_initialize(id: Value, params: &Value) -> JsonRpcResponse {
    let state = state::ServerState::get();
    let mut token_found = None;

    if state.security_config().auth_token.is_some() {
        let token_opt = params
            .get("auth_token")
            .or_else(|| params.get("token"))
            .or_else(|| params.get("_meta").and_then(|m| m.get("auth_token")))
            .or_else(|| params.get("_meta").and_then(|m| m.get("token")))
            .and_then(|v| v.as_str());

        if let Some(t) = token_opt {
            if state.authenticate(t) {
                token_found = Some("[PRESENT]".to_string());
            }
        }

        if !state.is_authenticated() {
            security::log_audit_event(
                "auth_failure",
                json!({
                    "method": "initialize",
                    "reason": "missing or invalid authentication token"
                }),
            );
            return JsonRpcResponse::error(
                id,
                -32001,
                "Unauthorized: missing or invalid authentication token".to_string(),
            );
        }
    }

    security::log_audit_event(
        "auth_success",
        json!({
            "method": "initialize",
            "token_present": token_found.is_some()
        }),
    );

    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "NexusIntelliCore",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Semantic code analysis MCP server with Privacy Gateway"
            }
        }),
    )
}

fn handle_tools_list(id: Value) -> JsonRpcResponse {
    let state = state::ServerState::get();
    let all_tools = tools::tool_definitions();
    let filtered_tools = if let Some(ref allowed) = state.security_config().allowed_tools {
        all_tools.as_array().map_or(all_tools.clone(), |arr| {
            let filtered: Vec<Value> = arr
                .iter()
                .filter(|t| {
                    t.get("name")
                        .and_then(|v| v.as_str())
                        .is_some_and(|name| allowed.iter().any(|tool| tool == name))
                })
                .cloned()
                .collect();
            Value::Array(filtered)
        })
    } else {
        all_tools
    };

    security::log_audit_event(
        "tools_list",
        json!({
            "count": filtered_tools.as_array().map_or(0, std::vec::Vec::len)
        }),
    );

    JsonRpcResponse::success(id, json!({ "tools": filtered_tools }))
}

async fn handle_tool_call(id: Value, params: Value) -> JsonRpcResponse {
    let name = if let Some(n) = params.get("name").and_then(|v| v.as_str()) {
        n.to_owned()
    } else {
        warn!("Missing 'name' in tool call");
        return JsonRpcResponse::error(id, -32602, "Missing 'name' in tool call".to_owned());
    };

    let state = state::ServerState::get();
    if let Some(ref allowed) = state.security_config().allowed_tools {
        if !allowed.contains(&name) {
            warn!(tool = %name, "Access denied: tool not in allowed list");
            security::log_audit_event(
                "tool_denied",
                json!({
                    "tool": name,
                    "reason": "tool not allowed in security configuration"
                }),
            );
            return JsonRpcResponse::error(
                id,
                -32003,
                format!("Access denied: tool '{name}' is not allowed"),
            );
        }
    }

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let policy = privacy_gateway::PrivacyPolicy::default();
    let sanitized_args = privacy_gateway::sanitize_json_args(&args, &policy);

    let start = std::time::Instant::now();
    info!(tool = %name, "Tool call received");

    security::log_audit_event(
        "tool_call_start",
        json!({
            "tool": name,
            "arguments": sanitized_args
        }),
    );

    match tools::dispatch_tool(&name, args).await {
        Ok(result) => {
            let elapsed = start.elapsed().as_millis();
            info!(tool = %name, elapsed_ms = %elapsed, "Tool call completed successfully");
            security::log_audit_event(
                "tool_call_success",
                json!({
                    "tool": name,
                    "elapsed_ms": elapsed
                }),
            );
            JsonRpcResponse::success(id, result)
        }
        Err(e) => {
            let error_msg = e.to_string();
            error!(tool = %name, error = %error_msg, "Tool call failed with internal error");
            security::log_audit_event(
                "tool_call_failure",
                json!({
                    "tool": name,
                    "error": error_msg
                }),
            );
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{ "type": "text", "text": format!("Internal error: {e}") }],
                    "isError": true
                }),
            )
        }
    }
}
