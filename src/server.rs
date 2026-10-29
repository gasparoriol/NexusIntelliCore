use crate::privacy_gateway;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::state::Session;
use crate::{security, state, tools};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::{error, info, warn};

pub async fn handle_request(session: &Session, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
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
        "initialize" => Some(handle_initialize(session, id, &req.params)),
        "notifications/initialized" => None,
        m if m.starts_with("notifications/") => None,
        "tools/list" => Some(handle_tools_list(id)),
        "tools/call" => Some(handle_tool_call(session, id, req.params).await),
        "ping" => Some(JsonRpcResponse::success(id, json!({}))),
        other => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {other}"),
        )),
    }
}

static AUTH_FAILURE_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Converts a `file://` URI (or a plain path) from the `initialize` request into a path.
fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let Some(rest) = uri.strip_prefix("file://") else {
        return uri.starts_with('/').then(|| PathBuf::from(uri));
    };
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let bytes = rest.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = rest.get(i + 1..i + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    let path = String::from_utf8(decoded).ok()?;
    // Windows drive URIs look like `/C:/dir`
    let path = match path.as_bytes() {
        [b'/', drive, b':', ..] if drive.is_ascii_alphabetic() => path[1..].to_owned(),
        _ => path,
    };
    Some(PathBuf::from(path))
}

/// Activates, for this session, the registered project matching `rootUri` or any
/// of `workspaceFolders` from the MCP `initialize` request.
fn select_project_from_initialize(session: &Session, params: &Value) {
    let state = state::ServerState::get();
    let root_uri = params.get("rootUri").and_then(Value::as_str);
    let folder_uris = params
        .get("workspaceFolders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| f.get("uri").and_then(Value::as_str));

    for uri in root_uri.into_iter().chain(folder_uris) {
        let Some(proj) = uri_to_path(uri).and_then(|p| state.project_containing(&p)) else {
            continue;
        };
        info!(project_id = %proj.id, "Active project selected from initialize handshake");
        session.set_active_project_id(proj.id.clone());
        return;
    }
}

fn handle_initialize(session: &Session, id: Value, params: &Value) -> JsonRpcResponse {
    let state = state::ServerState::get();
    let mut token_found = None;

    if state.security_config().auth_token_hash.is_some() {
        let token_opt = params
            .get("auth_token")
            .or_else(|| params.get("token"))
            .or_else(|| params.get("_meta").and_then(|m| m.get("auth_token")))
            .or_else(|| params.get("_meta").and_then(|m| m.get("token")))
            .and_then(|v| v.as_str());

        if let Some(t) = token_opt {
            if state.authenticate(t) {
                token_found = Some("[PRESENT]".to_string());
                AUTH_FAILURE_COUNT.store(0, std::sync::atomic::Ordering::Release);
            }
        }

        if !state.is_authenticated() {
            let fails = AUTH_FAILURE_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
            if fails >= 3 {
                let delay_ms = (250 * (1 << (fails - 3).min(4))).min(2000);
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
            security::log_audit_event(
                "auth_failure",
                json!({
                    "method": "initialize",
                    "reason": "missing or invalid authentication token",
                    "consecutive_failures": fails
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

    select_project_from_initialize(session, params);

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

async fn handle_tool_call(session: &Session, id: Value, params: Value) -> JsonRpcResponse {
    let name = if let Some(n) = params.get("name").and_then(|v| v.as_str()) {
        n.to_owned()
    } else {
        warn!("Missing 'name' in tool call");
        return JsonRpcResponse::error(id, -32602, "Missing 'name' in tool call".to_owned());
    };

    // Sanitize the caller-controlled tool name before using it in any error messages.
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (safe_name, _) = privacy_gateway::sanitize_output_text(&name, &policy);

    let state = state::ServerState::get();
    if let Some(ref allowed) = state.security_config().allowed_tools {
        if !allowed.contains(&name) {
            warn!(tool = %safe_name, "Access denied: tool not in allowed list");
            security::log_audit_event(
                "tool_denied",
                json!({
                    "tool": safe_name,
                    "reason": "tool not allowed in security configuration"
                }),
            );
            return JsonRpcResponse::error(
                id,
                -32003,
                format!("Access denied: tool '{safe_name}' is not allowed"),
            );
        }
    }

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let sanitized_args = privacy_gateway::sanitize_json_args(&args, &policy);

    let start = std::time::Instant::now();
    info!(tool = %safe_name, "Tool call received");

    security::log_audit_event(
        "tool_call_start",
        json!({
            "tool": safe_name,
            "arguments": sanitized_args
        }),
    );

    match tools::dispatch_tool(session, &name, args).await {
        Ok(result) => {
            let elapsed = start.elapsed().as_millis();
            info!(tool = %safe_name, elapsed_ms = %elapsed, "Tool call completed successfully");
            security::log_audit_event(
                "tool_call_success",
                json!({
                    "tool": safe_name,
                    "elapsed_ms": elapsed
                }),
            );
            JsonRpcResponse::success(id, result)
        }
        Err(e) => {
            error!(tool = %safe_name, "Tool call failed with internal error");
            let (sanitized_msg, _) = privacy_gateway::sanitize_output_text(&e.to_string(), &policy);
            security::log_audit_event("tool_call_failure", json!({ "tool": safe_name }));
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{ "type": "text", "text": format!("Internal error: {sanitized_msg}") }],
                    "isError": true
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::uri_to_path;
    use std::path::PathBuf;

    #[test]
    fn uri_to_path_decodes_file_uris() {
        assert_eq!(
            uri_to_path("file:///Users/me/My%20Project"),
            Some(PathBuf::from("/Users/me/My Project"))
        );
        assert_eq!(
            uri_to_path("file:///C:/work/app"),
            Some(PathBuf::from("C:/work/app"))
        );
        assert_eq!(
            uri_to_path("/plain/path"),
            Some(PathBuf::from("/plain/path"))
        );
        assert_eq!(uri_to_path("https://example.com"), None);
        assert_eq!(uri_to_path("file:///bad%zz"), None);
    }
}
