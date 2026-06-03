/// NexusIntelliCore MCP Server
///
/// Implements the Model Context Protocol (MCP) over stdin/stdout using
/// standard MCP framing (Content-Length headers).  All code extracts pass through the
/// Phase-4 Privacy Gateway before being returned to the LLM client.
mod analyzer;
mod audit_queries;
mod indexer;
mod privacy_gateway;
mod protocol;
mod relations;
mod sanitizer;
mod security;
mod state;
mod tools;
mod transport;
mod watcher;

use protocol::{JsonRpcRequest, JsonRpcResponse};
use serde_json::{json, Value};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Logging to stderr (stdout is reserved for JSON-RPC)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nexusintellicore=info".parse().unwrap())
                .add_directive("nexusintellicore_mcp=info".parse().unwrap()),
        )
        .init();

    // Determine project root from CLI arg or environment variable
    let root = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("MCP_ROOT_PATH").ok())
        .unwrap_or_else(|| {
            eprintln!("Usage: nexusintellicore <project-root>");
            eprintln!("   or: MCP_ROOT_PATH=/path/to/project nexusintellicore");
            std::process::exit(1);
        });

    if let Err(e) = state::ServerState::init(&root) {
        error!("Fatal: failed to initialise server state: {}", e);
        std::process::exit(1);
    }

    let state = state::ServerState::get();
    info!(root = %state.root().display(), "NexusIntelliCore MCP server started");

    // Start the file watcher for automatic cache invalidation.
    // The result is intentionally kept alive for the duration of the process.
    let _file_watcher = watcher::FileWatcher::start(state.root().to_path_buf());

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let mut transport = transport::McpTransport::new(stdin, stdout);
    let mut seen_first_message = false;

    loop {
        let read_result = if !seen_first_message {
            match timeout(Duration::from_secs(5), transport.read_message()).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(
                        "Still waiting for first MCP frame on stdin (client may be running but not wired to stdio transport)"
                    );
                    continue;
                }
            }
        } else {
            transport.read_message().await
        };

        match read_result {
            Ok(None) => {
                info!("EOF received, shutting down");
                break;
            }
            Ok(Some(msg)) => {
                seen_first_message = true;
                let response = match serde_json::from_value::<JsonRpcRequest>(msg) {
                    Ok(req) => {
                        if req.jsonrpc != "2.0" {
                            warn!(version = %req.jsonrpc, "Unsupported jsonrpc version");
                            Some(JsonRpcResponse::error(
                                req.id.unwrap_or(Value::Null),
                                -32600,
                                format!("Unsupported jsonrpc version: {}", req.jsonrpc),
                            ))
                        } else {
                            handle_request(req).await
                        }
                    }
                    Err(e) => Some(JsonRpcResponse::error(
                        Value::Null,
                        -32700,
                        format!("Parse error: {}", e),
                    )),
                };

                if let Some(resp) = response {
                    if let Err(e) = transport.write_message(&resp).await {
                        error!("Failed to write response — pipe closed? Error: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Read error or framing error: {}, shutting down", e);
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Request dispatcher
// ---------------------------------------------------------------------------

async fn handle_request(req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);

    let state = state::ServerState::get();
    if !state.is_authenticated() && req.method != "initialize" {
        security::log_audit_event("auth_failure", json!({
            "method": req.method,
            "reason": "unauthenticated request received before initialization"
        }));
        return Some(JsonRpcResponse::error(
            id,
            -32001,
            "Unauthorized: client must authenticate during initialization".to_string()
        ));
    }

    match req.method.as_str() {
        // ---- MCP lifecycle ------------------------------------------------
        "initialize" => Some(handle_initialize(id, req.params)),

        // Notifications carry no id and expect no response
        "notifications/initialized" => None,
        m if m.starts_with("notifications/") => None,

        // ---- MCP tool protocol --------------------------------------------
        "tools/list" => Some(handle_tools_list(id)),
        "tools/call" => Some(handle_tool_call(id, req.params).await),

        // ---- Ping (optional, some clients use it) -------------------------
        "ping" => Some(JsonRpcResponse::success(id, json!({}))),

        // ---- Unknown method -----------------------------------------------
        other => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", other),
        )),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle handlers
// ---------------------------------------------------------------------------

fn handle_initialize(id: Value, params: Value) -> JsonRpcResponse {
    let state = state::ServerState::get();
    let mut token_found = None;

    if state.security_config().auth_token.is_some() {
        let token_opt = params.get("auth_token")
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
            security::log_audit_event("auth_failure", json!({
                "method": "initialize",
                "reason": "missing or invalid authentication token"
            }));
            return JsonRpcResponse::error(
                id,
                -32001,
                "Unauthorized: missing or invalid authentication token".to_string(),
            );
        }
    }

    security::log_audit_event("auth_success", json!({
        "method": "initialize",
        "token_present": token_found.is_some()
    }));

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
        if let Some(arr) = all_tools.as_array() {
            let filtered: Vec<Value> = arr
                .iter()
                .filter(|t| {
                    t.get("name")
                        .and_then(|v| v.as_str())
                        .map(|name| allowed.contains(&name.to_string()))
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            Value::Array(filtered)
        } else {
            all_tools
        }
    } else {
        all_tools
    };

    security::log_audit_event("tools_list", json!({
        "count": filtered_tools.as_array().map(|a| a.len()).unwrap_or(0)
    }));

    JsonRpcResponse::success(id, json!({ "tools": filtered_tools }))
}

async fn handle_tool_call(id: Value, params: Value) -> JsonRpcResponse {
    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_owned(),
        None => {
            warn!("Missing 'name' in tool call");
            return JsonRpcResponse::error(id, -32602, "Missing 'name' in tool call".to_owned());
        }
    };

    let state = state::ServerState::get();
    if let Some(ref allowed) = state.security_config().allowed_tools {
        if !allowed.contains(&name) {
            warn!(tool = %name, "Access denied: tool not in allowed list");
            security::log_audit_event("tool_denied", json!({
                "tool": name,
                "reason": "tool not allowed in security configuration"
            }));
            return JsonRpcResponse::error(
                id,
                -32003,
                format!("Access denied: tool '{}' is not allowed", name),
            );
        }
    }

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let start = std::time::Instant::now();
    info!(tool = %name, "Tool call received");

    security::log_audit_event("tool_call_start", json!({
        "tool": name,
        "arguments": args
    }));

    match tools::dispatch_tool(&name, args).await {
        Ok(result) => {
            let elapsed = start.elapsed().as_millis();
            info!(tool = %name, elapsed_ms = %elapsed, "Tool call completed successfully");
            security::log_audit_event("tool_call_success", json!({
                "tool": name,
                "elapsed_ms": elapsed
            }));
            JsonRpcResponse::success(id, result)
        }
        Err(e) => {
            let error_msg = e.to_string();
            error!(tool = %name, error = %error_msg, "Tool call failed with internal error");
            security::log_audit_event("tool_call_failure", json!({
                "tool": name,
                "error": error_msg
            }));
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{ "type": "text", "text": format!("Internal error: {}", e) }],
                    "isError": true
                }),
            )
        }
    }
}
