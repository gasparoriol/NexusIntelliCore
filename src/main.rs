/// NexusIntelliCore — Code2Prompt MCP Server
///
/// Implements the Model Context Protocol (MCP) over stdin/stdout using
/// standard MCP framing (Content-Length headers).  All code extracts pass through the
/// Phase-4 Privacy Gateway before being returned to the LLM client.
mod analyzer;
mod indexer;
mod privacy_gateway;
mod protocol;
mod relations;
mod sanitizer;
mod state;
mod tools;
mod transport;

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
            eprintln!("Usage: nexusintellicore-mcp <project-root>");
            eprintln!("   or: MCP_ROOT_PATH=/path/to/project nexusintellicore-mcp");
            std::process::exit(1);
        });

    if let Err(e) = state::ServerState::init(&root) {
        error!("Fatal: failed to initialise server state: {}", e);
        std::process::exit(1);
    }

    let state = state::ServerState::get();
    info!(root = %state.root().display(), "NexusIntelliCore MCP server started");

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

    match req.method.as_str() {
        // ---- MCP lifecycle ------------------------------------------------
        "initialize" => Some(handle_initialize(id)),

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

fn handle_initialize(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "code2prompt-mcp",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Semantic code analysis MCP server with Privacy Gateway"
            }
        }),
    )
}

fn handle_tools_list(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!({ "tools": tools::tool_definitions() }))
}

async fn handle_tool_call(id: Value, params: Value) -> JsonRpcResponse {
    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_owned(),
        None => {
            warn!("Missing 'name' in tool call");
            return JsonRpcResponse::error(id, -32602, "Missing 'name' in tool call".to_owned());
        }
    };

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let start = std::time::Instant::now();
    info!(tool = %name, "Tool call received");

    match tools::dispatch_tool(&name, args).await {
        Ok(result) => {
            info!(tool = %name, elapsed_ms = %start.elapsed().as_millis(), "Tool call completed successfully");
            JsonRpcResponse::success(id, result)
        }
        Err(e) => {
            error!(tool = %name, error = %e, "Tool call failed with internal error");
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
