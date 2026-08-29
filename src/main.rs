/// `NexusIntelliCore` MCP Server
///
/// Implements the Model Context Protocol (MCP) over stdin/stdout using
/// standard MCP framing (Content-Length headers).  All code extracts pass through the
/// Phase-4 Privacy Gateway before being returned to the LLM client.
mod analyzer;
mod audit_queries;
mod indexer;
mod linter;
mod privacy_gateway;
mod protocol;
mod relations;
mod sanitizer;
mod security;
mod server;
mod state;
mod tools;
mod transport;
mod watcher;

use protocol::{JsonRpcRequest, JsonRpcResponse};
use serde_json::Value;

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

    // Collect project roots from CLI args (skip binary name) or environment variable
    let cli_roots: Vec<String> = std::env::args().skip(1).collect();
    let roots = if !cli_roots.is_empty() {
        cli_roots
    } else if let Ok(env_root) = std::env::var("MCP_ROOT_PATH") {
        vec![env_root]
    } else {
        vec![]
    };

    if roots.is_empty() {
        if let Err(e) = state::ServerState::init_empty() {
            error!("Fatal: failed to initialise server state: {e}");
            std::process::exit(1);
        }
        info!("NexusIntelliCore MCP server started (waiting for project registration via MCP)");
    } else {
        if let Err(e) = state::ServerState::init(&roots[0]) {
            error!("Fatal: failed to initialise server state: {e}");
            std::process::exit(1);
        }
        let state = state::ServerState::get();
        for additional in &roots[1..] {
            if let Err(e) = state.register_project(additional, None) {
                warn!(root = %additional, "Failed to register initial project root: {e}");
            }
        }
    }

    let state = state::ServerState::get();
    let registered = state.list_projects();
    info!(
        project_count = registered.len(),
        "NexusIntelliCore MCP server initialised with projects"
    );

    // Start file watchers for all registered initial projects
    let mut _file_watchers = Vec::new();
    for (id, _) in registered {
        if let Ok(proj) = state.get_project(Some(&id)) {
            if let Some(w) = watcher::FileWatcher::start(proj) {
                _file_watchers.push(w);
            }
        }
    }

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let mut transport = transport::McpTransport::new(stdin, stdout);

    loop {
        let read_result = transport.read_message().await;

        match read_result {
            Ok(None) => {
                info!("EOF received, shutting down");
                break;
            }
            Ok(Some(msg)) => {
                let response = match serde_json::from_value::<JsonRpcRequest>(msg) {
                    Ok(req) => {
                        if req.jsonrpc == "2.0" {
                            server::handle_request(req).await
                        } else {
                            warn!(version = %req.jsonrpc, "Unsupported jsonrpc version");
                            Some(JsonRpcResponse::error(
                                req.id.unwrap_or(Value::Null),
                                -32600,
                                format!("Unsupported jsonrpc version: {}", req.jsonrpc),
                            ))
                        }
                    }
                    Err(e) => Some(JsonRpcResponse::error(
                        Value::Null,
                        -32700,
                        format!("Parse error: {e}"),
                    )),
                };

                if let Some(resp) = response {
                    if let Err(e) = transport.write_message(&resp).await {
                        error!("Failed to write response - pipe closed? Error: {e}");
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Read error or framing error: {e}, shutting down");
                break;
            }
        }
    }
}
