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
        error!("Fatal: failed to initialise server state: {e}");
        std::process::exit(1);
    }

    let state = state::ServerState::get();
    info!(root = %state.root().display(), "NexusIntelliCore MCP server started");

    // Start the file watcher for automatic cache invalidation.
    // The result is intentionally kept alive for the duration of the process.
    let _file_watcher = watcher::FileWatcher::start(state.root());

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let mut transport = transport::McpTransport::new(stdin, stdout);

    loop {
        /*/
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
        */
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
