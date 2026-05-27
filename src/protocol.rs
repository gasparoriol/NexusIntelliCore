use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC 2.0 request (may also be a notification when `id` is absent).
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }
}

/// Build a MCP text content item.
pub fn text_content(text: impl Into<String>) -> Value {
    serde_json::json!({ "type": "text", "text": text.into() })
}

/// Wrap content items into a tool result object.
pub fn tool_response(content: Vec<Value>) -> Value {
    serde_json::json!({ "content": content })
}

/// Build a tool result that marks an error.
pub fn error_response(message: impl Into<String>) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": message.into() }],
        "isError": true
    })
}
