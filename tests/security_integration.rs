#![allow(clippy::match_same_arms)]
mod common;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn send_single_mcp_request_with_env(
    root: &str,
    request: &str,
    envs: &HashMap<&str, String>,
) -> String {
    let client = envs
        .iter()
        .fold(common::TestMcpClient::new(root), |client, (key, value)| {
            client.with_env(*key, value.as_str())
        });
    client.call(request)
}

fn unique_temp_log_path() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("nexus_audit_{ts}.log"))
}

#[test]
fn unauthenticated_request_is_rejected_when_auth_token_is_configured() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut envs = HashMap::new();
    envs.insert("MCP_AUTH_TOKEN", "test_token_123".to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#,
        &envs,
    );

    assert!(response.contains("Unauthorized"), "Response: {response}");
    assert!(response.contains("-32001") || response.contains("\"code\":-32001"));
}

#[test]
fn initialize_accepts_token_in_auth_token_parameter() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut envs = HashMap::new();
    envs.insert("MCP_AUTH_TOKEN", "test_token_123".to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"auth_token":"test_token_123"}}"#,
        &envs,
    );

    assert!(response.contains("\"result\""), "Response: {response}");
    assert!(!response.contains("Unauthorized"), "Response: {response}");
}

#[test]
fn initialize_accepts_token_in_meta_field() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut envs = HashMap::new();
    envs.insert("MCP_AUTH_TOKEN", "test_token_123".to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"_meta":{"auth_token":"test_token_123"}}}"#,
        &envs,
    );

    assert!(response.contains("\"result\""), "Response: {response}");
    assert!(!response.contains("Unauthorized"), "Response: {response}");
}

#[test]
fn initialize_rejects_invalid_token() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut envs = HashMap::new();
    envs.insert("MCP_AUTH_TOKEN", "test_token_123".to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"auth_token":"wrong"}}"#,
        &envs,
    );

    assert!(response.contains("Unauthorized"), "Response: {response}");
}

#[test]
fn allowed_tools_restricts_tools_list_output() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut envs = HashMap::new();
    envs.insert("MCP_ALLOWED_TOOLS", "get_module_summary".to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        &envs,
    );

    assert!(
        response.contains("get_module_summary"),
        "Response: {response}"
    );
    assert!(
        !response.contains("get_project_structure"),
        "Response: {response}"
    );
}

#[test]
fn blocked_tool_call_returns_custom_access_denied_error() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut envs = HashMap::new();
    envs.insert("MCP_ALLOWED_TOOLS", "get_module_summary".to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_project_structure","arguments":{}}}"#,
        &envs,
    );

    assert!(response.contains("Access denied"), "Response: {response}");
    assert!(response.contains("-32003") || response.contains("\"code\":-32003"));
}

#[test]
fn audit_log_file_is_written_when_configured() {
    let root = env!("CARGO_MANIFEST_DIR");
    let log_path = unique_temp_log_path();

    let mut envs = HashMap::new();
    envs.insert("MCP_AUDIT_LOG_PATH", log_path.to_string_lossy().to_string());

    let response = send_single_mcp_request_with_env(
        root,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}"#,
        &envs,
    );

    assert!(response.contains("\"result\""), "Response: {response}");

    let content = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!content.is_empty(), "Audit log should not be empty");
    assert!(
        content.contains("tools_list"),
        "Audit log content: {content}"
    );

    let _ = fs::remove_file(log_path);
}
