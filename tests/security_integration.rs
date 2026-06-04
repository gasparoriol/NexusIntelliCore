use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn read_single_framed_response(mut reader: std::process::ChildStdout) -> String {
    let mut responses = Vec::new();
    let mut buf = [0u8; 8192];
    let mut accumulated = Vec::new();

    while responses.is_empty() {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                accumulated.extend_from_slice(&buf[..n]);

                loop {
                    if accumulated.len() < 4 {
                        break;
                    }

                    let mut found_end = false;
                    let mut header_end = 0;
                    for i in 0..accumulated.len() - 3 {
                        if accumulated[i] == b'\r'
                            && accumulated[i + 1] == b'\n'
                            && accumulated[i + 2] == b'\r'
                            && accumulated[i + 3] == b'\n'
                        {
                            found_end = true;
                            header_end = i;
                            break;
                        }
                    }

                    if !found_end {
                        break;
                    }

                    let header_str = String::from_utf8_lossy(&accumulated[..header_end]);
                    let mut content_length = 0;
                    for line in header_str.lines() {
                        if let Some(rest) = line.strip_prefix("Content-Length: ") {
                            if let Ok(n) = rest.parse::<usize>() {
                                content_length = n;
                                break;
                            }
                        }
                    }

                    let body_start = header_end + 4;
                    let body_end = body_start + content_length;

                    if accumulated.len() >= body_end {
                        let body = String::from_utf8_lossy(&accumulated[body_start..body_end]);
                        responses.push(body.to_string());
                        accumulated.drain(..body_end);
                    } else {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    responses.first().cloned().unwrap_or_default()
}

fn send_single_mcp_request_with_env(
    root: &str,
    request: &str,
    envs: &HashMap<&str, String>,
) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nexusintellicore"));
    cmd.arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("MCP_SECURITY_CONFIG_PATH")
        .env_remove("MCP_AUTH_TOKEN")
        .env_remove("MCP_ALLOWED_TOOLS")
        .env_remove("MCP_AUDIT_LOG_PATH");

    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("Failed to start MCP server");

    let stdin = child.stdin.as_mut().unwrap();
    let body = request.as_bytes();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin.write_all(header.as_bytes()).unwrap();
    stdin.write_all(body).unwrap();
    stdin.flush().unwrap();
    drop(child.stdin.take());

    let stdout = child.stdout.take().unwrap();
    read_single_framed_response(stdout)
}

fn unique_temp_log_path() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("nexus_audit_{}.log", ts))
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

    assert!(response.contains("Unauthorized"), "Response: {}", response);
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

    assert!(response.contains("\"result\""), "Response: {}", response);
    assert!(!response.contains("Unauthorized"), "Response: {}", response);
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

    assert!(response.contains("\"result\""), "Response: {}", response);
    assert!(!response.contains("Unauthorized"), "Response: {}", response);
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

    assert!(response.contains("Unauthorized"), "Response: {}", response);
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
        "Response: {}",
        response
    );
    assert!(
        !response.contains("get_project_structure"),
        "Response: {}",
        response
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

    assert!(response.contains("Access denied"), "Response: {}", response);
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

    assert!(response.contains("\"result\""), "Response: {}", response);

    let content = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!content.is_empty(), "Audit log should not be empty");
    assert!(
        content.contains("tools_list"),
        "Audit log content: {}",
        content
    );

    let _ = fs::remove_file(log_path);
}
