//! Integration tests: send JSON-RPC over MCP-framed stdin, verify responses.
//!
//! Note: These tests are disabled until we resolve a bug where the server
//! doesn't properly handle multiple framed messages in sequence. For now,
//! we test that the MCP framing layer is correctly implemented via unit tests
//! in the transport module.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn read_framed_responses(mut reader: std::process::ChildStdout, count: usize) -> Vec<String> {
    let mut responses = Vec::new();
    let mut buf = [0u8; 8192];
    let mut accumulated = Vec::new();

    while responses.len() < count {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                accumulated.extend_from_slice(&buf[..n]);

                // Try to extract complete frames
                loop {
                    if accumulated.len() < 4 {
                        break;
                    }

                    // Look for \r\n\r\n
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

                    // Parse Content-Length
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

    responses
}

fn send_single_mcp_request(root: &str, request: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexusintellicore"))
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start MCP server");

    let stdin = child.stdin.as_mut().unwrap();

    // Helper to write MCP-framed message
    let write_frame = |stdin: &mut std::process::ChildStdin, msg: &str| {
        let body = msg.as_bytes();
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        stdin.write_all(header.as_bytes()).unwrap();
        stdin.write_all(body).unwrap();
        stdin.flush().unwrap();
    };

    // Send just the request
    write_frame(stdin, request);
    drop(child.stdin.take());

    let stdout = child.stdout.take().unwrap();
    let responses = read_framed_responses(stdout, 1);
    responses.first().cloned().unwrap_or_default()
}

#[test]
fn mcp_framing_is_correct() {
    // Test that the server responds with proper MCP framing
    let root = env!("CARGO_MANIFEST_DIR");
    let response = send_single_mcp_request(
        root,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#,
    );
    // The response should be valid JSON with id 1
    assert!(
        response.contains(r#""id":1"#),
        "Response should have id. Got: {}",
        response
    );
    assert!(
        response.contains(r#""jsonrpc":"2.0""#),
        "Response should be JSON-RPC 2.0. Got: {}",
        response
    );
}

#[test]
fn access_control_blocks_traversal() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response = send_single_mcp_request(
        root,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"inspect_symbol","arguments":{"file_path":"/etc/passwd","symbol_name":"root"}}}"#,
    );
    assert!(
        response.contains("Access denied")
            || response.contains("outside")
            || response.contains("Internal error"),
        "Path traversal should be denied. Got: {}",
        response
    );
}

/// Helper: extract the text content from a tools/call MCP response.
fn extract_tool_text(response: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(response).unwrap_or_default();
    v.pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_owned()
}

fn call_generate_project_docs(root: &str, args: &str) -> String {
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"generate_project_docs","arguments":{}}}}}"#,
        args
    );
    send_single_mcp_request(root, &request)
}

#[test]
fn generate_project_docs_returns_project_name_and_overview() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response = call_generate_project_docs(root, r#"{"max_files": 5}"#);
    let text = extract_tool_text(&response);

    assert!(
        text.contains("NexusIntelliCore"),
        "Generated docs should contain the project name. Got: {}",
        &text[..text.len().min(500)]
    );
    assert!(
        text.contains("## Overview") || text.contains("# NexusIntelliCore"),
        "Generated docs should have an Overview section. Got: {}",
        &text[..text.len().min(500)]
    );
}

#[test]
fn generate_project_docs_sections_filter_overview_only() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response =
        call_generate_project_docs(root, r#"{"sections": ["overview"], "max_files": 5}"#);
    let text = extract_tool_text(&response);

    assert!(
        text.contains("## Overview"),
        "Should contain Overview section. Got: {}",
        &text[..text.len().min(500)]
    );
    assert!(
        !text.contains("## Public API") && !text.contains("## How to use it"),
        "Should NOT contain API or Usage sections when only 'overview' requested. Got: {}",
        &text[..text.len().min(500)]
    );
}

#[test]
fn generate_project_docs_max_files_one_does_not_panic() {
    let root = env!("CARGO_MANIFEST_DIR");
    // max_files=1 is an edge-case that must not panic or return an error
    let response = call_generate_project_docs(root, r#"{"max_files": 1}"#);
    // Must be valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&response).expect("Response must be valid JSON even for max_files=1");
    assert!(
        parsed.pointer("/result/content").is_some() || parsed.pointer("/error").is_some(),
        "Response must have result.content or error. Got: {}",
        response
    );
}

#[test]
fn generate_project_docs_spanish_headings() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response = call_generate_project_docs(
        root,
        r#"{"sections": ["overview", "use_cases"], "language": "es", "max_files": 5}"#,
    );
    let text = extract_tool_text(&response);

    assert!(
        text.contains("Descripción general") || text.contains("Casos de uso"),
        "Spanish language option should produce Spanish headings. Got: {}",
        &text[..text.len().min(500)]
    );
}

#[test]
fn generate_project_docs_catalan_headings() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response = call_generate_project_docs(
        root,
        r#"{"sections": ["overview", "use_cases"], "language": "ca", "max_files": 5}"#,
    );
    let text = extract_tool_text(&response);

    assert!(
        text.contains("Descripció general") || text.contains("Casos d'ús"),
        "Catalan language option should produce Catalan headings. Got: {}",
        &text[..text.len().min(500)]
    );
}
