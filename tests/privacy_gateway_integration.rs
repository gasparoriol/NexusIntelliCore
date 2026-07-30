#[path = "../src/privacy_gateway.rs"]
mod privacy_gateway;
#[path = "../src/sanitizer.rs"]
mod sanitizer;

use privacy_gateway::{
    sanitize_dependency_graph, sanitize_function_source, sanitize_output_text, PrivacyPolicy,
};
use serde_json::json;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod fixtures {
    // Test fixture secrets — these are NOT real credentials, used only for regex pattern validation
    pub const FIXTURE_DB_URI: &str =
        "postgres://user:secret123@db.internal:5432/app?password=hardcoded";
    pub const FIXTURE_OPENAI_KEY: &str = "sk-abcdefghijklmnopqrstuvwxyz123456";
    pub const FIXTURE_INTERNAL_HOST: &str = "db.internal";
    pub const FIXTURE_DB_URI_PY: &str = "postgres://u:p@db.internal:5432/app";
}

#[test]
fn sanitize_output_text_redacts_database_uri_secret_and_internal_hostname() {
    let policy = PrivacyPolicy::default();
    let input = fixtures::FIXTURE_DB_URI;

    let (sanitized, redactions) = sanitize_output_text(input, &policy);

    assert_ne!(sanitized, input);
    assert!(!sanitized.contains("db.internal"));
    assert!(!sanitized.contains("secret123"));
    assert!(!redactions.is_empty());
}

#[test]
fn sanitize_function_source_strips_marked_rust_and_python_functions() {
    let policy = PrivacyPolicy::default();

    let rust_source = format!(
        r#"fn secret_fn() {{
    // @mcp-strip
    let token = "{}";
    println!("{{}}", token);
}}"#,
        fixtures::FIXTURE_OPENAI_KEY
    );
    let (rust_sanitized, _) = sanitize_function_source(&rust_source, "secret_fn", "rust", &policy);
    assert!(rust_sanitized.contains("fn secret_fn()"));
    assert!(!rust_sanitized.contains("abcdefghijklmnopqrstuvwxyz123456"));

    let py_source = format!(
        "def secret_py():  # @mcp-strip\n    return '{}'\n",
        fixtures::FIXTURE_DB_URI_PY
    );
    let (py_sanitized, _) = sanitize_function_source(&py_source, "secret_py", "python", &policy);
    assert!(py_sanitized.contains("def secret_py"));
    assert!(!py_sanitized.contains("db.internal"));
}

#[test]
fn sanitize_dependency_graph_filters_internal_hosts_and_secrets() {
    let policy = PrivacyPolicy::default();
    let graph = json!({
        "nodes": [
            {
                "id": "src/db/internal_client.rs",
                "label": format!("connects to {}", fixtures::FIXTURE_INTERNAL_HOST)
            }
        ],
        "edges": [
            {
                "source": format!("{}/service.rs", fixtures::FIXTURE_INTERNAL_HOST),
                "target": "src/main.rs",
                "label": format!("token={}", fixtures::FIXTURE_OPENAI_KEY)
            }
        ]
    });

    let (sanitized, redactions) = sanitize_dependency_graph(&graph, &policy);
    let out = serde_json::to_string(&sanitized).unwrap_or_default();

    assert!(!out.contains("db.internal"));
    assert!(!out.contains("abcdefghijklmnopqrstuvwxyz123456"));
    assert!(!redactions.is_empty());
}

fn read_framed_responses(mut reader: std::process::ChildStdout, count: usize) -> Vec<String> {
    let mut responses = Vec::new();
    let mut buf = [0u8; 8192];
    let mut accumulated = Vec::new();

    while responses.len() < count {
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

    let stdin = child.stdin.as_mut().expect("stdin should exist");
    let body = request.as_bytes();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin
        .write_all(header.as_bytes())
        .expect("header should be written");
    stdin.write_all(body).expect("body should be written");
    stdin.flush().expect("stdin should flush");
    drop(child.stdin.take());

    let stdout = child.stdout.take().expect("stdout should exist");
    let responses = read_framed_responses(stdout, 1);
    let result = responses.first().cloned().unwrap_or_default();

    let _ = child.wait();
    result
}

fn call_tool(root: &str, tool_name: &str, arguments: serde_json::Value) -> String {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    })
    .to_string();
    send_single_mcp_request(root, &request)
}

fn make_temp_root(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "nexusintellicore_privacy_{test_name}_{}_{}",
        std::process::id(),
        nonce
    ));
    std::fs::create_dir_all(&root).expect("temp root should be created");
    root
}

#[test]
fn refresh_index_applies_new_mcpignore_restrictions() {
    let root = make_temp_root("mcpignore_refresh");
    let hidden_file = root.join("src/hidden.rs");

    std::fs::create_dir_all(hidden_file.parent().expect("parent should exist"))
        .expect("src dir should exist");
    std::fs::write(&hidden_file, "pub fn hidden() {}\n").expect("fixture file should be written");

    let before = call_tool(
        root.to_string_lossy().as_ref(),
        "get_file_outline",
        serde_json::json!({ "file_path": hidden_file.to_string_lossy() }),
    );
    assert!(
        !before.contains("Access denied by .mcpignore policy"),
        "file should be accessible before .mcpignore is added: {before}"
    );

    std::fs::write(root.join(".mcpignore"), "src/hidden.rs\n")
        .expect(".mcpignore should be written");

    let refresh = call_tool(
        root.to_string_lossy().as_ref(),
        "refresh_index",
        serde_json::json!({}),
    );
    assert!(
        refresh.contains("Index refreshed successfully") || refresh.contains("result"),
        "refresh_index should succeed: {refresh}"
    );

    let after = call_tool(
        root.to_string_lossy().as_ref(),
        "get_file_outline",
        serde_json::json!({ "file_path": hidden_file.to_string_lossy() }),
    );
    assert!(
        after.contains("Access denied by .mcpignore policy"),
        "file should become restricted after refresh_index: {after}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
