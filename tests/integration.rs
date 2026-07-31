#![allow(clippy::match_same_arms, clippy::needless_pass_by_value)]

mod common;

use common::TestMcpClient;

fn send_single_mcp_request(root: &str, request: &str) -> String {
    TestMcpClient::new(root).call(request)
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
        "Response should have id. Got: {response}"
    );
    assert!(
        response.contains(r#""jsonrpc":"2.0""#),
        "Response should be JSON-RPC 2.0. Got: {response}"
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
        "Path traversal should be denied. Got: {response}"
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
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"generate_project_docs","arguments":{args}}}}}"#
    );
    send_single_mcp_request(root, &request)
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
        "Response must have result.content or error. Got: {response}"
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

#[test]
fn generate_project_docs_pagination_returns_offset_hint() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response = call_tool(
        root,
        "generate_project_docs",
        serde_json::json!({
            "max_files": 1,
            "file_offset": 0
        }),
    );
    let text = extract_tool_text(&response);

    if text.contains("of") {
        assert!(
            text.contains("file_offset"),
            "Pagination response should include file_offset hint. Got: {}",
            &text[..text.len().min(500)]
        );
    }
}

#[test]
fn inspect_symbol_simple_name_returns_ambiguous_payload_when_multiple_matches() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/AmbiguousSymbols.java");
    let response = call_tool(
        root,
        "inspect_symbol",
        serde_json::json!({
            "file_path": fixture,
            "symbol_name": "onCommandSuccess",
            "match_mode": "simple"
        }),
    );

    let text = extract_tool_text(&response);
    let payload: serde_json::Value =
        serde_json::from_str(&text).expect("Ambiguous response should be JSON");

    assert_eq!(payload["status"], "ambiguous", "Payload: {payload}");
    let candidates = payload["candidates"]
        .as_array()
        .expect("candidates must be an array");
    assert!(candidates.len() >= 2, "Payload: {payload}");
    for c in candidates {
        assert!(c.get("qualified_name").is_some(), "Candidate: {c}");
        assert!(c.get("signature").is_some(), "Candidate: {c}");
        assert!(c.get("start_line").is_some(), "Candidate: {c}");
        assert!(c.get("end_line").is_some(), "Candidate: {c}");
    }
}

#[test]
fn inspect_symbol_qualified_mode_returns_exact_inner_method() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/AmbiguousSymbols.java");
    let response = call_tool(
        root,
        "inspect_symbol",
        serde_json::json!({
            "file_path": fixture,
            "symbol_name": "OuterHandler.AuthListener.onCommandSuccess",
            "match_mode": "qualified"
        }),
    );

    let text = extract_tool_text(&response);
    assert!(
        text.contains("inner:"),
        "Qualified match should return inner method body. Got: {text}"
    );
}

#[test]
fn inspect_symbol_signature_hint_disambiguates_overloads() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/AmbiguousSymbols.java");
    let response = call_tool(
        root,
        "inspect_symbol",
        serde_json::json!({
            "file_path": fixture,
            "symbol_name": "onCommandSuccess",
            "match_mode": "simple",
            "signature_hint": "int code"
        }),
    );

    let text = extract_tool_text(&response);
    assert!(
        text.contains("outer-2:"),
        "signature_hint should select int overload. Got: {text}"
    );
}

#[test]
fn inspect_symbol_return_all_matches_returns_json_with_sanitized_sources() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/AmbiguousSymbols.java");
    let response = call_tool(
        root,
        "inspect_symbol",
        serde_json::json!({
            "file_path": fixture,
            "symbol_name": "onCommandSuccess",
            "match_mode": "simple",
            "return_all_matches": true
        }),
    );

    let text = extract_tool_text(&response);
    let payload: serde_json::Value =
        serde_json::from_str(&text).expect("return_all_matches response should be JSON");

    assert_eq!(payload["status"], "ok", "Payload: {payload}");
    let matches = payload["matches"]
        .as_array()
        .expect("matches must be an array");
    assert!(matches.len() >= 2, "Payload: {payload}");
    for m in matches {
        assert!(m.get("qualified_name").is_some(), "Match: {m}");
        assert!(m.get("signature").is_some(), "Match: {m}");
        assert!(m.get("source").is_some(), "Match: {m}");
    }
}

#[test]
fn tool_caching_and_invalidation() {
    let root = env!("CARGO_MANIFEST_DIR");
    let arguments = serde_json::json!({
        "file_path": format!("{}/src/state.rs", root)
    });

    // First call: should compute
    let res1 = call_tool(root, "get_file_outline", arguments.clone());

    // Second call: should hit cache
    let res2 = call_tool(root, "get_file_outline", arguments.clone());

    assert_eq!(res1, res2, "Cached response should match original response");

    // Call refresh_index (which should invalidate the tool cache)
    let refresh_res = call_tool(root, "refresh_index", serde_json::json!({}));
    assert!(
        refresh_res.contains("result"),
        "refresh_index should succeed"
    );

    // Third call: should recompute (but return the same result)
    let res3 = call_tool(root, "get_file_outline", arguments);
    assert_eq!(
        res1, res3,
        "Response after refresh_index should still match"
    );
}

#[test]
fn get_server_stats_is_always_available_and_returns_stats() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response = call_tool(root, "get_server_stats", serde_json::json!({}));
    let text = extract_tool_text(&response);

    assert!(
        text.contains("Server Statistics"),
        "Stats response should contain heading. Got: {text}"
    );
    assert!(
        text.contains("Uptime"),
        "Stats response should contain Uptime. Got: {text}"
    );
    assert!(
        text.contains("AST Cache"),
        "Stats response should contain AST Cache. Got: {text}"
    );
    assert!(
        text.contains("Tool Cache"),
        "Stats response should contain Tool Cache. Got: {text}"
    );
    assert!(
        text.contains("Tool Invocations"),
        "Stats response should contain Tool Invocations. Got: {text}"
    );
}
