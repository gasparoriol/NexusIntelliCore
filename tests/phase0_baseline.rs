// Phase 0 baseline: frozen snapshot tests.
// These tests assert exact counts and structural contracts so any future change is immediately visible.
// DO NOT relax assertions here without updating the ADR and recording a before/after.

mod common;
use common::TestMcpClient;

fn call_tool(root: &str, name: &str, args: serde_json::Value) -> String {
    TestMcpClient::new(root).call_tool(name, args)
}

fn extract_text(response: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(response).unwrap_or_default();
    v.pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_owned()
}

/// Framing baseline: ping must echo id=1 and declare JSON-RPC 2.0.
#[test]
fn framing_ping_roundtrip_is_stable() {
    let root = env!("CARGO_MANIFEST_DIR");
    let response =
        TestMcpClient::new(root).call(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#);
    assert!(
        response.contains(r#""id":1"#),
        "framing baseline: id must be echoed; got: {response}"
    );
    assert!(
        response.contains(r#""jsonrpc":"2.0""#),
        "framing baseline: version must be 2.0; got: {response}"
    );
}

/// Audit baseline: audit_sample.rs fixture contains exactly 2 unsafe blocks.
#[test]
fn audit_fixture_unsafe_block_count_is_two() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/audit_sample.rs");
    let response = call_tool(
        root,
        "query_ast",
        serde_json::json!({
            "file_path": fixture,
            "query": "(unsafe_block) @unsafe"
        }),
    );
    let text = extract_text(&response);
    let payload: serde_json::Value =
        serde_json::from_str(&text).expect("query_ast must return a JSON payload");
    let count = payload["capture_count"].as_u64().unwrap_or(0);
    assert_eq!(
        count, 2,
        "audit baseline: expected 2 unsafe blocks in audit_sample.rs; got {count}"
    );
}

/// Privacy baseline: credential strings in privacy_sample.py must be redacted by the gateway.
#[test]
fn privacy_fixture_credential_strings_are_redacted() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/privacy_sample.py");
    let response = call_tool(
        root,
        "query_ast",
        serde_json::json!({
            "file_path": fixture,
            "query": "(string) @s"
        }),
    );
    let text = extract_text(&response);
    assert!(
        !text.contains("sk-abcdefghijklmnopqrstuvwxyz123456"),
        "privacy baseline: API key must be redacted in query_ast output"
    );
    assert!(
        !text.contains("secret123"),
        "privacy baseline: DB password must be redacted in query_ast output"
    );
    assert!(
        !text.contains("db.internal"),
        "privacy baseline: internal hostname must be redacted in query_ast output"
    );
    let payload: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let total_redactions: usize = payload["captures"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|c| c["redactions"].as_array())
        .map(|r| r.len())
        .sum();
    assert!(
        total_redactions > 0,
        "privacy baseline: the privacy gateway must record at least one redaction"
    );
}

/// Graph baseline: get_dependencies_graph returns structured JSON with a 'nodes' key.
#[test]
fn graph_endpoint_returns_structured_json() {
    let root = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{root}/tests/fixtures/audit_sample.rs");
    let response = call_tool(
        root,
        "get_dependencies_graph",
        serde_json::json!({ "file_path": fixture, "depth": 1 }),
    );
    let text = extract_text(&response);
    assert!(
        text.contains("\"nodes\""),
        "graph baseline: response must include a 'nodes' key; got: {}",
        &text[..text.len().min(300)]
    );
}
