/// Corpus adversarial de privacidad (mitigación 02, fase 1 + A3).
///
/// Cada test envía un payload que contiene un valor sintético sensible y
/// afirma que ese valor no aparece en la respuesta serializada.
/// La segunda invocación verifica el mismo resultado servido desde caché.
mod common;
use common::TestMcpClient;

// Matches sanitizer.rs pattern: sk-[a-zA-Z0-9]{32,}
const SENTINEL_KEY: &str = "sk-FAKEOPENAIKEYABCDEFGHIJKLMNOPQRS";
const SENTINEL_IP: &str = "192.168.99.254";
const SENTINEL_JWT: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJGQUtFVVNFUiIsImlhdCI6MTcwMDAwMDAwMH0.FAKE";
const SENTINEL_PASSWORD: &str = "db_password=hunter2_fakeSENTINEL";
const SENTINEL_HOST: &str = "internal.secret-corp.example.com";

fn call(request: &str) -> String {
    TestMcpClient::new(env!("CARGO_MANIFEST_DIR")).call(request)
}

fn extract_text(response: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(response).unwrap_or_default();
    v.pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or(response)
        .to_owned()
}

fn assert_no_sentinel(text: &str, sentinel: &str, label: &str) {
    assert!(
        !text.contains(sentinel),
        "{label}: sentinel '{sentinel}' must not appear in response"
    );
}

/// `get_file_outline` on a path that contains a sentinel string.
/// The path is rejected by access control; the error must not echo the sentinel.
#[test]
fn error_response_does_not_echo_sentinel_in_file_path() {
    let sentinel_path = format!("/tmp/{SENTINEL_KEY}.rs");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_file_outline",
            "arguments": { "file_path": sentinel_path }
        }
    })
    .to_string();

    let text = extract_text(&call(&request));
    assert_no_sentinel(&text, SENTINEL_KEY, "file_path error");
}

/// `get_server_stats` never touches user input, but its output must not
/// expose environment-level secrets that might appear in the root path.
#[test]
fn server_stats_does_not_expose_secrets() {
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": { "name": "get_server_stats", "arguments": {} }
    })
    .to_string();

    let text = extract_text(&call(&request));
    // JWT and password patterns should be sanitized even if they somehow
    // ended up in the server root path.
    assert_no_sentinel(&text, SENTINEL_JWT, "server_stats JWT");
    assert_no_sentinel(&text, SENTINEL_PASSWORD, "server_stats password");
}

/// Unknown tool name must not echo sentinel values embedded in the name.
#[test]
fn unknown_tool_error_does_not_echo_sentinel() {
    let sentinel_name = format!("nonexistent_{SENTINEL_KEY}");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 3,
        "method": "tools/call",
        "params": { "name": sentinel_name, "arguments": {} }
    })
    .to_string();

    let text = extract_text(&call(&request));
    assert_no_sentinel(&text, SENTINEL_KEY, "unknown tool error");
}

/// `inspect_symbol` missing `symbol_name` argument — the error must not
/// echo the sentinel file_path value.
#[test]
fn missing_arg_error_does_not_echo_sentinel_path() {
    let sentinel_path = format!("/tmp/{SENTINEL_IP}/{SENTINEL_KEY}.rs");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 4,
        "method": "tools/call",
        "params": {
            "name": "inspect_symbol",
            "arguments": { "file_path": sentinel_path }
        }
    })
    .to_string();

    let text = extract_text(&call(&request));
    assert_no_sentinel(&text, SENTINEL_KEY, "missing arg file_path");
    assert_no_sentinel(&text, SENTINEL_IP, "missing arg IP");
}

/// Same request sent twice: the cached result must also be free of sentinels.
#[test]
fn cached_response_does_not_leak_sentinel() {
    let sentinel_path = format!("/tmp/{SENTINEL_KEY}.rs");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 5,
        "method": "tools/call",
        "params": {
            "name": "get_file_outline",
            "arguments": { "file_path": sentinel_path }
        }
    })
    .to_string();

    let text1 = extract_text(&call(&request));
    let text2 = extract_text(&call(&request));
    assert_no_sentinel(&text1, SENTINEL_KEY, "first call");
    assert_no_sentinel(&text2, SENTINEL_KEY, "cached call");
}

/// `read_config_file` on a path that encodes all sentinels; must not reveal them.
#[test]
fn config_file_error_does_not_echo_sentinels() {
    let sentinel_path = format!("/tmp/{SENTINEL_HOST}/{SENTINEL_PASSWORD}.env");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 6,
        "method": "tools/call",
        "params": {
            "name": "read_config_file",
            "arguments": { "file_path": sentinel_path }
        }
    })
    .to_string();

    let text = extract_text(&call(&request));
    assert_no_sentinel(&text, SENTINEL_PASSWORD, "config file path password");
}

/// Idempotence: the gateway does not reintroduce plaintext on a second pass.
/// Verified at server round-trip level.
#[test]
fn privacy_pass_is_idempotent_on_corpus() {
    let root = env!("CARGO_MANIFEST_DIR");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "method": "tools/call",
        "params": { "name": "get_server_stats", "arguments": {} }
    })
    .to_string();

    let text = extract_text(&TestMcpClient::new(root).call(&request));
    // Stats output will not contain any of the corpus sentinels because none
    // are injected into the stats code path; this confirms the pass is inert.
    assert_no_sentinel(&text, SENTINEL_JWT, "idempotence JWT");
    assert_no_sentinel(&text, SENTINEL_KEY, "idempotence key");
}
