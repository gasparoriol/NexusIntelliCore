#[path = "../src/privacy_gateway.rs"]
mod privacy_gateway;
#[path = "../src/sanitizer.rs"]
mod sanitizer;

mod common;

use privacy_gateway::{
    sanitize_dependency_graph, sanitize_function_source, sanitize_output_text, PrivacyPolicy,
};
use serde_json::json;

#[cfg(test)]
mod fixtures {
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

#[test]
fn refresh_index_applies_new_mcpignore_restrictions() {
    let root = common::make_temp_workspace("mcpignore_refresh");
    let hidden_file = root.join("src/hidden.rs");
    let client = common::TestMcpClient::new(root.to_string_lossy().to_string());

    std::fs::create_dir_all(hidden_file.parent().expect("parent should exist"))
        .expect("src dir should exist");
    std::fs::write(&hidden_file, "pub fn hidden() {}\n").expect("fixture file should be written");

    let before = client.call_tool(
        "get_file_outline",
        serde_json::json!({ "file_path": hidden_file.to_string_lossy() }),
    );
    assert!(
        !before.contains("Access denied by .mcpignore policy"),
        "file should be accessible before .mcpignore is added: {before}"
    );

    std::fs::write(root.join(".mcpignore"), "src/hidden.rs\n")
        .expect(".mcpignore should be written");

    let refresh = client.call_tool("refresh_index", serde_json::json!({}));
    assert!(
        refresh.contains("Index refreshed successfully") || refresh.contains("result"),
        "refresh_index should succeed: {refresh}"
    );

    let after = client.call_tool(
        "get_file_outline",
        serde_json::json!({ "file_path": hidden_file.to_string_lossy() }),
    );
    assert!(
        after.contains("Access denied by .mcpignore policy"),
        "file should become restricted after refresh_index: {after}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
