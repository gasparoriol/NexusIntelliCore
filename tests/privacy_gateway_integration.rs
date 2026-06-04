#[path = "../src/privacy_gateway.rs"]
mod privacy_gateway;
#[path = "../src/sanitizer.rs"]
mod sanitizer;

use privacy_gateway::{
    sanitize_dependency_graph, sanitize_function_source, sanitize_output_text, PrivacyPolicy,
};
use serde_json::json;

#[test]
fn sanitize_output_text_redacts_database_uri_secret_and_internal_hostname() {
    let policy = PrivacyPolicy::default();
    let input = "postgres://user:secret123@db.internal:5432/app?password=hardcoded";

    let (sanitized, redactions) = sanitize_output_text(input, &policy);

    assert_ne!(sanitized, input);
    assert!(!sanitized.contains("db.internal"));
    assert!(!sanitized.contains("secret123"));
    assert!(!redactions.is_empty());
}

#[test]
fn sanitize_function_source_strips_marked_rust_and_python_functions() {
    let policy = PrivacyPolicy::default();

    let rust_source = r#"fn secret_fn() {
    // @mcp-strip
    let token = \"sk-abcdefghijklmnopqrstuvwxyz123456\";
    println!(\"{}\", token);
}"#;
    let (rust_sanitized, _) = sanitize_function_source(rust_source, "secret_fn", "rust", &policy);
    assert!(rust_sanitized.contains("fn secret_fn()"));
    assert!(!rust_sanitized.contains("abcdefghijklmnopqrstuvwxyz123456"));

    let py_source =
        "def secret_py():  # @mcp-strip\n    return 'postgres://u:p@db.internal:5432/app'\n";
    let (py_sanitized, _) = sanitize_function_source(py_source, "secret_py", "python", &policy);
    assert!(py_sanitized.contains("def secret_py"));
    assert!(!py_sanitized.contains("db.internal"));
}

#[test]
fn sanitize_dependency_graph_filters_internal_hosts_and_secrets() {
    let policy = PrivacyPolicy::default();
    let graph = json!({
        "nodes": [
            { "id": "src/db/internal_client.rs", "label": "connects to db.internal" }
        ],
        "edges": [
            {
                "source": "db.internal/service.rs",
                "target": "src/main.rs",
                "label": "token=sk-abcdefghijklmnopqrstuvwxyz123456"
            }
        ]
    });

    let (sanitized, redactions) = sanitize_dependency_graph(&graph, &policy);
    let out = serde_json::to_string(&sanitized).unwrap_or_default();

    assert!(!out.contains("db.internal"));
    assert!(!out.contains("abcdefghijklmnopqrstuvwxyz123456"));
    assert!(!redactions.is_empty());
}
