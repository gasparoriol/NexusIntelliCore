#[path = "../src/privacy_gateway.rs"]
mod privacy_gateway;
#[path = "../src/sanitizer.rs"]
mod sanitizer;

use privacy_gateway::{
    sanitize_dependency_graph, sanitize_function_source, sanitize_output_text, PrivacyPolicy,
};
use serde_json::json;

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
