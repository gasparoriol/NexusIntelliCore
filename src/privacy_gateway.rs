/// Privacy Gateway — Unified sanitization layer for all tool outputs
///
/// This module centralizes all privacy and security filtering that runs on tool outputs.
/// Every piece of data returned to the LLM client passes through here.
///
/// Responsibilities:
/// - Redact secret patterns (API keys, database URIs, private IPs, etc.)
/// - Sanitize import paths and module names
/// - Strip sensitive comments and flagged function bodies
/// - Apply @mcp-strip filtering
/// - Never expose actual secret values, only types + line numbers
use serde_json::{json, Value};

use crate::sanitizer;

/// Policy for what to do when a secret or sensitive pattern is found
#[derive(Clone, Debug)]
pub struct PrivacyPolicy {
    /// If true, omit restricted content entirely
    #[allow(dead_code)]
    pub omit_restricted: bool,
    /// If true, redact secret VALUES but show [REDACTED: TYPE]
    pub redact_secrets: bool,
    /// If true, apply @mcp-strip filtering
    pub apply_strip_marks: bool,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self {
            omit_restricted: false,
            redact_secrets: true,
            apply_strip_marks: true,
        }
    }
}

/// Sanitize text that may contain secrets, sensitive hostnames, or comments.
/// Returns both the sanitized text and a list of redaction actions applied.
pub fn sanitize_output_text(text: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    if !policy.redact_secrets {
        return (text.to_string(), Vec::new());
    }

    let (sanitized, redactions) = sanitizer::sanitize_text(text);

    let redaction_summary: Vec<String> = redactions.iter().map(|r| r.to_string()).collect();

    (sanitized, redaction_summary)
}

/// Sanitize import strings (may contain hostnames or module names)
pub fn sanitize_import(import_text: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    if !policy.redact_secrets {
        return (import_text.to_string(), Vec::new());
    }

    let (sanitized, redactions) = sanitizer::sanitize_text(import_text);
    let redaction_summary: Vec<String> = redactions.iter().map(|r| r.to_string()).collect();

    (sanitized, redaction_summary)
}

/// Sanitize a file outline (imports list, function signatures, class names)
pub fn sanitize_file_outline(outline: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    sanitize_output_text(outline, policy)
}

/// Sanitize a doc comment (/// lines, /** */ blocks, Python docstrings).
///
/// Applies only the secret-redaction pass — `strip_sensitive_comments` is
/// intentionally skipped here because doc comments are, by definition, meant
/// to be read; stripping them on keyword matches would destroy the output.
/// Secrets in doc comments (e.g. example tokens) are still redacted.
pub fn sanitize_doc_comment(comment: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    if !policy.redact_secrets {
        return (comment.to_string(), Vec::new());
    }
    let (sanitized, redactions) = sanitizer::sanitize_text(comment);
    let redaction_summary: Vec<String> = redactions.iter().map(|r| r.to_string()).collect();
    (sanitized, redaction_summary)
}

/// Sanitize function/method source code.
/// - Strips body when `@mcp-strip` is present (language-aware)
/// - Removes sensitive comments
/// - Redacts secrets
pub fn sanitize_function_source(
    source: &str,
    _signature: &str,
    language: &str,
    policy: &PrivacyPolicy,
) -> (String, Vec<String>) {
    let mut sanitized = source.to_string();
    let mut redactions = Vec::new();

    // Step 1: Strip body only when the function is annotated with @mcp-strip.
    // The check is language-aware: Rust/JS/TS use `// @mcp-strip`,
    // Python uses `# @mcp-strip`. Stripping unconditionally would hide all
    // function bodies, defeating the purpose of inspect_symbol.
    if policy.apply_strip_marks && sanitizer::has_mcp_strip(&sanitized) {
        sanitized = sanitizer::strip_function_body(&sanitized, language);
    }

    // Step 2: Remove sensitive comments
    sanitized = sanitizer::strip_sensitive_comments(&sanitized);

    // Step 3: Redact secrets
    let (final_sanitized, secret_redactions) = sanitizer::sanitize_text(&sanitized);
    redactions.extend(secret_redactions.iter().map(|r| r.to_string()));

    (final_sanitized, redactions)
}

/// Sanitize a dependency graph report.
/// Remove hostnames and normalized module names that may be sensitive.
pub fn sanitize_dependency_graph(
    graph_json: &Value,
    policy: &PrivacyPolicy,
) -> (Value, Vec<String>) {
    if !policy.redact_secrets {
        return (graph_json.clone(), Vec::new());
    }

    let mut sanitized = graph_json.clone();
    let mut redactions = Vec::new();

    // Sanitize node IDs (file paths, hostnames)
    if let Some(nodes) = sanitized.get_mut("nodes") {
        if let Some(arr) = nodes.as_array_mut() {
            for node in arr {
                if let Some(id) = node.get_mut("id") {
                    if let Some(id_str) = id.as_str() {
                        let (clean_id, node_redactions) = sanitize_output_text(id_str, policy);
                        *id = Value::String(clean_id);
                        redactions.extend(node_redactions);
                    }
                }
                if let Some(label) = node.get_mut("label") {
                    if let Some(label_str) = label.as_str() {
                        let (clean_label, label_redactions) =
                            sanitize_output_text(label_str, policy);
                        *label = Value::String(clean_label);
                        redactions.extend(label_redactions);
                    }
                }
            }
        }
    }

    // Sanitize edge endpoints and optional label.
    // "source" and "target" hold file paths that may contain sensitive hostnames.
    if let Some(edges) = sanitized.get_mut("edges") {
        if let Some(arr) = edges.as_array_mut() {
            for edge in arr {
                for key in &["source", "target", "label"] {
                    if let Some(val) = edge.get_mut(*key) {
                        if let Some(s) = val.as_str() {
                            let (clean, edge_redactions) = sanitize_output_text(s, policy);
                            *val = Value::String(clean);
                            redactions.extend(edge_redactions);
                        }
                    }
                }
            }
        }
    }

    (sanitized, redactions)
}

/// Sanitize security audit report.
/// Keep types and line numbers, but NEVER expose actual secret values.
///
/// The audit scanner reports secret *types* and *locations*, not values — but
/// a bug in evidence formatting could accidentally include a raw value. This
/// second-layer pass ensures nothing slips through.
pub fn sanitize_security_report(report: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    sanitize_output_text(report, policy)
}

/// Get all defined secret patterns (for reference/documentation)
#[allow(dead_code)]
pub fn get_sanitization_rules() -> Value {
    json!({
        "secret_patterns": [
            "OpenAI API keys (sk-*)",
            "AWS access keys (AKIA*)",
            "JWT tokens",
            "Database URIs (postgres://, mysql://, mongodb://, redis://)",
            "Private IP addresses (10.x, 172.16-31.x, 192.168.x)",
            "GitHub tokens (gh_*, ghp_*, etc.)",
            "Generic secrets (password=, api_key=, secret=)",
            "PEM private keys (-----BEGIN)",
            "Internal hostnames (*.internal, *.corp, *.local)"
        ],
        "handled_comment_types": [
            "confidential",
            "classified",
            "SSN",
            "PII"
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_import_with_internal_hostname() {
        let import = "import UserService from 'db.internal/service';";
        let policy = PrivacyPolicy::default();
        let (sanitized, redactions) = sanitize_import(import, &policy);
        assert!(
            !sanitized.contains("db.internal"),
            "Internal hostname should be redacted. Got: {}",
            sanitized
        );
        assert!(!redactions.is_empty());
    }

    #[test]
    fn sanitize_import_no_redaction_when_disabled() {
        let import = "import UserService from 'db.internal/service';";
        let policy = PrivacyPolicy {
            redact_secrets: false,
            ..Default::default()
        };
        let (sanitized, redactions) = sanitize_import(import, &policy);
        assert_eq!(sanitized, import);
        assert!(redactions.is_empty());
    }

    #[test]
    fn sanitize_outline_text() {
        let outline = "## Imports\n  import api_key from 'sk-abcdefghijklmnopqrstuvwxyz123456';";
        let policy = PrivacyPolicy::default();
        let (sanitized, redactions) = sanitize_file_outline(outline, &policy);
        assert!(
            !sanitized.contains("sk-abcdef"),
            "API key should be redacted. Got: {}",
            sanitized
        );
        assert!(!redactions.is_empty());
    }

    #[test]
    fn sanitize_function_source_strips_marked_rust() {
        let source = "fn secret() {\n  // @mcp-strip\n  println!(\"password: admin123\");\n}";
        let policy = PrivacyPolicy::default();
        let (sanitized, _redactions) = sanitize_function_source(source, "secret", "rust", &policy);
        assert!(
            !sanitized.contains("admin123") || sanitized.contains("[REDACTED"),
            "Body should be stripped. Got: {}",
            sanitized
        );
    }

    #[test]
    fn sanitize_function_source_no_strip_without_annotation() {
        // A function without @mcp-strip must NOT have its body hidden.
        // inspect_symbol is supposed to show the full source.
        let source = "fn public_helper() {\n    let x = compute();\n    x + 1\n}";
        let policy = PrivacyPolicy::default();
        let (sanitized, _) = sanitize_function_source(source, "public_helper", "rust", &policy);
        assert!(
            sanitized.contains("compute"),
            "Body of unannotated function must not be stripped. Got: {}",
            sanitized
        );
    }

    #[test]
    fn sanitize_function_source_strips_marked_python() {
        let source = "def secret():  # @mcp-strip\n    return os.environ['DB_PASS']\n";
        let policy = PrivacyPolicy::default();
        let (sanitized, _) = sanitize_function_source(source, "secret", "python", &policy);
        assert!(
            sanitized.contains("def secret"),
            "def line must be preserved. Got: {}",
            sanitized
        );
        assert!(
            !sanitized.contains("DB_PASS"),
            "Body must be stripped for Python @mcp-strip. Got: {}",
            sanitized
        );
    }

    #[test]
    fn test_sanitize_dependency_graph() {
        let graph = json!({
            "nodes": [
                { "id": "src/db/conn.rs", "label": "Database connection from db.internal" }
            ],
            "edges": [
                { "source": "db.internal/conn.rs", "target": "src/main.rs", "label": "import conn from 'db.internal/psql'" }
            ]
        });

        let policy = PrivacyPolicy::default();
        let (sanitized, _redactions) = sanitize_dependency_graph(&graph, &policy);

        let node_label = sanitized["nodes"][0]["label"].as_str().unwrap_or("");
        assert!(
            !node_label.contains("db.internal"),
            "Hostname should be redacted in node label. Got: {}",
            node_label
        );

        // source and target must also be sanitized — this was the original bypass
        let edge_source = sanitized["edges"][0]["source"].as_str().unwrap_or("");
        assert!(
            !edge_source.contains("db.internal"),
            "Hostname should be redacted in edge source. Got: {}",
            edge_source
        );

        let edge_target = sanitized["edges"][0]["target"].as_str().unwrap_or("");
        assert!(
            edge_target == "src/main.rs",
            "Clean edge target should be unchanged. Got: {}",
            edge_target
        );

        let edge_label = sanitized["edges"][0]["label"].as_str().unwrap_or("");
        assert!(
            !edge_label.contains("db.internal"),
            "Hostname should be redacted in edge label. Got: {}",
            edge_label
        );
    }
}
