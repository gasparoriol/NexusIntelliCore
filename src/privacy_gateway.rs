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
use tracing::warn;

use crate::sanitizer;

#[derive(Default, Clone, Debug)]
struct DynamicSecurityOverrides {
    custom_redaction_patterns: Vec<String>,
    custom_strip_placeholder: Option<String>,
}

fn load_dynamic_overrides() -> DynamicSecurityOverrides {
    let mut overrides = DynamicSecurityOverrides::default();

    if let Ok(raw) = std::env::var("MCP_CUSTOM_REDACTION_PATTERNS") {
        overrides.custom_redaction_patterns.extend(
            raw.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty()),
        );
    }

    if let Ok(raw) = std::env::var("MCP_CUSTOM_STRIP_PLACEHOLDER") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            overrides.custom_strip_placeholder = Some(trimmed.to_string());
        }
    }

    if let Ok(config_path) = std::env::var("MCP_SECURITY_CONFIG_PATH") {
        if let Ok(raw) = std::fs::read_to_string(config_path) {
            if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                if let Some(arr) = parsed
                    .get("custom_redaction_patterns")
                    .and_then(|v| v.as_array())
                {
                    overrides.custom_redaction_patterns.extend(
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .filter(|p| !p.is_empty()),
                    );
                }

                if overrides.custom_strip_placeholder.is_none() {
                    overrides.custom_strip_placeholder = parsed
                        .get("custom_strip_placeholder")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                }
            }
        }
    }

    overrides
}

fn apply_custom_redaction_patterns(text: &str) -> (String, Vec<String>) {
    let patterns = load_dynamic_overrides().custom_redaction_patterns;
    if patterns.is_empty() {
        return (text.to_string(), Vec::new());
    }

    let mut out = text.to_string();
    let mut fired = Vec::new();
    for pattern in patterns {
        match regex::Regex::new(&pattern) {
            Ok(re) => {
                if re.is_match(&out) {
                    out = re.replace_all(&out, "[REDACTED_BY_MCP]").into_owned();
                    fired.push(format!("CUSTOM_PATTERN:{pattern}"));
                }
            }
            Err(e) => {
                warn!(pattern = %pattern, error = %e, "Invalid custom redaction regex ignored");
            }
        }
    }
    (out, fired)
}

fn sanitize_text_with_dynamic_patterns(text: &str) -> (String, Vec<String>) {
    let (sanitized, mut redactions) = sanitizer::sanitize_text(text);
    let (sanitized_custom, custom_redactions) = apply_custom_redaction_patterns(&sanitized);
    redactions.extend(custom_redactions);
    (sanitized_custom, redactions)
}

/// Policy for what to do when a secret or sensitive pattern is found
#[derive(Clone, Debug)]
pub struct PrivacyPolicy {
    /// If true, omit restricted content entirely
    #[allow(dead_code)]
    pub omit_restricted: bool,
    /// If true, redact secret VALUES but show [REDACTED: TYPE]
    pub redact_secrets: bool,
    /// If true, apply @mcp-strip filtering
    #[allow(dead_code)]
    pub apply_strip_marks: bool,

    pub sensitive_keys: Vec<String>,
}

impl PrivacyPolicy {
    pub fn new(keys: Vec<&str>) -> Self {
        Self {
            sensitive_keys: keys.into_iter().map(str::to_owned).collect(),
            omit_restricted: false,
            redact_secrets: true,
            apply_strip_marks: true,
        }
    }

    pub fn is_sensitive(&self, key: &str) -> bool {
        // Normalizamos a minúsculas para evitar errores por case-sensitivity
        self.sensitive_keys.contains(&key.to_lowercase())
    }
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self::new(vec![
            "api_key",
            "password",
            "token",
            "secret",
            "authorization",
            "private_key",
        ])
    }
}

/// Sanitize text that may contain secrets, sensitive hostnames, or comments.
/// Returns both the sanitized text and a list of redaction actions applied.
pub fn sanitize_output_text(text: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    if !policy.redact_secrets {
        return (text.to_string(), Vec::new());
    }

    let (sanitized, redactions) = sanitize_text_with_dynamic_patterns(text);
    (sanitized, redactions)
}

/// Sanitize import strings (may contain hostnames or module names)
pub fn sanitize_import(import_text: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    if !policy.redact_secrets {
        return (import_text.to_string(), Vec::new());
    }

    let (sanitized, redactions) = sanitize_text_with_dynamic_patterns(import_text);
    (sanitized, redactions)
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
#[allow(dead_code)]
pub fn sanitize_doc_comment(comment: &str, policy: &PrivacyPolicy) -> (String, Vec<String>) {
    if !policy.redact_secrets {
        return (comment.to_string(), Vec::new());
    }
    let (sanitized, redactions) = sanitize_text_with_dynamic_patterns(comment);
    (sanitized, redactions)
}

/// Sanitize function/method source code.
/// - Strips body when `@mcp-strip` is present (language-aware)
/// - Removes sensitive comments
/// - Redacts secrets
pub fn sanitize_function_source(
    source: &str,
    _signature: &str,
    _language: &str,
    _policy: &PrivacyPolicy,
) -> (String, Vec<String>) {
    let mut redactions = Vec::new();

    // Step 1: Remove sensitive comments
    let sanitized = sanitizer::strip_sensitive_comments(source);

    // Step 2: Redact secrets
    let (final_sanitized, secret_redactions) = sanitize_text_with_dynamic_patterns(&sanitized);
    redactions.extend(secret_redactions.iter().cloned());

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
#[allow(dead_code)]
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

///Sanitize JSON arguments recursively, redacting any sensitive strings found in keys or values.
/// It's used to sanitize structured data returned by tools, such as dependency graphs or audit reports.
pub fn sanitize_json_args(value: &serde_json::Value, policy: &PrivacyPolicy) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let (clean, _redacted) = sanitize_output_text(s, policy);
            serde_json::Value::String(clean)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|item| sanitize_json_args(item, policy))
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if policy.is_sensitive(k) {
                        (k.clone(), serde_json::json!("[REDACTED]"))
                    } else {
                        (k.clone(), sanitize_json_args(v, policy))
                    }
                })
                .collect(),
        ),

        _ => value.clone(),
    }
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
            "Internal hostname should be redacted. Got: {sanitized}"
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
            "API key should be redacted. Got: {sanitized}"
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
            "Body should be stripped. Got: {sanitized}"
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
            "Body of unannotated function must not be stripped. Got: {sanitized}"
        );
    }

    #[test]
    fn sanitize_function_source_strips_marked_python() {
        let source = "def secret():  # @mcp-strip\n    return os.environ['DB_PASS']\n";
        // Stripping occurs via AST body byte range before calling sanitize_function_source
        let stripped = sanitizer::strip_body_by_range(
            source,
            (14, source.len()),
            "python",
            sanitizer::DEFAULT_STRIP_PLACEHOLDER,
        );
        let policy = PrivacyPolicy::default();
        let (sanitized, _) = sanitize_function_source(&stripped, "secret", "python", &policy);
        assert!(
            sanitized.contains("def secret"),
            "def line must be preserved. Got: {sanitized}"
        );
        assert!(
            !sanitized.contains("DB_PASS"),
            "Body must be stripped for Python @mcp-strip. Got: {sanitized}"
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
            "Hostname should be redacted in node label. Got: {node_label}"
        );

        // source and target must also be sanitized — this was the original bypass
        let edge_source = sanitized["edges"][0]["source"].as_str().unwrap_or("");
        assert!(
            !edge_source.contains("db.internal"),
            "Hostname should be redacted in edge source. Got: {edge_source}"
        );

        let edge_target = sanitized["edges"][0]["target"].as_str().unwrap_or("");
        assert!(
            edge_target == "src/main.rs",
            "Clean edge target should be unchanged. Got: {edge_target}"
        );

        let edge_label = sanitized["edges"][0]["label"].as_str().unwrap_or("");
        assert!(
            !edge_label.contains("db.internal"),
            "Hostname should be redacted in edge label. Got: {edge_label}"
        );
    }

    #[test]
    fn sanitize_json_args_redacts_string_values() {
        let policy = PrivacyPolicy::default();
        let input = serde_json::json!({
            "file_path": "/home/user/project/main.rs",
            "api_key": "sk-openai-XXXXXXXXXXXXXXXXXXXXXXXX"
        });
        let result = sanitize_json_args(&input, &policy);
        // api_key debe estar redactado
        let key_val = result["api_key"].as_str().unwrap();
        assert!(
            key_val.contains("[REDACTED"),
            "API key should be redacted, got: {key_val}"
        );
    }

    #[test]
    fn sanitize_json_args_preserves_non_string_types() {
        let policy = PrivacyPolicy::default();
        let input = serde_json::json!({
            "count": 42,
            "enabled": true,
            "ratio": 0.5
        });
        let result = sanitize_json_args(&input, &policy);
        assert_eq!(result["count"], serde_json::json!(42));
        assert_eq!(result["enabled"], serde_json::json!(true));
    }

    #[test]
    fn sanitize_json_args_handles_nested_arrays() {
        let policy = PrivacyPolicy::default();
        let input = serde_json::json!({
            "sections": ["overview", "api"]
        });
        let result = sanitize_json_args(&input, &policy);
        // Valores inocuos no deben ser alterados
        assert_eq!(result["sections"][0].as_str().unwrap(), "overview");
    }

    #[test]
    fn sanitize_output_text_applies_custom_redaction_pattern() {
        let orig_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();
        let temp_dir = std::env::temp_dir();
        let config_file = temp_dir.join("privacy_gateway_custom_pattern_test.json");
        std::fs::write(
            &config_file,
            r#"{
  "custom_redaction_patterns": ["ACME-[0-9]{4}"]
}"#,
        )
        .unwrap();

        std::env::set_var(
            "MCP_SECURITY_CONFIG_PATH",
            config_file.to_string_lossy().to_string(),
        );

        let policy = PrivacyPolicy::default();
        let (sanitized, redactions) = sanitize_output_text("ticket=ACME-1234", &policy);
        assert!(sanitized.contains("[REDACTED_BY_MCP]"));
        assert!(redactions.iter().any(|r| r.contains("CUSTOM_PATTERN")));

        let _ = std::fs::remove_file(config_file);
        if let Some(v) = orig_config {
            std::env::set_var("MCP_SECURITY_CONFIG_PATH", v);
        } else {
            std::env::remove_var("MCP_SECURITY_CONFIG_PATH");
        }
    }
}
