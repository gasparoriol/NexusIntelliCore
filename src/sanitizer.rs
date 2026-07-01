/// Phase 4: Privacy Gateway — sanitizes all AST text before it reaches the LLM.
///
/// • 4.1  Intercepts secrets (API keys, AWS keys, JWTs, DB URIs, private IPs, …)
/// • 4.2  Strips function bodies marked with `// @mcp-strip`
/// • 4.3  Removes or redacts sensitive inline comments
use lazy_static::lazy_static;
use regex::Regex;

pub const DEFAULT_STRIP_PLACEHOLDER: &str = "Lógica de negocio ofuscada por seguridad";

// ---------------------------------------------------------------------------
// Compiled regex patterns (lazy, compiled once at first use)
// ---------------------------------------------------------------------------
lazy_static! {
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex)> = vec![
        // OpenAI / Anthropic-style API keys
        (
            "OPENAI_KEY",
            Regex::new(r"sk-[a-zA-Z0-9]{32,}").unwrap(),
        ),
        // AWS access key ID
        (
            "AWS_ACCESS_KEY",
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        ),
        // JWT (three base64url segments)
        (
            "JWT_TOKEN",
            Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap(),
        ),
        // Database connection URIs
        (
            "DB_CONNECTION_URI",
            Regex::new(
                r#"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|mariadb|sqlite)://[^\s"'`\r\n]+"#,
            )
            .unwrap(),
        ),
        // Private / non-routable IPv4 addresses
        (
            "PRIVATE_IP",
            Regex::new(
                r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            )
            .unwrap(),
        ),
        // GitHub fine-grained / classic personal access tokens
        (
            "GITHUB_TOKEN",
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b").unwrap(),
        ),
        // Generic password / secret / token variable assignments
        (
            "GENERIC_SECRET",
            Regex::new(
                r#"(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key)\s*[=:]\s*("[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[A-Za-z0-9!@#$%^&*()\-_+=\[\]{};:|,.<>/?]{8,})"#,
            )
            .unwrap(),
        ),
        // PEM private keys
        (
            "PEM_PRIVATE_KEY",
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
        ),
        // Internal hostname patterns (e.g. db.internal, api.corp.local)
        (
            "INTERNAL_HOSTNAME",
            Regex::new(r"\b[\w-]+\.(internal|corp|local|lan|intranet)\b").unwrap(),
        ),
    ];

    /// Detects the `// @mcp-strip` annotation (Rust / JS / TS / Java style).
    static ref MCP_STRIP_RE: Regex =
        Regex::new(r"(?m)//\s*@mcp-strip\b").unwrap();

    /// Detects the `# @mcp-strip` annotation (Python style).
    static ref MCP_STRIP_PY_RE: Regex =
        Regex::new(r"(?m)#\s*@mcp-strip\b").unwrap();

    /// Matches inline comments that look like they contain employee data,
    /// credentials, or confidentiality markers.
    static ref SENSITIVE_COMMENT_RE: Regex = Regex::new(
        r"(?im)//[^\n]*(confidential|classified|do\s+not\s+share|employee\s+id|salary|ssn|social\s+security|do\s+not\s+commit)",
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Language Support — Comment Styles and Detection
// ---------------------------------------------------------------------------

/// Return the comment style for a given programming language.
/// This ensures language-aware detection of `@mcp-strip` annotations.
///
/// # Examples
/// - Python, Ruby, Shell, YAML → `"#"`
/// - Rust, Go, Java, JS, TS, C, C++, Kotlin, Swift → `"//"`
/// - Unknown languages → default to `"//"` (safe fallback)
#[allow(dead_code)]
pub fn comment_style(lang: &str) -> &'static str {
    match lang.to_lowercase().as_str() {
        "python" | "ruby" | "shell" | "bash" | "yaml" | "yml" => "#",
        _ => "//", // fallback for unknown languages
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Replace every detected secret inside `text` with `[REDACTED_BY_MCP]`.
///
/// Returns `(sanitized_text, list_of_pattern_labels_that_fired)`.
///
/// **Note on memory security (known limitation)**: This implementation redacts
/// secrets in the output sent to the LLM client but does NOT guarantee zeroization
/// of intermediate heap buffers. Copies of strings containing scanned secrets remain
/// in memory until the system allocator overwrites them. For true zeroization,
/// wrap intermediate buffers in `zeroize::Zeroizing<Vec<u8>>` (add `zeroize = "1"`
/// to Cargo.toml) and call `.zeroize()` on drop. For production use with highly
/// sensitive secrets (HIPAA, PCI-DSS), consider a separate process boundary.
pub fn sanitize_text(text: &str) -> (String, Vec<String>) {
    let mut result = text.to_owned();
    let mut fired: Vec<String> = Vec::new();

    for (label, pattern) in SECRET_PATTERNS.iter() {
        if pattern.is_match(&result) {
            result = pattern
                .replace_all(&result, "[REDACTED_BY_MCP]")
                .into_owned();
            fired.push((*label).to_string());
        }
    }

    (result, fired)
}

/// Scan `text` for ALL secret matches.
///
/// Returns a vec of `(pattern_label, 1-based_line_number)`.
pub fn detect_all_secrets(text: &str) -> Vec<(&'static str, usize)> {
    let mut findings = Vec::new();
    for (label, pattern) in SECRET_PATTERNS.iter() {
        for m in pattern.find_iter(text) {
            let line = text[..m.start()].chars().filter(|&c| c == '\n').count() + 1;
            findings.push((*label, line));
        }
    }
    findings
}

/// Returns `true` when the text contains a `@mcp-strip` annotation.
///
/// Recognizes both `// @mcp-strip` (Rust / JS / TS / Java) and
/// `# @mcp-strip` (Python).
pub fn has_mcp_strip(text: &str) -> bool {
    MCP_STRIP_RE.is_match(text) || MCP_STRIP_PY_RE.is_match(text)
}

/// Remove comments that contain sensitive metadata (employee data, etc.).
pub fn strip_sensitive_comments(text: &str) -> String {
    SENSITIVE_COMMENT_RE
        .replace_all(text, "// [COMMENT REDACTED BY MCP]")
        .into_owned()
}

fn indentation_from_body_slice(body: &str) -> Option<String> {
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ws = line
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect::<String>();
        return Some(ws);
    }
    None
}

fn indentation_after_signature(before: &str) -> String {
    let base_ws = before
        .lines()
        .last()
        .map(|line| {
            line.chars()
                .take_while(|c| *c == ' ' || *c == '\t')
                .collect::<String>()
        })
        .unwrap_or_default();

    format!("{base_ws}    ")
}

/// Replace a function body using precise AST byte ranges.
///
/// `body_range` is relative to `source` (`FunctionInfo::body_source`).
/// For brace languages it typically excludes `{` and `}`.
/// For Python it should include the full indentation-based block.
pub fn strip_body_by_range(
    source: &str,
    body_range: (usize, usize),
    language: &str,
    placeholder: &str,
) -> String {
    let bytes = source.as_bytes();
    let (start, end) = body_range;
    if start > bytes.len() || end > bytes.len() || start > end {
        return source.to_owned();
    }

    let before = std::str::from_utf8(&bytes[..start]).unwrap_or(source);
    let body = std::str::from_utf8(&bytes[start..end]).unwrap_or("");
    let after = std::str::from_utf8(&bytes[end..]).unwrap_or("");

    if language == "python" {
        let indent = indentation_from_body_slice(body)
            .unwrap_or_else(|| indentation_after_signature(before));
        return format!("{before}{indent}# [{placeholder}]\n{indent}pass{after}");
    }

    // Common case for brace languages with interior body range.
    if before.trim_end().ends_with('{') {
        let indent = indentation_after_signature(before);
        return format!("{before}\n{indent}/* {placeholder} */\n{after}");
    }

    // Generic fallback for non-brace bodies.
    let comment = comment_style(language);
    let indent = indentation_after_signature(before);
    format!("{before}\n{indent}{comment} [{placeholder}]\n{after}")
}

/// Legacy fallback when AST body ranges are unavailable.
#[deprecated(note = "Prefer strip_body_by_range with AST byte ranges")]
pub fn strip_function_body_with_placeholder(
    code: &str,
    language: &str,
    placeholder: &str,
) -> String {
    if language == "python" {
        // Heuristic fallback: replace everything after the first newline.
        if let Some(pos) = code.find('\n') {
            return strip_body_by_range(code, (pos + 1, code.len()), language, placeholder);
        }
        return code.to_owned();
    }

    if let Some(open) = code.find('{') {
        let close = code.rfind('}').unwrap_or(code.len());
        if open < close {
            return strip_body_by_range(code, (open + 1, close), language, placeholder);
        }
    }
    code.to_owned()
}

/// Legacy compatibility wrapper using the default placeholder.
#[allow(dead_code)]
#[allow(deprecated)]
pub fn strip_function_body(code: &str, language: &str) -> String {
    strip_function_body_with_placeholder(code, language, DEFAULT_STRIP_PLACEHOLDER)
}

/// Strip a function body using precise byte offsets from the AST rather than
/// searching for the first `{`.
///
/// `source` is the full function text (i.e. `FunctionInfo::body_source`).
/// `body_range` is `(inner_start, inner_end)` **relative to the start of
/// `source`**, where:
/// - `inner_start` is the byte immediately after the opening `{`
/// - `inner_end` is the byte offset of the closing `}`
///
/// Returns `source` unchanged if the offsets are out of bounds.
#[allow(dead_code)]
pub fn strip_body_by_range_default(
    source: &str,
    body_range: (usize, usize),
    language: &str,
) -> String {
    strip_body_by_range(source, body_range, language, DEFAULT_STRIP_PLACEHOLDER)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_openai_key() {
        let (out, labels) = sanitize_text("key = sk-abcdefghijklmnopqrstuvwxyz123456");
        assert!(out.contains("[REDACTED_BY_MCP]"));
        assert!(labels.iter().any(|l| l == "OPENAI_KEY"));
    }

    #[test]
    fn redacts_db_uri() {
        let (out, _) = sanitize_text("let url = postgres://user:pass@db.internal:5432/prod;");
        assert!(out.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn detects_private_ip() {
        assert!(!detect_all_secrets("server = 192.168.1.100").is_empty());
    }

    #[test]
    fn detects_mcp_strip() {
        // Rust / JS / TS style (//)
        assert!(has_mcp_strip("fn secret() { // @mcp-strip\n}"));
        assert!(!has_mcp_strip("fn public() { }"));
        // Python style (#)
        assert!(has_mcp_strip("def secret():  # @mcp-strip\n    pass"));
        assert!(!has_mcp_strip("def public():\n    pass"));
    }

    #[test]
    fn strips_python_function_body() {
        let code = "def secret():  # @mcp-strip\n    internal_logic()\n    return 42\n";
        let stripped = strip_function_body(code, "python");
        assert!(stripped.contains("def secret()"), "def line must be kept");
        assert!(
            stripped.contains("# [Lógica de negocio ofuscada por seguridad]"),
            "placeholder must appear"
        );
        assert!(
            !stripped.contains("internal_logic"),
            "body must not appear. Got: {}",
            stripped
        );
    }

    #[test]
    fn strips_async_python_function_body() {
        let code = "    async def fetch(self):  # @mcp-strip\n        await self.conn.query()\n";
        let stripped = strip_function_body(code, "python");
        assert!(stripped.contains("async def fetch"));
        assert!(!stripped.contains("conn.query"));
    }

    #[test]
    fn strips_function_body() {
        let code = "fn secret() {\n    do_stuff();\n}";
        let stripped = strip_function_body(code, "rust");
        assert!(stripped.contains("/* Lógica de negocio ofuscada por seguridad */"));
        assert!(stripped.contains("fn secret()"));
    }

    #[test]
    fn redacts_jwt_token() {
        let jwt = "token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let (out, labels) = sanitize_text(jwt);
        assert!(out.contains("[REDACTED_BY_MCP]"));
        assert!(labels.contains(&"JWT_TOKEN".to_string()));
    }

    #[test]
    fn redacts_github_token() {
        let (out, labels) =
            sanitize_text("gh_token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn");
        assert!(out.contains("[REDACTED_BY_MCP]"));
        assert!(labels.contains(&"GITHUB_TOKEN".to_string()));
    }

    #[test]
    fn redacts_aws_key() {
        let (out, labels) = sanitize_text("key = AKIAIOSFODNN7EXAMPLE");
        assert!(out.contains("[REDACTED_BY_MCP]"));
        assert!(labels.contains(&"AWS_ACCESS_KEY".to_string()));
    }

    #[test]
    fn redacts_pem_private_key() {
        let (out, _) = sanitize_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
        );
        assert!(out.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn redacts_generic_secret_assignment() {
        let (out, labels) = sanitize_text(r#"password = "SuperS3cret!Pass""#);
        assert!(out.contains("[REDACTED_BY_MCP]"));
        assert!(labels.contains(&"GENERIC_SECRET".to_string()));
    }

    #[test]
    fn redacts_internal_hostname() {
        let (out, _) = sanitize_text("host = db-primary.internal");
        assert!(out.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn does_not_redact_public_ip() {
        let (out, _) = sanitize_text("dns = 8.8.8.8");
        assert!(!out.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn does_not_redact_non_private_192() {
        let (out, _) = sanitize_text("addr = 192.167.1.1");
        assert!(!out.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn handles_empty_string() {
        let (out, labels) = sanitize_text("");
        assert_eq!(out, "");
        assert!(labels.is_empty());
    }

    #[test]
    fn handles_unicode_without_panic() {
        let (out, _) = sanitize_text("// コメント: password = \"日本語テスト12345678\"");
        assert!(out.contains("[REDACTED_BY_MCP]"));
    }

    #[test]
    fn comment_style_python_uses_hash() {
        assert_eq!(comment_style("python"), "#");
        assert_eq!(comment_style("PYTHON"), "#");
        assert_eq!(comment_style("ruby"), "#");
        assert_eq!(comment_style("shell"), "#");
        assert_eq!(comment_style("yaml"), "#");
    }

    #[test]
    fn comment_style_c_style_langs_use_slash() {
        assert_eq!(comment_style("rust"), "//");
        assert_eq!(comment_style("go"), "//");
        assert_eq!(comment_style("golang"), "//");
        assert_eq!(comment_style("java"), "//");
        assert_eq!(comment_style("javascript"), "//");
        assert_eq!(comment_style("typescript"), "//");
        assert_eq!(comment_style("c"), "//");
        assert_eq!(comment_style("cpp"), "//");
        assert_eq!(comment_style("c++"), "//");
        assert_eq!(comment_style("kotlin"), "//");
        assert_eq!(comment_style("swift"), "//");
    }

    #[test]
    fn comment_style_unknown_defaults_to_slash() {
        assert_eq!(comment_style("unknown"), "//");
        assert_eq!(comment_style("cobol"), "//");
    }

    #[test]
    fn detects_mcp_strip_in_go() {
        // Go function with @mcp-strip
        let go_code = "func secretFunc() { // @mcp-strip\n    // logic\n}";
        assert!(
            has_mcp_strip(go_code),
            "should detect Go @mcp-strip annotation"
        );

        let go_no_strip = "func publicFunc() {\n    // logic\n}";
        assert!(
            !has_mcp_strip(go_no_strip),
            "should not detect @mcp-strip when absent"
        );
    }

    #[test]
    fn detects_mcp_strip_in_java() {
        // Java method with @mcp-strip
        let java_code = "public void secretMethod() { // @mcp-strip\n    doStuff();\n}";
        assert!(
            has_mcp_strip(java_code),
            "should detect Java @mcp-strip annotation"
        );

        let java_no_strip = "public void publicMethod() {\n    doStuff();\n}";
        assert!(
            !has_mcp_strip(java_no_strip),
            "should not detect @mcp-strip when absent"
        );
    }

    #[test]
    fn detects_mcp_strip_in_typescript() {
        // TypeScript function with @mcp-strip
        let ts_code = "function secretFn(): void { // @mcp-strip\n    secretLogic();\n}";
        assert!(
            has_mcp_strip(ts_code),
            "should detect TypeScript @mcp-strip annotation"
        );

        let ts_no_strip = "function publicFn(): void {\n    secretLogic();\n}";
        assert!(
            !has_mcp_strip(ts_no_strip),
            "should not detect @mcp-strip when absent"
        );
    }

    #[test]
    fn detects_mcp_strip_in_c() {
        // C function with @mcp-strip
        let c_code = "void secretFunc() { // @mcp-strip\n    internal_logic();\n}";
        assert!(
            has_mcp_strip(c_code),
            "should detect C @mcp-strip annotation"
        );

        let c_no_strip = "void publicFunc() {\n    internal_logic();\n}";
        assert!(
            !has_mcp_strip(c_no_strip),
            "should not detect @mcp-strip when absent"
        );
    }

    #[test]
    fn detects_mcp_strip_in_cpp() {
        // C++ method with @mcp-strip
        let cpp_code = "void MyClass::secretMethod() { // @mcp-strip\n    internalState = 42;\n}";
        assert!(
            has_mcp_strip(cpp_code),
            "should detect C++ @mcp-strip annotation"
        );

        let cpp_no_strip = "void MyClass::publicMethod() {\n    state = 42;\n}";
        assert!(
            !has_mcp_strip(cpp_no_strip),
            "should not detect @mcp-strip when absent"
        );
    }

    #[test]
    fn strips_go_function_body() {
        let go_code = "func secretFunc() { // @mcp-strip\n    internalCall()\n}";
        let stripped = strip_function_body(go_code, "go");
        assert!(stripped.contains("func secretFunc()"));
        assert!(stripped.contains("/* Lógica de negocio ofuscada por seguridad */"));
        assert!(!stripped.contains("internalCall"));
    }

    #[test]
    fn strips_java_method_body() {
        let java_code = "public void secretMethod() { // @mcp-strip\n    dbQuery();\n}";
        let stripped = strip_function_body(java_code, "java");
        assert!(stripped.contains("public void secretMethod()"));
        assert!(stripped.contains("/* Lógica de negocio ofuscada por seguridad */"));
        assert!(!stripped.contains("dbQuery"));
    }

    #[test]
    fn strips_typescript_function_body() {
        let ts_code = "function secretFn(): void { // @mcp-strip\n    apiCall();\n}";
        let stripped = strip_function_body(ts_code, "typescript");
        assert!(stripped.contains("function secretFn(): void {"));
        assert!(stripped.contains("/* Lógica de negocio ofuscada por seguridad */"));
        assert!(!stripped.contains("apiCall"));
    }

    #[test]
    fn strips_c_function_body() {
        let c_code = "void secretFunc() { // @mcp-strip\n    internal_op();\n}";
        let stripped = strip_function_body(c_code, "c");
        assert!(stripped.contains("void secretFunc()"));
        assert!(stripped.contains("/* Lógica de negocio ofuscada por seguridad */"));
        assert!(!stripped.contains("internal_op"));
    }

    #[test]
    fn strips_sensitive_comments() {
        let code = "let x = 1; // CONFIDENTIAL: do not share\nlet y = 2;";
        let out = strip_sensitive_comments(code);
        assert!(out.contains("[COMMENT REDACTED BY MCP]"));
        assert!(out.contains("let y = 2;"));
    }

    #[test]
    fn detect_all_finds_multiple_secrets() {
        let text = "key1 = sk-abcdefghijklmnopqrstuvwxyz123456\n\
                    key2 = AKIAIOSFODNN7EXAMPLE\n\
                    host = db.internal";
        let findings = detect_all_secrets(text);
        assert!(
            findings.len() >= 3,
            "Expected >=3 findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn strip_body_with_brace_in_comment() {
        let code = "fn foo() // { comment\n{\n    real_body();\n}";
        let stripped = strip_function_body(code, "rust");
        assert!(stripped.contains("fn foo()"));
        assert!(stripped.contains("/* Lógica de negocio ofuscada por seguridad */"));
        assert!(stripped.contains("}"));
        assert!(!stripped.contains("real_body"));
    }
}
