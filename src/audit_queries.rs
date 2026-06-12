// Tree-sitter queries used by `audit_file_ast` in `analyzer.rs`.
//
// Each constant is a tree-sitter s-expression pattern string suitable for
// passing to `tree_sitter::Query::new(language, pattern)`.
//
// Only structural patterns are included here; regex-based secret detection
// lives in `sanitizer.rs` and remains unchanged.

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

/// Rust — `unsafe { … }` expression blocks.
///
/// Catches both bare `unsafe { }` and unsafe blocks inside `unsafe fn`.
pub const RUST_UNSAFE_BLOCK: &str = r#"
(unsafe_block) @unsafe_block
"#;

/// Rust — `unsafe fn` definitions (function-level unsafety declaration).
pub const RUST_UNSAFE_FN: &str = r#"
(function_item "unsafe" name: (identifier) @fn_name) @unsafe_fn
"#;

/// Rust — `.unwrap()` / `.expect(…)` calls that can cause panics.
///
/// Matches field-expression calls where the method name is `unwrap` or `expect`.
/// Reserved for future use in a panic-risk analysis pass.
#[allow(dead_code)]
pub const RUST_PANICS: &str = r#"
(call_expression
  function: (field_expression
    field: (field_identifier) @name
    (#match? @name "^(unwrap|expect)$"))) @panic_call
"#;

// Detects `unsafe` blocks in Rust source.
pub const RUST_UNSAFE_BLOCK_QUERY: &str = r#"
  (unsafe_block) @unsafe_block
"#;

/// Detects inline assembly (`asm!`) calls in Rust.
pub const RUST_INLINE_ASM_QUERY: &str = r#"
  (macro_invocation
    macro: (identifier) @name
    (#eq? @name "asm"))
  @asm_call
"#;

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

/// JS/TS — `eval(…)` and `new Function(…)` calls.
pub const JS_EVAL: &str = r#"
(call_expression
  function: (identifier) @name
  (#match? @name "^(eval|exec)$")) @eval_call
"#;

/// Detects `eval(...)` calls in JS/TS.
pub const JS_EVAL_QUERY: &str = r#"
  (call_expression
    function: (identifier) @fn_name
    (#eq? @fn_name "eval"))
  @eval_call
"#;

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

/// Python — `eval(…)`, `exec(…)`, and `compile(…)` calls.
pub const PY_EVAL: &str = r#"
(call
  function: (identifier) @name
  (#match? @name "^(eval|exec|compile)$")) @eval_call
"#;

/// Detects `eval(...)` and `exec(...)` calls in Python.
pub const PYTHON_EVAL_EXEC_QUERY: &str = r#"
  (call
    function: (identifier) @fn_name
    (#match? @fn_name "^(eval|exec)$"))
  @dangerous_call
"#;

// ─── Java ────────────────────────────────────────────────────────────────────

/// Detects `Runtime.exec(...)` and `ProcessBuilder` calls in Java.
pub const JAVA_EXEC_QUERY: &str = r#"
  (method_invocation
    name: (identifier) @name
    (#eq? @name "exec"))
  @exec_call
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Query;

    /// Verifica que todas las queries son S-expressions válidas para su lenguaje.
    #[test]
    fn rust_unsafe_query_is_valid() {
        let lang = tree_sitter_rust::language();
        assert!(Query::new(lang, RUST_UNSAFE_BLOCK_QUERY).is_ok());
    }

    #[test]
    fn python_eval_exec_query_is_valid() {
        let lang = tree_sitter_python::language();
        assert!(Query::new(lang, PYTHON_EVAL_EXEC_QUERY).is_ok());
    }

    #[test]
    fn js_eval_query_is_valid() {
        let lang = tree_sitter_javascript::language();
        assert!(Query::new(lang, JS_EVAL_QUERY).is_ok());
    }

    #[test]
    fn ts_eval_query_is_valid() {
        let lang = tree_sitter_typescript::language_typescript();
        assert!(Query::new(lang, JS_EVAL_QUERY).is_ok());
    }

    #[test]
    fn tsx_eval_query_is_valid() {
        let lang = tree_sitter_typescript::language_tsx();
        assert!(Query::new(lang, JS_EVAL_QUERY).is_ok());
    }
}
