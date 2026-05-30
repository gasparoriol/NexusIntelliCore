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

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

/// JS/TS — `eval(…)` and `new Function(…)` calls.
pub const JS_EVAL: &str = r#"
(call_expression
  function: (identifier) @name
  (#match? @name "^(eval|exec)$")) @eval_call
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
