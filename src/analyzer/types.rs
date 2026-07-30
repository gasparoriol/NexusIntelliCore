use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    /// Canonical symbol path including owner context when available
    /// (e.g. `Outer.Inner.method` or `Type::method`).
    pub qualified_name: String,
    /// Optional owner path without the method name
    /// (e.g. `Outer.Inner` or `Type`).
    #[allow(dead_code)]
    pub owner_chain: Option<String>,
    /// The function signature (everything before the opening brace).
    pub signature: String,
    /// Normalized signature used for deterministic matching/disambiguation.
    #[allow(dead_code)]
    pub normalized_signature: Option<String>,
    /// The full source of the function body (may be stripped later).
    pub body_source: String,
    pub start_line: usize,
    pub end_line: usize,
    /// `true` when `@mcp-strip` is detected via AST comment nodes (not string literals).
    pub is_strip_marked: bool,
    /// Byte range of the function body relative to `body_source` start.
    /// For brace languages, the range excludes outer `{` and `}`.
    /// For Python, it spans the full indented block.
    /// `None` only for unsupported body shapes.
    pub body_byte_range: Option<(usize, usize)>,
    /// Doc comment block immediately preceding the function definition.
    pub doc_comment: Option<String>,
    /// `true` when the symbol is publicly visible (language-aware heuristic).
    pub is_public: bool,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub name: String,
    pub kind: String, // "class", "struct", "impl", "trait", …
    pub start_line: usize,
    pub end_line: usize,
    /// Doc comment block immediately preceding the type definition.
    pub doc_comment: Option<String>,
    /// `true` when the symbol is publicly visible (language-aware heuristic).
    pub is_public: bool,
}

/// Semantic classification of an import statement.
///
/// Computed at extraction time from the import path string; refined to
/// `InternalLocal` / `InternalRestricted` / `Unresolved` when the file
/// index is available (see `resolve_import_path` in `tools.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ImportKind {
    /// Import resolves to a file within the project's allowed files.
    InternalLocal,
    /// Import resolves to a file blocked by `.mcpignore`.
    InternalRestricted,
    /// External dependency (crate, npm package, Python package, stdlib, …).
    ExternalLibrary,
    /// Cannot be determined — relative import that didn't resolve, or unknown.
    Unresolved,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    /// The raw import/use line.
    pub raw: String,
    /// The extracted module/package path (without surrounding quotes or keywords).
    pub path: String,
    /// Semantic classification of the import.
    pub kind: ImportKind,
    /// Resolved absolute path within the project. `None` for external/unresolved.
    /// Reserved for future use (cross-file navigation, refactoring tools, etc.).
    #[allow(dead_code)]
    pub resolved_path: Option<PathBuf>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StringLiteral {
    pub value: String,
    pub line: usize,
}

/// A single CSS rule set (selector + property names).
#[derive(Debug, Clone)]
pub struct CssRuleInfo {
    pub selector: String,
    pub properties: Vec<String>,
    pub media_query: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
}

/// An HTML element extracted from a template (including Angular binding attributes).
#[derive(Debug, Clone)]
pub struct HtmlElementInfo {
    pub tag_name: String,
    pub class_names: Vec<String>,
    pub is_angular_component: bool,
    pub input_bindings: Vec<String>,
    pub output_bindings: Vec<String>,
    pub start_line: usize,
    #[allow(dead_code)]
    pub end_line: usize,
}

#[derive(Debug, Default, Clone)]
pub struct FileAnalysis {
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    #[allow(dead_code)]
    pub string_literals: Vec<StringLiteral>,
    pub language: String,
    /// Populated for `.css` files; `None` for all other languages.
    pub css_rules: Option<Vec<CssRuleInfo>>,
    /// Populated for `.html` / `.htm` files; `None` for all other languages.
    pub html_elements: Option<Vec<HtmlElementInfo>>,
    /// Module-level / file-level documentation comment (e.g. Rust `//!`, Python module docstring).
    pub module_doc: Option<String>,
}

/// Kind of security finding detected by `audit_file_ast`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditFindingKind {
    /// `unsafe { }` block or `unsafe fn` (Rust).
    UnsafeCode,
    /// `eval()` / `exec()` / `compile()` dynamic execution call.
    DynamicExecution,
    /// Assignment to a dangerous sink (for example `innerHTML = ...`).
    InsecureAssignment,
}

/// A single AST-derived security finding with source location.
#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub kind: AuditFindingKind,
    pub line: usize,
    pub description: String,
}

#[derive(Debug, serde::Serialize)]
pub struct PatternMatch {
    pub pattern: String,
    pub evidence: String,
    pub file: String,
    pub line: usize,
}

/// How an application entrypoint was identified.
#[derive(Debug, Clone, PartialEq)]
pub enum EntrypointKind {
    /// A `main` function (or `__main__` sentinel for Python).
    MainFunction,
    /// A CLI framework was detected via imports.
    CliFramework(String),
    /// An HTTP framework was detected via imports.
    HttpFramework(String),
    /// No `main` found but public symbols exist — likely a library crate/module.
    LibraryCrate,
}

/// A detected application entrypoint.
#[derive(Debug, Clone)]
pub struct Entrypoint {
    pub kind: EntrypointKind,
    pub file: PathBuf,
    /// Name of the entry symbol when applicable (e.g. `"main"`, `"__main__"`).
    pub symbol: Option<String>,
    /// Signature string when available.
    pub signature: Option<String>,
}

/// Confidence level for an inferred use case.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UseCaseConfidence {
    #[allow(dead_code)]
    Low,
    Medium,
    High,
}

/// A use case inferred from public symbols and their doc-comments.
#[derive(Debug, Clone)]
pub struct InferredUseCase {
    pub title: String,
    pub description: String,
    /// Function names that contributed to this inference.
    pub functions: Vec<String>,
    pub confidence: UseCaseConfidence,
}
