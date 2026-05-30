/// Phase 3: Tree-sitter Code Analyzer
///
/// Parses source files for each supported language and extracts:
/// • Function / method signatures and bodies
/// • Class / struct / impl definitions
/// • Import / use statements (for dependency graph)
/// • String literals (for secret scanning)
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use tree_sitter::{Language, Parser, Query, QueryCursor};

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

pub enum Lang {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Java,
    C,
    CSharp,
    Css,
    Scss,
    Sass,
    Html,
    Unknown,
}

pub fn detect_language(path: &Path) -> Lang {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Lang::Rust,
        Some("py") => Lang::Python,
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => Lang::JavaScript,
        Some("ts") => Lang::TypeScript,
        Some("tsx") => Lang::Tsx,
        Some("java") => Lang::Java,
        Some("c") | Some("h") => Lang::C,
        Some("cs") => Lang::CSharp,
        Some("css") => Lang::Css,
        Some("scss") => Lang::Scss,
        Some("sass") => Lang::Sass,
        Some("html") | Some("htm") => Lang::Html,
        _ => Lang::Unknown,
    }
}

fn ts_language(lang: &Lang) -> Option<Language> {
    match lang {
        Lang::Rust => Some(tree_sitter_rust::language()),
        Lang::Python => Some(tree_sitter_python::language()),
        Lang::JavaScript => Some(tree_sitter_javascript::language()),
        Lang::TypeScript => Some(tree_sitter_typescript::language_typescript()),
        Lang::Tsx => Some(tree_sitter_typescript::language_tsx()),
        Lang::Java => Some(tree_sitter_java::language()),
        Lang::C => Some(tree_sitter_c::language()),
        Lang::CSharp => Some(tree_sitter_c_sharp::language()),
        Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => None,
        Lang::Unknown => None,
    }
}

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    /// The function signature (everything before the opening brace).
    pub signature: String,
    /// The full source of the function body (may be stripped later).
    pub body_source: String,
    pub start_line: usize,
    pub end_line: usize,
    /// `true` when `@mcp-strip` is detected via AST comment nodes (not string literals).
    pub is_strip_marked: bool,
    /// Byte range of the body interior relative to `body_source` start,
    /// excluding the outer `{` and `}`. `None` for Python and unsupported
    /// body shapes. Used by `strip_body_by_range` for precise stripping.
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
    pub resolved_path: Option<std::path::PathBuf>,
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

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

// ---------------------------------------------------------------------------
// AST-based security audit
// ---------------------------------------------------------------------------

/// Kind of security finding detected by `audit_file_ast`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditFindingKind {
    /// `unsafe { }` block or `unsafe fn` (Rust).
    UnsafeCode,
    /// `eval()` / `exec()` / `compile()` dynamic execution call.
    DynamicExecution,
}

/// A single AST-derived security finding with source location.
#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub kind: AuditFindingKind,
    pub line: usize,
    pub description: String,
}

/// Run AST-based security checks on `source` for the given `lang`.
///
/// Returns only findings where the tree-sitter query matches an *actual*
/// AST node — not occurrences inside comments or string literals (which
/// are correctly excluded because they're not matched by the structural
/// queries).
///
/// Falls back to an empty vector for languages without tree-sitter support.
pub fn audit_file_ast(source: &str, lang: &Lang) -> Vec<AuditFinding> {
    let ts_lang = match ts_language(lang) {
        Some(l) => l,
        None => return Vec::new(),
    };

    let mut parser = Parser::new();
    if parser.set_language(ts_lang).is_err() {
        return Vec::new();
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let source_bytes = source.as_bytes();
    let mut findings: Vec<AuditFinding> = Vec::new();

    // --- Unsafe code (Rust only) ---
    if let Lang::Rust = lang {
        for query_str in &[
            crate::audit_queries::RUST_UNSAFE_BLOCK,
            crate::audit_queries::RUST_UNSAFE_FN,
        ] {
            let query = match Query::new(ts_lang, query_str) {
                Ok(q) => q,
                Err(_) => continue,
            };
            let mut cursor = QueryCursor::new();
            for m in cursor.matches(&query, tree.root_node(), source_bytes) {
                // Use the first capture as the representative node for line reporting.
                if let Some(cap) = m.captures.first() {
                    let line = cap.node.start_position().row + 1;
                    let is_fn = query_str.contains("fn_name");
                    findings.push(AuditFinding {
                        kind: AuditFindingKind::UnsafeCode,
                        line,
                        description: if is_fn {
                            "unsafe fn declaration".to_owned()
                        } else {
                            "unsafe block".to_owned()
                        },
                    });
                }
            }
        }
    }

    // --- Dynamic execution (eval/exec) ---
    let eval_query_str = match lang {
        Lang::Python => Some(crate::audit_queries::PY_EVAL),
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => Some(crate::audit_queries::JS_EVAL),
        _ => None,
    };

    if let Some(qstr) = eval_query_str {
        if let Ok(query) = Query::new(ts_lang, qstr) {
            let mut cursor = QueryCursor::new();
            for m in cursor.matches(&query, tree.root_node(), source_bytes) {
                if let Some(cap) = m.captures.first() {
                    let line = cap.node.start_position().row + 1;
                    let name = std::str::from_utf8(
                        &source_bytes[cap.node.start_byte()..cap.node.end_byte()],
                    )
                    .unwrap_or("eval")
                    .to_owned();
                    findings.push(AuditFinding {
                        kind: AuditFindingKind::DynamicExecution,
                        line,
                        description: format!("{}() call", name),
                    });
                }
            }
        }
    }

    findings
}

/// Parse `path` and return a `FileAnalysis`.
pub fn analyze_file(path: &Path) -> Result<FileAnalysis> {
    // Guard: reject files that are too large
    let metadata = std::fs::metadata(path).with_context(|| format!("Cannot stat {:?}", path))?;
    if metadata.len() > MAX_FILE_SIZE {
        anyhow::bail!(
            "File {:?} exceeds maximum size ({} bytes > {} bytes)",
            path,
            metadata.len(),
            MAX_FILE_SIZE
        );
    }

    let source =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {:?}", path))?;

    let lang = detect_language(path);

    // CSS / SCSS / HTML: dedicated parsers with a different data model — return early
    match &lang {
        Lang::Css => return parse_css_file(&source),
        Lang::Html => return parse_html_file(&source),
        Lang::Scss | Lang::Sass => {
            return Ok(FileAnalysis {
                language: "scss".to_owned(),
                ..Default::default()
            })
        }
        _ => {}
    }

    let ts_lang = match ts_language(&lang) {
        Some(l) => l,
        None => {
            return Ok(FileAnalysis {
                language: "unknown".to_owned(),
                ..Default::default()
            })
        }
    };

    let lang_name = match &lang {
        Lang::Rust => "rust",
        Lang::Python => "python",
        Lang::JavaScript => "javascript",
        Lang::TypeScript => "typescript",
        Lang::Tsx => "tsx",
        Lang::Java => "java",
        Lang::C => "c",
        Lang::CSharp => "csharp",
        Lang::Unknown => "unknown",
        // Handled by early returns above — these branches are unreachable at runtime
        Lang::Css => "css",
        Lang::Scss | Lang::Sass => "scss",
        Lang::Html => "html",
    };

    let mut parser = Parser::new();
    parser
        .set_language(ts_lang)
        .context("Failed to set tree-sitter language")?;

    let tree = parser
        .parse(&source, None)
        .context("tree-sitter failed to produce a parse tree")?;

    let root = tree.root_node();

    let functions = extract_functions(root, &source, &lang, &ts_lang)?;
    let classes = extract_classes(root, &source, &lang, &ts_lang)?;
    let imports = extract_imports(root, &source, &lang, &ts_lang)?;
    let string_literals = extract_strings(root, &source, &lang, &ts_lang)?;

    let module_doc = extract_module_doc(&source, &lang);

    Ok(FileAnalysis {
        functions,
        classes,
        imports,
        string_literals,
        language: lang_name.to_owned(),
        css_rules: None,
        html_elements: None,
        module_doc,
    })
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

fn extract_functions(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &Lang,
    ts_lang: &Language,
) -> Result<Vec<FunctionInfo>> {
    let query_str = match lang {
        Lang::Rust => "(function_item name: (identifier) @name) @fn",
        Lang::Python => "(function_definition name: (identifier) @name) @fn",
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            // function_declaration + class method_definition +
            // interface method_signature + const/let arrow/function expressions
            "[(function_declaration name: (identifier) @name) @fn \
              (method_definition name: (property_identifier) @name) @fn \
              (method_signature name: (property_identifier) @name) @fn \
              (variable_declarator name: (identifier) @name \
                value: [(arrow_function) (function_expression)]) @fn]"
        }
        Lang::Java => {
            "[(method_declaration name: (identifier) @name) @fn \
              (constructor_declaration name: (identifier) @name) @fn]"
        }
        Lang::C => {
            // Captures plain functions; pointer-returning functions
            // (ptr_declarator wrapping function_declarator) are not covered here.
            "(function_definition \
               declarator: (function_declarator \
                 declarator: (identifier) @name)) @fn"
        }
        Lang::CSharp => {
            "[(method_declaration name: (identifier) @name) @fn \
              (constructor_declaration name: (identifier) @name) @fn \
              (operator_declaration) @fn \
              (destructor_declaration name: (identifier) @name) @fn]"
        }
        Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => return Ok(vec![]),
    };

    let source_lines: Vec<&str> = source.lines().collect();
    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        // caps: list of (capture_name, node, text)
        let fn_node = caps.iter().find(|(name, _, _)| *name == "fn")?;
        let name_cap = caps.iter().find(|(name, _, _)| *name == "name")?;

        let fn_node_ts = fn_node.1;
        let fn_text = &source[fn_node_ts.byte_range()];
        let name_text = name_cap.2.clone();

        // Use the AST body-node boundary to correctly delimit the signature.
        // find_body_node only returns block-style bodies, so expression arrow
        // functions fall through to extract_signature (no truncation risk).
        let signature = {
            let fn_start = fn_node_ts.start_byte();
            match find_body_node(fn_node_ts) {
                Some(body_node) if body_node.start_byte() > fn_start => {
                    source[fn_start..body_node.start_byte()].trim().to_owned()
                }
                _ => extract_signature(fn_text),
            }
        };
        // Python `comment` nodes are tree-sitter "extras" whose position inside
        // the body block is not guaranteed across parser versions. Regex-based
        // detection is safe for Python because `#` in a string literal is
        // extremely unlikely to form a `# @mcp-strip` annotation. For all
        // C-style languages we use the AST path to avoid false positives from
        // `// @mcp-strip` appearing inside a string literal.
        let is_strip = match lang {
            Lang::Python => crate::sanitizer::has_mcp_strip(fn_text),
            _ => has_mcp_strip_in_ast(fn_node_ts, source.as_bytes()),
        };
        let start_line = fn_node_ts.start_position().row + 1;
        let doc_comment = extract_preceding_comment(&source_lines, start_line);
        let is_public = is_public_fn(&signature, &name_text, lang);

        // Populate body_byte_range for C-style brace-delimited bodies.
        // Python uses indentation; body_byte_range is intentionally None.
        let fn_start_byte = fn_node_ts.start_byte();
        let body_byte_range = match lang {
            Lang::Python => None,
            _ => find_body_node(fn_node_ts).map(|body_node| {
                let inner_start = (body_node.start_byte() + 1).saturating_sub(fn_start_byte);
                let inner_end = body_node
                    .end_byte()
                    .saturating_sub(fn_start_byte)
                    .saturating_sub(1);
                (inner_start, inner_end)
            }),
        };

        Some(FunctionInfo {
            name: name_text,
            signature,
            body_source: fn_text.to_owned(),
            start_line,
            end_line: fn_node_ts.end_position().row + 1,
            is_strip_marked: is_strip,
            body_byte_range,
            doc_comment,
            is_public,
        })
    })
}

fn extract_classes(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &Lang,
    ts_lang: &Language,
) -> Result<Vec<ClassInfo>> {
    let query_str = match lang {
        Lang::Rust => {
            "[(struct_item name: (type_identifier) @name) @cls \
              (enum_item name: (type_identifier) @name) @cls \
              (impl_item type: (type_identifier) @name) @cls \
              (trait_item name: (type_identifier) @name) @cls]"
        }
        Lang::Python => "(class_definition name: (identifier) @name) @cls",
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            "(class_declaration name: (identifier) @name) @cls"
        }
        Lang::Java => {
            "[(class_declaration name: (identifier) @name) @cls \
              (interface_declaration name: (identifier) @name) @cls \
              (enum_declaration name: (identifier) @name) @cls \
              (record_declaration name: (identifier) @name) @cls \
              (annotation_type_declaration name: (identifier) @name) @cls]"
        }
        Lang::C => {
            // Named (tagged) struct / union / enum definitions.
            "[(struct_specifier name: (type_identifier) @name) @cls \
              (union_specifier  name: (type_identifier) @name) @cls \
              (enum_specifier   name: (type_identifier) @name) @cls]"
        }
        Lang::CSharp => {
            "[(class_declaration     name: (identifier) @name) @cls \
              (interface_declaration name: (identifier) @name) @cls \
              (struct_declaration    name: (identifier) @name) @cls \
              (enum_declaration      name: (identifier) @name) @cls]"
        }
        Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => return Ok(vec![]),
    };

    let source_lines: Vec<&str> = source.lines().collect();
    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let cls_node = caps.iter().find(|(n, _, _)| *n == "cls")?;
        let name_cap = caps.iter().find(|(n, _, _)| *n == "name")?;

        let ts_node = cls_node.1;
        let raw_kind = ts_node.kind();
        let kind = match raw_kind {
            "struct_item" => "struct",
            "enum_item" => "enum",
            "impl_item" => "impl",
            "trait_item" => "trait",
            "class_definition" | "class_declaration" => "class",
            "interface_declaration" => "interface",
            "enum_declaration" => "enum",
            "record_declaration" => "record",
            "annotation_type_declaration" => "@interface",
            // C
            "struct_specifier" => "struct",
            "union_specifier" => "union",
            "enum_specifier" => "enum",
            // C# (struct_declaration distinct from Rust struct_item)
            "struct_declaration" => "struct",
            _ => raw_kind,
        };

        let start_line = ts_node.start_position().row + 1;
        let doc_comment = extract_preceding_comment(&source_lines, start_line);
        let is_public = is_public_class(&source_lines, start_line, &name_cap.2, lang);

        Some(ClassInfo {
            name: name_cap.2.clone(),
            kind: kind.to_owned(),
            start_line,
            end_line: ts_node.end_position().row + 1,
            doc_comment,
            is_public,
        })
    })
}

fn extract_imports(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &Lang,
    ts_lang: &Language,
) -> Result<Vec<ImportInfo>> {
    let query_str = match lang {
        Lang::Rust => "(use_declaration) @import",
        Lang::Python => "[(import_statement) @import (import_from_statement) @import]",
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => "(import_statement) @import",
        Lang::Java => "(import_declaration) @import",
        Lang::C => "(preproc_include) @import",
        Lang::CSharp => "(using_directive) @import",
        Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => return Ok(vec![]),
    };

    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let imp = caps.iter().find(|(n, _, _)| *n == "import")?;
        let raw = source[imp.1.byte_range()].trim().to_owned();

        // Extract the module/package path, specialized by language
        let path = match lang {
            Lang::Rust => {
                // For Rust: `use foo::bar::baz;` → path is `foo::bar::baz`
                raw.trim_start_matches("use ")
                    .trim_end_matches(';')
                    .to_owned()
            }
            Lang::Python => {
                // For Python: `from pkg.mod import name` → extract `pkg.mod`
                // or `import pkg.mod` → extract `pkg.mod`
                extract_python_import_path(&raw)
            }
            Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
                // Prefer AST source field over brittle text parsing of 'from ...'
                if let Some(src_node) = imp.1.child_by_field_name("source") {
                    let quoted = source[src_node.byte_range()].trim();
                    quoted
                        .trim_matches(|c: char| c == '"' || c == '\'')
                        .to_owned()
                } else {
                    extract_js_import_path(&raw)
                }
            }
            Lang::Java => {
                // For Java: `import com.example.Service;` → path is `com.example.Service`
                raw.trim_start_matches("import ")
                    .trim_end_matches(';')
                    .to_owned()
            }
            Lang::C => {
                // `#include <stdio.h>` → `stdio.h`, `#include "foo.h"` → `foo.h`
                raw.trim_start_matches("#include")
                    .trim()
                    .trim_matches(|c: char| c == '<' || c == '>' || c == '"')
                    .to_owned()
            }
            Lang::CSharp => {
                // `using System.Collections.Generic;` → `System.Collections.Generic`
                // `using static System.Math;`         → `System.Math`
                raw.trim_start_matches("using")
                    .trim()
                    .trim_start_matches("static")
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .to_owned()
            }
            Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => raw.clone(),
        };

        Some(ImportInfo {
            raw,
            kind: classify_import_kind_from_path(&path, lang),
            path,
            resolved_path: None,
        })
    })
}

/// Classify an import path into a `ImportKind` using only the path string and
/// language heuristics (no file system access). The result may be refined
/// later when the file index is available.
pub(crate) fn classify_import_kind_from_path(path: &str, lang: &Lang) -> ImportKind {
    // Relative paths → likely a project-local file
    if path.starts_with("./") || path.starts_with("../") {
        return ImportKind::InternalLocal;
    }
    // Python relative: `from . import foo` or `from .utils import bar`
    if path.starts_with('.') {
        return ImportKind::InternalLocal;
    }
    // Rust project-local references
    if let Lang::Rust = lang {
        if path.starts_with("crate::") || path.starts_with("self::") || path.starts_with("super::")
        {
            return ImportKind::InternalLocal;
        }
    }
    // Everything else is treated as an external library (crate, npm, PyPI, …)
    ImportKind::ExternalLibrary
}
/// `from pkg.mod import name` → `pkg.mod`
/// `import pkg.mod` → `pkg.mod`
fn extract_python_import_path(import_stmt: &str) -> String {
    if import_stmt.starts_with("from ") {
        // "from pkg.mod import ..." → extract "pkg.mod"
        if let Some(from_part) = import_stmt.strip_prefix("from ") {
            if let Some(import_idx) = from_part.find(" import ") {
                return from_part[..import_idx].trim().to_owned();
            }
        }
    } else if import_stmt.starts_with("import ") {
        // "import pkg.mod" → extract "pkg.mod"
        return import_stmt
            .trim_start_matches("import ")
            .trim_end_matches(',')
            .trim()
            .to_owned();
    }
    import_stmt.to_owned()
}

/// Extract module path from a JS/TS import statement.
/// `import { foo } from './utils'` → `./utils`
/// `import foo from 'module'` → `module`
fn extract_js_import_path(import_stmt: &str) -> String {
    // Look for the `from '...'` or `from "..."` part
    if let Some(from_idx) = import_stmt.find("from") {
        let after_from = &import_stmt[from_idx + 4..];
        // Find the opening quote
        if let Some(quote_idx) = after_from.find(['\'', '"']) {
            let quote_char = after_from.chars().nth(quote_idx).unwrap();
            let start = quote_idx + 1;
            // Find the closing quote
            if let Some(end) = after_from[start..].find(quote_char) {
                return after_from[start..start + end].to_owned();
            }
        }
    }
    import_stmt.to_owned()
}

fn extract_strings(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &Lang,
    ts_lang: &Language,
) -> Result<Vec<StringLiteral>> {
    let query_str = match lang {
        Lang::Rust => {
            "[(string_literal) @str \
              (raw_string_literal) @str]"
        }
        Lang::Python => "(string) @str",
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => "(string) @str",
        Lang::Java => "(string_literal) @str",
        Lang::C => "(string_literal) @str",
        Lang::CSharp => "[(string_literal) @str (verbatim_string_literal) @str]",
        Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => return Ok(vec![]),
    };

    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let s = caps.iter().find(|(n, _, _)| *n == "str")?;
        Some(StringLiteral {
            value: source[s.1.byte_range()].to_owned(),
            line: s.1.start_position().row + 1,
        })
    })
}

// ---------------------------------------------------------------------------
// Query runner helper
// ---------------------------------------------------------------------------

/// Run a named tree-sitter query and map each match through `f`.
/// `f` receives `(match_index, Vec<(capture_name, Node, text)>)`.
fn run_named_query<T>(
    language: &Language,
    query_str: &str,
    root: tree_sitter::Node<'_>,
    source: &str,
    mut f: impl FnMut(usize, Vec<(String, tree_sitter::Node<'_>, String)>) -> Option<T>,
) -> Result<Vec<T>> {
    let query = Query::new(*language, query_str)
        .with_context(|| format!("Failed to compile tree-sitter query: {}", query_str))?;

    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, root, source.as_bytes());

    let mut results = Vec::new();

    for m in matches {
        let mut caps = Vec::new();
        for cap in m.captures {
            let node = cap.node;
            let name = query.capture_names()[cap.index as usize].clone();
            let text = source[node.byte_range()].to_owned();
            caps.push((name, node, text));
        }

        if let Some(res) = f(m.pattern_index, caps) {
            results.push(res);
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Detect `@mcp-strip` via AST comment nodes rather than full-text regex.
///
/// Checks only genuine comment nodes:
/// 1. The named sibling immediately preceding the function in the same scope.
/// 2. The children of the function body that precede the first real statement.
///
/// This prevents false positives when `@mcp-strip` appears inside a string
/// literal or in a distant comment unrelated to this function.
fn has_mcp_strip_in_ast(func_node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    const MARKER: &[u8] = b"@mcp-strip";

    // Case 1: comment node immediately preceding the function in the same scope
    if let Some(prev) = func_node.prev_named_sibling() {
        if prev.kind().contains("comment") {
            let text = &source[prev.start_byte()..prev.end_byte()];
            if text.windows(MARKER.len()).any(|w| w == MARKER) {
                return true;
            }
        }
    }

    // Case 2: scan leading children of the body block for a comment with @mcp-strip.
    // We iterate ALL children (named + anonymous) because Python treats `comment`
    // nodes as "extra" tokens — they may not appear at named_child(0).
    // We stop at the first real (named, non-comment) statement to avoid scanning
    // the entire body.
    if let Some(body) = func_node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind().contains("comment") {
                let text = &source[child.start_byte()..child.end_byte()];
                if text.windows(MARKER.len()).any(|w| w == MARKER) {
                    return true;
                }
            } else if child.is_named() {
                // First real statement found — stop scanning.
                break;
            }
        }
    }

    false
}

/// Find the block body of a function-like AST node.
///
/// Only returns nodes with kind `block` or `statement_block` — the
/// brace-delimited bodies — so that expression arrow functions
/// (`() => expr`) fall through to the text-based fallback.
/// Also handles `variable_declarator` wrapping `arrow_function` /
/// `function_expression` by diving into the `value` field.
fn find_body_node(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let body = node.child_by_field_name("body").or_else(|| {
        // variable_declarator: look inside the arrow/function_expression value
        node.child_by_field_name("value")
            .and_then(|val| val.child_by_field_name("body"))
    })?;

    // Only block-style bodies delimit signatures reliably.
    // `compound_statement` is the C/C++ equivalent of `block`.
    if matches!(
        body.kind(),
        "block" | "statement_block" | "compound_statement"
    ) {
        Some(body)
    } else {
        None
    }
}

/// Extract function signature (text before the opening brace / body).
pub fn extract_signature(fn_source: &str) -> String {
    if let Some(pos) = fn_source.find('{') {
        fn_source[..pos].trim().to_owned()
    } else {
        // Python: find the last ':' that's followed by a newline (body start)
        // This avoids cutting at type hint colons like `def foo(x: int) -> str:`
        let mut depth = 0i32; // track parenthesis nesting
        for (i, ch) in fn_source.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ':' if depth == 0 => {
                    return fn_source[..=i].trim().to_owned();
                }
                _ => {}
            }
        }
        fn_source.trim().to_owned()
    }
}

// ---------------------------------------------------------------------------
// Doc comment and visibility helpers
// ---------------------------------------------------------------------------

/// Extract the doc-comment block immediately preceding the given 1-based line.
///
/// Walks backwards from `before_line - 1`, collecting contiguous comment lines.
/// Stops at the first blank or non-comment line. Returns `None` if nothing found.
///
/// Recognised prefixes: `///`, `//!`, `//`, `#` (Python), `/**`, `/*`, ` *`.
/// This is intentionally line-based rather than AST-based because tree-sitter
/// does not guarantee adjacency between a `line_comment` node and the
/// following declaration.
pub fn extract_preceding_comment(lines: &[&str], before_line: usize) -> Option<String> {
    if before_line < 2 || before_line > lines.len() {
        return None;
    }
    let mut collected: Vec<&str> = Vec::new();
    let mut i = before_line - 1; // start one position above (0-based)
    while i > 0 {
        i -= 1;
        let trimmed = lines[i].trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with("///")
            || trimmed.starts_with("//!")
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/**")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            collected.push(lines[i]);
        } else {
            break;
        }
    }
    if collected.is_empty() {
        return None;
    }
    collected.reverse();
    Some(collected.join("\n"))
}

/// Extract the module-level / file-level documentation comment.
///
/// - **Rust**: consecutive `//!` lines at the top of the file.
/// - **Python**: first triple-quoted string (`"""` or `'''`) at the top.
/// - **Java / TypeScript / JavaScript**: `/** … */` block before the first
///   non-comment token.
/// - All other languages: `None`.
pub fn extract_module_doc(source: &str, lang: &Lang) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    match lang {
        Lang::Rust => {
            let doc_lines: Vec<&str> = lines
                .iter()
                .take_while(|l| {
                    let t = l.trim();
                    t.starts_with("//!") || t.is_empty()
                })
                .filter(|l| l.trim().starts_with("//!"))
                .copied()
                .collect();
            if doc_lines.is_empty() {
                None
            } else {
                Some(doc_lines.join("\n"))
            }
        }
        Lang::Python => {
            let first = lines.iter().position(|l| !l.trim().is_empty())?;
            let trimmed = lines[first].trim();
            let quote = if trimmed.starts_with("\"\"\"") {
                "\"\"\""
            } else if trimmed.starts_with("'''") {
                "'''"
            } else {
                return None;
            };
            let mut doc = vec![lines[first]];
            // Single-line docstring closes on the same line after the opening
            let rest_of_first = trimmed.get(3..).unwrap_or("");
            if rest_of_first.contains(quote) {
                return Some(doc.join("\n"));
            }
            for line in lines.iter().skip(first + 1) {
                doc.push(line);
                if line.contains(quote) {
                    break;
                }
            }
            Some(doc.join("\n"))
        }
        Lang::Java | Lang::TypeScript | Lang::Tsx | Lang::JavaScript => {
            let first = lines.iter().position(|l| !l.trim().is_empty())?;
            let trimmed = lines[first].trim();
            if !trimmed.starts_with("/**") && !trimmed.starts_with("/*") {
                return None;
            }
            let mut doc = vec![lines[first]];
            if !trimmed.contains("*/") {
                for line in lines.iter().skip(first + 1) {
                    doc.push(line);
                    if line.contains("*/") {
                        break;
                    }
                }
            }
            Some(doc.join("\n"))
        }
        _ => None,
    }
}

/// Determine if a function is publicly visible (language-aware heuristic).
///
/// For languages with no visibility keyword (C), returns `true` by convention.
/// TypeScript/JS use `export` presence and absence of `private` keyword.
fn is_public_fn(signature: &str, name: &str, lang: &Lang) -> bool {
    match lang {
        Lang::Rust => signature.starts_with("pub ") || signature.starts_with("pub("),
        Lang::Java => signature.contains("public "),
        Lang::Python => !name.starts_with('_'),
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            !name.starts_with('_') && !signature.contains("private ") && !signature.contains("#")
            // JS private fields (#name)
        }
        Lang::CSharp => signature.contains("public "),
        Lang::C => true,
        _ => true,
    }
}

/// Determine if a type definition is publicly visible (language-aware heuristic).
///
/// Examines the source line at `start_line` (1-based) for visibility modifiers.
fn is_public_class(source_lines: &[&str], start_line: usize, name: &str, lang: &Lang) -> bool {
    let line_text = if start_line > 0 && start_line <= source_lines.len() {
        source_lines[start_line - 1].trim()
    } else {
        ""
    };
    match lang {
        Lang::Rust => line_text.starts_with("pub ") || line_text.starts_with("pub("),
        Lang::Java => line_text.contains("public "),
        Lang::Python => !name.starts_with('_'),
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            !name.starts_with('_') && !line_text.contains("private ")
        }
        Lang::CSharp => line_text.contains("public "),
        Lang::C => true,
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Design-pattern heuristics (Phase 3 / Tool 5)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
pub struct PatternMatch {
    pub pattern: String,
    pub evidence: String,
    pub file: String,
    pub line: usize,
}

/// Run heuristic checks against a `FileAnalysis` to find common design patterns.
pub fn detect_patterns(analysis: &FileAnalysis, file_path: &str) -> Vec<PatternMatch> {
    let mut found = Vec::new();

    let fn_names: Vec<&str> = analysis.functions.iter().map(|f| f.name.as_str()).collect();

    // Singleton — static INSTANCE field + get_instance / instance / singleton
    if fn_names.iter().any(|n| {
        matches!(
            *n,
            "instance" | "get_instance" | "singleton" | "getInstance"
        )
    }) {
        found.push(PatternMatch {
            pattern: "Singleton".to_owned(),
            evidence: "Found instance() / get_instance() / getInstance() method".to_owned(),
            file: file_path.to_owned(),
            line: analysis
                .functions
                .iter()
                .find(|f| {
                    matches!(
                        f.name.as_str(),
                        "instance" | "get_instance" | "singleton" | "getInstance"
                    )
                })
                .map(|f| f.start_line)
                .unwrap_or(0),
        });
    }

    // Builder — fn build(self) + multiple fn with_*
    let with_count = fn_names.iter().filter(|n| n.starts_with("with_")).count();
    let has_build = fn_names.iter().any(|n| *n == "build" || *n == "finish");
    if with_count >= 2 && has_build {
        found.push(PatternMatch {
            pattern: "Builder".to_owned(),
            evidence: format!("{} with_*() methods + build()/finish() method", with_count),
            file: file_path.to_owned(),
            line: analysis
                .functions
                .iter()
                .find(|f| f.name.starts_with("with_"))
                .map(|f| f.start_line)
                .unwrap_or(0),
        });
    }

    // Factory — class/struct named *Factory or create_*/make_* functions
    let factory_class = analysis
        .classes
        .iter()
        .any(|c| c.name.to_lowercase().contains("factory"));
    let create_fns = fn_names
        .iter()
        .filter(|n| n.starts_with("create_") || n.starts_with("make_") || n.starts_with("new_"))
        .count();
    if factory_class || create_fns >= 2 {
        found.push(PatternMatch {
            pattern: "Factory".to_owned(),
            evidence: if factory_class {
                "Found *Factory class".to_owned()
            } else {
                format!("{} create_*/make_*/new_*() methods", create_fns)
            },
            file: file_path.to_owned(),
            line: 0,
        });
    }

    // Observer — subscribe/unsubscribe/notify/on_* methods
    let has_subscribe = fn_names
        .iter()
        .any(|n| *n == "subscribe" || *n == "register");
    let has_notify = fn_names
        .iter()
        .any(|n| *n == "notify" || *n == "emit" || *n == "publish" || *n == "dispatch");
    if has_subscribe && has_notify {
        found.push(PatternMatch {
            pattern: "Observer".to_owned(),
            evidence: "Found subscribe()/register() + notify()/emit() methods".to_owned(),
            file: file_path.to_owned(),
            line: 0,
        });
    }

    // Repository — find_*/save/delete methods grouped in a struct/class
    let find_count = fn_names
        .iter()
        .filter(|n| n.starts_with("find_") || n.starts_with("get_by"))
        .count();
    let has_save = fn_names
        .iter()
        .any(|n| *n == "save" || *n == "insert" || *n == "persist");
    let has_delete = fn_names.iter().any(|n| *n == "delete" || *n == "remove");
    if find_count >= 1 && has_save && has_delete {
        found.push(PatternMatch {
            pattern: "Repository".to_owned(),
            evidence: format!(
                "{} find_*()/get_by_*() + save() + delete() methods",
                find_count
            ),
            file: file_path.to_owned(),
            line: 0,
        });
    }

    // Strategy — trait/interface + multiple implementations named *Strategy
    let has_strategy_name = analysis
        .classes
        .iter()
        .any(|c| c.name.to_lowercase().contains("strategy"));
    if has_strategy_name {
        found.push(PatternMatch {
            pattern: "Strategy".to_owned(),
            evidence: "Found class/struct/trait with 'Strategy' in name".to_owned(),
            file: file_path.to_owned(),
            line: analysis
                .classes
                .iter()
                .find(|c| c.name.to_lowercase().contains("strategy"))
                .map(|c| c.start_line)
                .unwrap_or(0),
        });
    }

    found
}

// ---------------------------------------------------------------------------
// CSS parser
// ---------------------------------------------------------------------------

fn parse_css_file(source: &str) -> Result<FileAnalysis> {
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_css::language())
        .context("Failed to set tree-sitter CSS language")?;
    let tree = parser
        .parse(source, None)
        .context("tree-sitter-css failed to produce a parse tree")?;

    let root = tree.root_node();
    let mut rules = Vec::new();
    collect_css_rule_sets(root, source, &mut rules, None);

    Ok(FileAnalysis {
        language: "css".to_owned(),
        css_rules: Some(rules),
        ..Default::default()
    })
}

fn collect_css_rule_sets(
    node: tree_sitter::Node<'_>,
    source: &str,
    rules: &mut Vec<CssRuleInfo>,
    media_query: Option<String>,
) {
    match node.kind() {
        "rule_set" => {
            let mut selector = String::new();
            let mut properties = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "selectors" => {
                        selector = source[child.byte_range()].trim().to_owned();
                    }
                    "block" => {
                        let mut block_cursor = child.walk();
                        for block_child in child.children(&mut block_cursor) {
                            if block_child.kind() == "declaration" {
                                if let Some(prop) = extract_css_property_name(block_child, source) {
                                    properties.push(prop);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if !selector.is_empty() {
                rules.push(CssRuleInfo {
                    selector,
                    properties,
                    media_query: media_query.clone(),
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                });
            }
        }
        "media_statement" => {
            // Extract the condition between "@media" and the first "{"
            let raw = &source[node.byte_range()];
            let media_text = raw
                .find("@media")
                .and_then(|start| {
                    let after = &raw[start + "@media".len()..];
                    after.find('{').map(|end| after[..end].trim().to_owned())
                })
                .unwrap_or_default();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_css_rule_sets(child, source, rules, Some(media_text.clone()));
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_css_rule_sets(child, source, rules, media_query.clone());
            }
        }
    }
}

fn extract_css_property_name(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    // Try field name first (tree-sitter-css uses a "property_name" field)
    if let Some(prop_node) = node.child_by_field_name("property_name") {
        let text = source[prop_node.byte_range()].trim().to_owned();
        if !text.is_empty() {
            return Some(text);
        }
    }
    // Fallback: take raw text before the first ':'
    let raw = source[node.byte_range()].trim();
    raw.find(':')
        .map(|i| raw[..i].trim().to_owned())
        .filter(|s| !s.is_empty() && !s.contains('{') && !s.contains('}'))
}

// ---------------------------------------------------------------------------
// HTML parser
// ---------------------------------------------------------------------------

fn parse_html_file(source: &str) -> Result<FileAnalysis> {
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_html::language())
        .context("Failed to set tree-sitter HTML language")?;
    let tree = parser
        .parse(source, None)
        .context("tree-sitter-html failed to produce a parse tree")?;

    let root = tree.root_node();
    let mut elements = Vec::new();
    collect_html_elements(root, source, &mut elements);

    Ok(FileAnalysis {
        language: "html".to_owned(),
        html_elements: Some(elements),
        ..Default::default()
    })
}

fn collect_html_elements(
    node: tree_sitter::Node<'_>,
    source: &str,
    elements: &mut Vec<HtmlElementInfo>,
) {
    let kind = node.kind();
    if kind == "start_tag" || kind == "self_closing_tag" {
        let mut tag_name = String::new();
        let mut class_names = Vec::new();
        let mut input_bindings = Vec::new();
        let mut output_bindings = Vec::new();

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "tag_name" => {
                    tag_name = source[child.byte_range()].to_owned();
                }
                "attribute" => {
                    parse_html_attribute(
                        child,
                        source,
                        &mut class_names,
                        &mut input_bindings,
                        &mut output_bindings,
                    );
                }
                _ => {}
            }
        }
        if !tag_name.is_empty() {
            elements.push(HtmlElementInfo {
                is_angular_component: is_angular_component(&tag_name),
                tag_name,
                class_names,
                input_bindings,
                output_bindings,
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
            });
        }
    }
    // Always recurse
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_html_elements(child, source, elements);
    }
}

fn parse_html_attribute(
    node: tree_sitter::Node<'_>,
    source: &str,
    class_names: &mut Vec<String>,
    input_bindings: &mut Vec<String>,
    output_bindings: &mut Vec<String>,
) {
    let mut attr_name = String::new();
    let mut attr_value = String::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "attribute_name" => {
                attr_name = source[child.byte_range()].to_owned();
            }
            "quoted_attribute_value" => {
                let mut val_cursor = child.walk();
                for val_child in child.children(&mut val_cursor) {
                    if val_child.kind() == "attribute_value" {
                        attr_value = source[val_child.byte_range()].to_owned();
                    }
                }
            }
            _ => {}
        }
    }
    if attr_name.is_empty() {
        return;
    }
    if attr_name.starts_with('[') && attr_name.ends_with(']') {
        let inner = &attr_name[1..attr_name.len() - 1];
        if let Some(stripped) = inner.strip_prefix("class.") {
            // Angular class binding: [class.active]="condition"
            class_names.push(stripped.to_owned());
        } else {
            input_bindings.push(inner.to_owned());
        }
    } else if attr_name.starts_with('(') && attr_name.ends_with(')') {
        // Angular event binding: (click)="handler()"
        let event = &attr_name[1..attr_name.len() - 1];
        output_bindings.push(event.to_owned());
    } else if attr_name == "class" && !attr_value.is_empty() {
        class_names.extend(attr_value.split_whitespace().map(str::to_owned));
    }
}

/// Heuristic: custom Angular component selectors contain a hyphen and are not
/// a known HTML built-in element that happens to contain a hyphen.
fn is_angular_component(tag: &str) -> bool {
    tag.contains('-')
        && !matches!(
            tag,
            "accept-charset"
                | "annotation-xml"
                | "color-profile"
                | "font-face"
                | "font-face-src"
                | "font-face-uri"
                | "font-face-format"
                | "font-face-name"
                | "missing-glyph"
        )
}

// ---------------------------------------------------------------------------
// Doc-generation helpers: entrypoint detection & use-case inference
// ---------------------------------------------------------------------------

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
    pub file: std::path::PathBuf,
    /// Name of the entry symbol when applicable (e.g. `"main"`, `"__main__"`).
    pub symbol: Option<String>,
    /// Signature string when available.
    pub signature: Option<String>,
}

/// Scan `analyses` and return detected entrypoints.
///
/// Operates entirely on data already in memory — no new I/O or parsing.
pub fn detect_entrypoints(analyses: &[(std::path::PathBuf, FileAnalysis)]) -> Vec<Entrypoint> {
    const CLI_MARKERS: &[(&str, &str)] = &[
        ("clap", "clap"),
        ("structopt", "structopt"),
        ("argparse", "argparse"),
        ("click", "click"),
        ("typer", "typer"),
        ("commander", "commander"),
        ("yargs", "yargs"),
        ("picocli", "picocli"),
        ("commons-cli", "commons-cli"),
    ];

    const HTTP_MARKERS: &[(&str, &str)] = &[
        ("actix_web", "actix-web"),
        ("actix-web", "actix-web"),
        ("axum", "axum"),
        ("warp", "warp"),
        ("rocket", "rocket"),
        ("fastapi", "fastapi"),
        ("flask", "flask"),
        ("django", "django"),
        ("express", "express"),
        ("fastify", "fastify"),
        ("springframework", "spring-boot"),
        ("spring-boot", "spring-boot"),
        ("quarkus", "quarkus"),
        ("hyper", "hyper"),
    ];

    let mut result: Vec<Entrypoint> = Vec::new();
    let mut found_main = false;
    let mut has_public_api = false;
    let mut cli_found = false;
    let mut http_found = false;

    for (path, analysis) in analyses {
        // Main function
        for func in &analysis.functions {
            if func.name == "main" {
                found_main = true;
                result.push(Entrypoint {
                    kind: EntrypointKind::MainFunction,
                    file: path.clone(),
                    symbol: Some("main".to_owned()),
                    signature: Some(func.signature.clone()),
                });
                break;
            }
        }

        // Python __main__ sentinel (appears as a string literal `"__main__"`)
        if analysis.language == "python" {
            for lit in &analysis.string_literals {
                if lit.value == "__main__" {
                    found_main = true;
                    result.push(Entrypoint {
                        kind: EntrypointKind::MainFunction,
                        file: path.clone(),
                        symbol: Some("__main__".to_owned()),
                        signature: None,
                    });
                    break;
                }
            }
        }

        // Framework detection via imports
        for imp in &analysis.imports {
            let imp_lower = imp.path.to_lowercase();
            if !cli_found {
                for (marker, name) in CLI_MARKERS {
                    if imp_lower.contains(marker) {
                        cli_found = true;
                        result.push(Entrypoint {
                            kind: EntrypointKind::CliFramework((*name).to_owned()),
                            file: path.clone(),
                            symbol: None,
                            signature: None,
                        });
                        break;
                    }
                }
            }
            if !http_found {
                for (marker, name) in HTTP_MARKERS {
                    if imp_lower.contains(marker) {
                        http_found = true;
                        result.push(Entrypoint {
                            kind: EntrypointKind::HttpFramework((*name).to_owned()),
                            file: path.clone(),
                            symbol: None,
                            signature: None,
                        });
                        break;
                    }
                }
            }
        }

        if analysis.functions.iter().any(|f| f.is_public)
            || analysis.classes.iter().any(|c| c.is_public)
        {
            has_public_api = true;
        }
    }

    // No main found but public API exists → library
    if !found_main && has_public_api && result.is_empty() {
        result.push(Entrypoint {
            kind: EntrypointKind::LibraryCrate,
            file: std::path::PathBuf::new(),
            symbol: None,
            signature: None,
        });
    }

    result
}

// ---------------------------------------------------------------------------

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

/// Infer practical use cases from public API names and doc-comments.
///
/// Strategy:
/// 1. **High** — doc-comment lines containing action verbs (`allows`, `enables`, …).
/// 2. **Medium** — public functions grouped by semantic name prefix (`create_*`, …),
///    groups of ≥ 2 functions.
///
/// Low-confidence items are kept only when nothing better was found.
pub fn infer_use_cases(analyses: &[(std::path::PathBuf, FileAnalysis)]) -> Vec<InferredUseCase> {
    const VERB_PREFIXES: &[(&str, &str)] = &[
        ("create_", "Creating"),
        ("new_", "Creating"),
        ("build_", "Building"),
        ("generate_", "Generating"),
        ("parse_", "Parsing"),
        ("read_", "Reading"),
        ("load_", "Loading"),
        ("write_", "Writing"),
        ("save_", "Saving"),
        ("export_", "Exporting"),
        ("import_", "Importing"),
        ("validate_", "Validating"),
        ("check_", "Checking"),
        ("verify_", "Verifying"),
        ("search_", "Searching"),
        ("find_", "Finding"),
        ("query_", "Querying"),
        ("get_", "Retrieving"),
        ("fetch_", "Fetching"),
        ("send_", "Sending"),
        ("process_", "Processing"),
        ("handle_", "Handling"),
        ("convert_", "Converting"),
        ("transform_", "Transforming"),
        ("analyze_", "Analyzing"),
        ("audit_", "Auditing"),
        ("inspect_", "Inspecting"),
        ("refresh_", "Refreshing"),
        ("update_", "Updating"),
        ("delete_", "Deleting"),
        ("remove_", "Removing"),
    ];

    const DOC_VERBS: &[&str] = &[
        "use this",
        "useful for",
        "allows",
        "enables",
        "use when",
        "use it to",
        "can be used",
        "is used to",
        "provides",
        "supports",
    ];

    let mut use_cases: Vec<InferredUseCase> = Vec::new();

    // --- Pass 1: High confidence — explicit doc-comment phrases ---
    for (_, analysis) in analyses {
        for func in &analysis.functions {
            if !func.is_public {
                continue;
            }
            if let Some(ref doc) = func.doc_comment {
                let doc_lower = doc.to_lowercase();
                for verb in DOC_VERBS {
                    if doc_lower.contains(verb) {
                        let sentence = doc
                            .lines()
                            .find(|l| l.to_lowercase().contains(verb))
                            .map(|l| {
                                l.trim()
                                    .trim_start_matches("///")
                                    .trim_start_matches("//")
                                    .trim_start_matches('#')
                                    .trim()
                                    .to_owned()
                            })
                            .unwrap_or_default();

                        if sentence.len() > 10 {
                            let already = use_cases.iter().any(|uc| {
                                uc.confidence == UseCaseConfidence::High
                                    && uc.functions.contains(&func.name)
                            });
                            if !already {
                                use_cases.push(InferredUseCase {
                                    title: format!("Using `{}`", func.name),
                                    description: sentence,
                                    functions: vec![func.name.clone()],
                                    confidence: UseCaseConfidence::High,
                                });
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    // --- Pass 2: Medium confidence — function name prefix grouping ---
    {
        use std::collections::HashMap;
        let mut prefix_groups: HashMap<&str, Vec<String>> = HashMap::new();

        for (_, analysis) in analyses {
            for func in &analysis.functions {
                if !func.is_public {
                    continue;
                }
                for (prefix, _) in VERB_PREFIXES {
                    if func.name.starts_with(prefix) {
                        prefix_groups
                            .entry(prefix)
                            .or_default()
                            .push(func.name.clone());
                        break;
                    }
                }
            }
        }

        for (prefix, fns) in &prefix_groups {
            if fns.len() < 2 {
                continue;
            }
            let label = VERB_PREFIXES
                .iter()
                .find(|(p, _)| p == prefix)
                .map(|(_, l)| *l)
                .unwrap_or("Working with");

            let already_covered = use_cases.iter().any(|uc| {
                uc.confidence == UseCaseConfidence::High
                    && uc.functions.iter().any(|f| fns.contains(f))
            });
            if already_covered {
                continue;
            }

            let sample: Vec<&str> = fns.iter().take(3).map(String::as_str).collect();
            use_cases.push(InferredUseCase {
                title: format!("{} data", label),
                description: format!(
                    "Functions such as `{}` provide {} capabilities.",
                    sample.join("`, `"),
                    label.to_lowercase()
                ),
                functions: fns.clone(),
                confidence: UseCaseConfidence::Medium,
            });
        }
    }

    // Sort High → Medium → Low; truncate to 8
    use_cases.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    use_cases.truncate(8);

    use_cases
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_detect_language() {
        use std::path::PathBuf;
        assert!(matches!(
            detect_language(&PathBuf::from("foo.css")),
            Lang::Css
        ));
        assert!(matches!(
            detect_language(&PathBuf::from("foo.scss")),
            Lang::Scss
        ));
        assert!(matches!(
            detect_language(&PathBuf::from("foo.html")),
            Lang::Html
        ));
        assert!(matches!(
            detect_language(&PathBuf::from("foo.htm")),
            Lang::Html
        ));
    }

    #[test]
    fn test_parse_css_basic() {
        let source = ".btn { color: red; background: blue; }\n.container { padding: 16px; }";
        let result = parse_css_file(source).expect("CSS parse failed");
        assert_eq!(result.language, "css");
        let rules = result.css_rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].selector, ".btn");
        assert!(rules[0].properties.contains(&"color".to_owned()));
        assert!(rules[0].properties.contains(&"background".to_owned()));
        assert_eq!(rules[1].selector, ".container");
    }

    #[test]
    fn test_parse_css_media_query() {
        let source = "@media (max-width: 768px) { .hero { display: none; } }";
        let result = parse_css_file(source).expect("CSS media parse failed");
        let rules = result.css_rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].selector, ".hero");
        assert!(rules[0].media_query.is_some());
    }

    #[test]
    fn test_parse_html_basic() {
        let source = r#"<div class="hero-container"><button (click)="save()">Save</button></div>"#;
        let result = parse_html_file(source).expect("HTML parse failed");
        assert_eq!(result.language, "html");
        let elements = result.html_elements.unwrap();
        let div = elements
            .iter()
            .find(|e| e.tag_name == "div")
            .expect("No div");
        assert!(div.class_names.contains(&"hero-container".to_owned()));
        let btn = elements
            .iter()
            .find(|e| e.tag_name == "button")
            .expect("No button");
        assert!(btn.output_bindings.contains(&"click".to_owned()));
    }

    #[test]
    fn test_html_angular_component_detection() {
        let source = r#"<app-header [title]="pageTitle"></app-header>"#;
        let result = parse_html_file(source).expect("HTML parse failed");
        let elements = result.html_elements.unwrap();
        let comp = elements.iter().find(|e| e.tag_name == "app-header");
        assert!(comp.is_some(), "app-header not found");
        let comp = comp.unwrap();
        assert!(comp.is_angular_component);
        assert!(comp.input_bindings.contains(&"title".to_owned()));
    }

    #[test]
    fn test_is_angular_component() {
        assert!(is_angular_component("app-header"));
        assert!(is_angular_component("my-custom-element"));
        assert!(!is_angular_component("div"));
        assert!(!is_angular_component("font-face")); // SVG built-in
    }

    #[test]
    fn test_scss_returns_empty_analysis() {
        // SCSS files are detected but not parsed — we just record the language
        use std::path::PathBuf;
        assert!(matches!(
            detect_language(&PathBuf::from("app.scss")),
            Lang::Scss
        ));
    }

    // -----------------------------------------------------------------------
    // Tests for get_module_summary helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_preceding_comment_rust_triple_slash() {
        let src = "/// Initialises the server.\n/// Returns an error if root is invalid.\npub fn init() {}";
        let lines: Vec<&str> = src.lines().collect();
        // fn is on line 3 (1-based)
        let doc = extract_preceding_comment(&lines, 3);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert!(doc.contains("Initialises the server."));
        assert!(doc.contains("Returns an error"));
    }

    #[test]
    fn test_extract_preceding_comment_none_when_no_comment() {
        let src = "\npub fn foo() {}";
        let lines: Vec<&str> = src.lines().collect();
        // fn is on line 2, but line 1 is blank → no comment
        let doc = extract_preceding_comment(&lines, 2);
        assert!(doc.is_none());
    }

    #[test]
    fn test_extract_preceding_comment_on_first_line() {
        let src = "pub fn foo() {}";
        let lines: Vec<&str> = src.lines().collect();
        // before_line = 1 → nothing above it
        let doc = extract_preceding_comment(&lines, 1);
        assert!(doc.is_none());
    }

    #[test]
    fn test_extract_preceding_comment_python_hash() {
        let src = "# Compute the checksum.\ndef checksum(data):\n    pass";
        let lines: Vec<&str> = src.lines().collect();
        let doc = extract_preceding_comment(&lines, 2);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Compute the checksum"));
    }

    #[test]
    fn test_extract_preceding_comment_java_block() {
        let src = "/**\n * Parses the request body.\n */\npublic void parse() {}";
        let lines: Vec<&str> = src.lines().collect();
        let doc = extract_preceding_comment(&lines, 4);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert!(doc.contains("/**"));
        assert!(doc.contains("Parses the request body."));
    }

    #[test]
    fn test_extract_module_doc_rust() {
        let src = "//! Top-level module doc.\n//! More info.\n\nuse std::io;";
        let doc = extract_module_doc(src, &Lang::Rust);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert!(doc.contains("Top-level module doc."));
        assert!(doc.contains("More info."));
    }

    #[test]
    fn test_extract_module_doc_rust_no_inner_doc() {
        let src = "// Regular comment\npub fn foo() {}";
        let doc = extract_module_doc(src, &Lang::Rust);
        assert!(doc.is_none());
    }

    #[test]
    fn test_extract_module_doc_python_triple_quote() {
        let src = "\"\"\"\nThis module handles authentication.\n\"\"\"\n\ndef login(): pass";
        let doc = extract_module_doc(src, &Lang::Python);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("authentication"));
    }

    #[test]
    fn test_extract_module_doc_python_single_line() {
        let src = "\"\"\"Short module doc.\"\"\"\ndef foo(): pass";
        let doc = extract_module_doc(src, &Lang::Python);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Short module doc."));
    }

    #[test]
    fn test_is_public_fn_rust() {
        assert!(is_public_fn("pub fn dispatch()", "dispatch", &Lang::Rust));
        assert!(!is_public_fn("fn internal()", "internal", &Lang::Rust));
        assert!(is_public_fn("pub(crate) fn semi()", "semi", &Lang::Rust));
    }

    #[test]
    fn test_is_public_fn_python_underscore() {
        assert!(is_public_fn("def process(data):", "process", &Lang::Python));
        assert!(!is_public_fn("def _helper():", "_helper", &Lang::Python));
        assert!(!is_public_fn(
            "def __init__(self):",
            "__init__",
            &Lang::Python
        ));
    }

    #[test]
    fn test_is_public_fn_java() {
        assert!(is_public_fn("public void serve()", "serve", &Lang::Java));
        assert!(!is_public_fn("private void serve()", "serve", &Lang::Java));
        assert!(!is_public_fn(
            "protected void serve()",
            "serve",
            &Lang::Java
        ));
    }

    #[test]
    fn test_is_public_class_rust() {
        let lines = vec!["pub struct Config {", "    field: u32,", "}"];
        assert!(is_public_class(&lines, 1, "Config", &Lang::Rust));

        let lines2 = vec!["struct Internal {", "}"];
        assert!(!is_public_class(&lines2, 1, "Internal", &Lang::Rust));
    }

    #[test]
    fn test_extract_preceding_comment_stops_at_blank_line() {
        // Only the last comment block (no blank between it and the fn) should be captured
        let src = "/// Old comment\n\n/// Real doc.\nfn foo() {}";
        let lines: Vec<&str> = src.lines().collect();
        // fn is on line 4
        let doc = extract_preceding_comment(&lines, 4);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        // Must NOT include "Old comment" (it's separated by a blank line)
        assert!(!doc.contains("Old comment"));
        assert!(doc.contains("Real doc."));
    }

    // --- detect_entrypoints tests ---

    fn make_analysis(
        language: &str,
        functions: Vec<FunctionInfo>,
        imports: Vec<ImportInfo>,
    ) -> FileAnalysis {
        FileAnalysis {
            language: language.to_owned(),
            functions,
            imports,
            ..Default::default()
        }
    }

    fn make_fn(name: &str, is_public: bool) -> FunctionInfo {
        FunctionInfo {
            name: name.to_owned(),
            signature: format!("pub fn {}()", name),
            body_source: String::new(),
            start_line: 1,
            end_line: 3,
            is_strip_marked: false,
            body_byte_range: None,
            doc_comment: None,
            is_public,
        }
    }

    fn make_import(path: &str) -> ImportInfo {
        ImportInfo {
            raw: path.to_owned(),
            path: path.to_owned(),
            kind: ImportKind::ExternalLibrary,
            resolved_path: None,
        }
    }

    #[test]
    fn test_detect_main_function_rust() {
        use std::path::PathBuf;
        let analysis = make_analysis("rust", vec![make_fn("main", false)], vec![]);
        let analyses = vec![(PathBuf::from("src/main.rs"), analysis)];
        let entrypoints = detect_entrypoints(&analyses);
        assert_eq!(entrypoints.len(), 1);
        assert_eq!(entrypoints[0].kind, EntrypointKind::MainFunction);
        assert_eq!(entrypoints[0].symbol, Some("main".to_owned()));
    }

    #[test]
    fn test_detect_clap_from_imports() {
        use std::path::PathBuf;
        let analysis = make_analysis(
            "rust",
            vec![make_fn("run", true)],
            vec![make_import("clap::Parser")],
        );
        let analyses = vec![(PathBuf::from("src/cli.rs"), analysis)];
        let entrypoints = detect_entrypoints(&analyses);
        assert!(entrypoints
            .iter()
            .any(|e| matches!(&e.kind, EntrypointKind::CliFramework(n) if n == "clap")));
    }

    #[test]
    fn test_detect_http_framework_from_imports() {
        use std::path::PathBuf;
        let analysis = make_analysis(
            "rust",
            vec![make_fn("serve", true)],
            vec![make_import("axum::Router")],
        );
        let analyses = vec![(PathBuf::from("src/server.rs"), analysis)];
        let entrypoints = detect_entrypoints(&analyses);
        assert!(entrypoints
            .iter()
            .any(|e| matches!(&e.kind, EntrypointKind::HttpFramework(n) if n == "axum")));
    }

    #[test]
    fn test_detect_library_crate_no_main() {
        use std::path::PathBuf;
        let analysis = make_analysis("rust", vec![make_fn("parse_config", true)], vec![]);
        let analyses = vec![(PathBuf::from("src/lib.rs"), analysis)];
        let entrypoints = detect_entrypoints(&analyses);
        assert_eq!(entrypoints.len(), 1);
        assert_eq!(entrypoints[0].kind, EntrypointKind::LibraryCrate);
    }

    #[test]
    fn test_detect_nothing_when_no_signals() {
        use std::path::PathBuf;
        // Only private functions, no imports, no main
        let analysis = make_analysis("rust", vec![make_fn("internal_helper", false)], vec![]);
        let analyses = vec![(PathBuf::from("src/lib.rs"), analysis)];
        let entrypoints = detect_entrypoints(&analyses);
        assert!(entrypoints.is_empty());
    }

    // --- infer_use_cases tests ---

    fn make_fn_with_doc(name: &str, doc: &str) -> FunctionInfo {
        let mut f = make_fn(name, true);
        f.doc_comment = Some(doc.to_owned());
        f
    }

    #[test]
    fn test_infer_use_case_from_doc_comment_verb() {
        use std::path::PathBuf;
        let analysis = make_analysis(
            "rust",
            vec![make_fn_with_doc(
                "send_notification",
                "/// allows sending push notifications to registered users",
            )],
            vec![],
        );
        let analyses = vec![(PathBuf::from("src/notif.rs"), analysis)];
        let cases = infer_use_cases(&analyses);
        assert!(!cases.is_empty());
        assert_eq!(cases[0].confidence, UseCaseConfidence::High);
        assert!(cases[0].description.contains("allows"));
    }

    #[test]
    fn test_group_by_function_name_prefix() {
        use std::path::PathBuf;
        let analysis = make_analysis(
            "rust",
            vec![
                make_fn("parse_json", true),
                make_fn("parse_yaml", true),
                make_fn("parse_toml", true),
            ],
            vec![],
        );
        let analyses = vec![(PathBuf::from("src/parser.rs"), analysis)];
        let cases = infer_use_cases(&analyses);
        assert!(!cases.is_empty());
        let parsing_case = cases
            .iter()
            .find(|c| c.title.contains("Parsing") || c.description.contains("parsing"));
        assert!(parsing_case.is_some());
        assert_eq!(parsing_case.unwrap().confidence, UseCaseConfidence::Medium);
    }

    #[test]
    fn test_no_use_cases_when_data_insufficient() {
        use std::path::PathBuf;
        // Single function with no doc-comment and no group partner
        let analysis = make_analysis("rust", vec![make_fn("do_something", true)], vec![]);
        let analyses = vec![(PathBuf::from("src/lib.rs"), analysis)];
        let cases = infer_use_cases(&analyses);
        // "do_something" doesn't match any prefix and has no doc-comment → no cases
        assert!(cases.is_empty());
    }

    #[test]
    fn test_high_confidence_beats_medium_for_same_function() {
        use std::path::PathBuf;
        // A function that both has a doc-comment verb AND falls in a prefix group
        let analysis = make_analysis(
            "rust",
            vec![
                make_fn_with_doc(
                    "parse_config",
                    "/// allows parsing TOML configuration files",
                ),
                make_fn("parse_yaml", true),
            ],
            vec![],
        );
        let analyses = vec![(PathBuf::from("src/config.rs"), analysis)];
        let cases = infer_use_cases(&analyses);
        // High confidence case must appear first
        assert_eq!(cases[0].confidence, UseCaseConfidence::High);
    }

    // -----------------------------------------------------------------------
    // PR1 regression tests: AST-based @mcp-strip detection
    // -----------------------------------------------------------------------

    /// @mcp-strip inside a string literal must NOT mark the function.
    #[test]
    fn pr1_mcp_strip_in_string_literal_is_not_a_false_positive() {
        let dir = std::env::temp_dir();
        let path = dir.join("pr1_test_string_literal.rs");
        std::fs::write(
            &path,
            "pub fn display_hint() {\n    let msg = \"use // @mcp-strip to hide a body\";\n    println!(\"{}\", msg);\n}\n",
        )
        .unwrap();
        let analysis = analyze_file(&path).expect("analyze_file failed");
        let f = analysis
            .functions
            .iter()
            .find(|f| f.name == "display_hint")
            .expect("Function not found");
        assert!(
            !f.is_strip_marked,
            "@mcp-strip inside a string literal must NOT set is_strip_marked. Got: true"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A Rust function with generic type parameters in the signature must have
    /// a valid body_byte_range so that strip_body_by_range preserves the full
    /// signature (including angle brackets) and removes only the body.
    #[test]
    fn pr1_body_byte_range_correct_with_generic_signature() {
        let dir = std::env::temp_dir();
        let path = dir.join("pr1_test_generic.rs");
        std::fs::write(
            &path,
            "pub fn transform<K, V>(map: std::collections::HashMap<K, V>) -> Vec<K>\nwhere\n    K: Clone,\n{\n    // @mcp-strip\n    vec![]\n}\n",
        )
        .unwrap();
        let analysis = analyze_file(&path).expect("analyze_file failed");
        let f = analysis
            .functions
            .iter()
            .find(|f| f.name == "transform")
            .expect("Function not found");
        assert!(f.is_strip_marked, "Function must be strip-marked via AST");
        assert!(
            f.body_byte_range.is_some(),
            "body_byte_range must be populated for a Rust function"
        );
        let (start, end) = f.body_byte_range.unwrap();
        let stripped = crate::sanitizer::strip_body_by_range(&f.body_source, (start, end));
        assert!(
            stripped.contains("HashMap"),
            "Generic type in signature must survive stripping. Got: {}",
            stripped
        );
        assert!(
            !stripped.contains("vec![]"),
            "Body implementation must be hidden after stripping. Got: {}",
            stripped
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Python function with `# @mcp-strip` as the first comment inside the
    /// body must have is_strip_marked = true (AST detection, not string scan).
    #[test]
    fn pr1_python_first_body_comment_sets_strip_marked() {
        let dir = std::env::temp_dir();
        let path = dir.join("pr1_test_python.py");
        std::fs::write(
            &path,
            "def secret_fn():\n    # @mcp-strip\n    return 'classified'\n",
        )
        .unwrap();
        let analysis = analyze_file(&path).expect("analyze_file failed");
        let f = analysis
            .functions
            .iter()
            .find(|f| f.name == "secret_fn")
            .expect("Python function not found");
        assert!(
            f.is_strip_marked,
            "Python function with # @mcp-strip as first body comment must be strip-marked"
        );
        // body_byte_range is None for Python (indentation-based, not brace-based)
        assert!(
            f.body_byte_range.is_none(),
            "body_byte_range must be None for Python (no brace-delimited body)"
        );
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // PR2 regression tests: ImportKind classification
    // -----------------------------------------------------------------------

    /// External crate import (`use serde;`) must be `ExternalLibrary`.
    #[test]
    fn pr2_rust_external_crate_is_external_library() {
        let dir = std::env::temp_dir();
        let path = dir.join("pr2_test_external.rs");
        std::fs::write(
            &path,
            "use serde;\nuse serde_json::Value;\n\nfn noop() {}\n",
        )
        .unwrap();
        let analysis = analyze_file(&path).expect("analyze_file failed");
        for imp in &analysis.imports {
            assert_eq!(
                imp.kind,
                ImportKind::ExternalLibrary,
                "Rust crate '{}' must be ExternalLibrary, not {:?}",
                imp.path,
                imp.kind
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Rust project-local imports (`crate::analyzer`, `self::foo`, `super::bar`)
    /// must be classified as `InternalLocal` at extraction time.
    #[test]
    fn pr2_rust_crate_self_super_are_internal_local() {
        let dir = std::env::temp_dir();
        let path = dir.join("pr2_test_internal.rs");
        std::fs::write(
            &path,
            "use crate::analyzer;\nuse self::foo;\nuse super::bar;\n\nfn noop() {}\n",
        )
        .unwrap();
        let analysis = analyze_file(&path).expect("analyze_file failed");
        for imp in &analysis.imports {
            assert_eq!(
                imp.kind,
                ImportKind::InternalLocal,
                "Rust import '{}' must be InternalLocal, not {:?}",
                imp.path,
                imp.kind
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// JS relative imports (`./utils`, `../lib/helper`) must be `InternalLocal`
    /// according to the classifier (pure unit test — avoids pre-existing JS
    /// tree-sitter query bug in `analyze_file`).
    #[test]
    fn pr2_js_relative_imports_are_internal_local() {
        assert_eq!(
            classify_import_kind_from_path("./utils", &Lang::JavaScript),
            ImportKind::InternalLocal
        );
        assert_eq!(
            classify_import_kind_from_path("../lib/helper", &Lang::JavaScript),
            ImportKind::InternalLocal
        );
    }

    /// Scoped package imports (e.g. `@angular/core`) must be `ExternalLibrary`
    /// (pure unit test).
    #[test]
    fn pr2_angular_package_import_is_external_library() {
        assert_eq!(
            classify_import_kind_from_path("@angular/core", &Lang::JavaScript),
            ImportKind::ExternalLibrary
        );
        assert_eq!(
            classify_import_kind_from_path("@angular/common/http", &Lang::JavaScript),
            ImportKind::ExternalLibrary
        );
    }

    // -----------------------------------------------------------------------
    // PR4 — AST-based audit tests
    // -----------------------------------------------------------------------

    /// An `unsafe` keyword inside a comment must NOT generate an UnsafeCode finding.
    /// The old line-by-line scanner would match `// This was unsafe { bad() }` because
    /// it searches for the substring `"unsafe {"` without understanding the syntax.
    #[test]
    fn pr4_unsafe_in_comment_is_not_a_false_positive() {
        // This Rust snippet has the word "unsafe {" only inside a comment.
        let source = r#"
fn safe_function() {
    // Previously this code used unsafe { ptr.write(0) } — now it's safe.
    let x = 42;
    let _ = x;
}
"#;
        let findings = audit_file_ast(source, &Lang::Rust);
        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == AuditFindingKind::UnsafeCode)
            .collect();
        assert!(
            unsafe_findings.is_empty(),
            "expected no UnsafeCode findings from a comment, got: {:?}",
            unsafe_findings
        );
    }

    /// A real multi-line `unsafe { }` block must generate an UnsafeCode finding.
    #[test]
    fn pr4_multiline_unsafe_block_is_detected() {
        let source = r#"
fn raw_write(ptr: *mut u8, val: u8) {
    unsafe
    {
        *ptr = val;
    }
}
"#;
        let findings = audit_file_ast(source, &Lang::Rust);
        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == AuditFindingKind::UnsafeCode)
            .collect();
        assert!(
            !unsafe_findings.is_empty(),
            "expected at least one UnsafeCode finding for a real unsafe block"
        );
    }

    /// A Python `eval()` call must generate a DynamicExecution finding.
    #[test]
    fn pr4_python_eval_call_generates_finding() {
        let source = r#"
def run_user_code(user_input):
    result = eval(user_input)
    return result
"#;
        let findings = audit_file_ast(source, &Lang::Python);
        let eval_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == AuditFindingKind::DynamicExecution)
            .collect();
        assert!(
            !eval_findings.is_empty(),
            "expected a DynamicExecution finding for eval() call"
        );
    }
}
