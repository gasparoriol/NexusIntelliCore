/// Phase 3: Tree-sitter Code Analyzer
///
/// Parses source files for each supported language and extracts:
/// • Function / method signatures and bodies
/// • Class / struct / impl definitions
/// • Import / use statements (for dependency graph)
/// • String literals (for secret scanning)
use std::path::Path;

use anyhow::{Context, Result};
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
    /// `true` when the comment `// @mcp-strip` appears inside this function.
    pub is_strip_marked: bool,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub name: String,
    pub kind: String, // "class", "struct", "impl", "trait", …
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    /// The raw import/use line.
    pub raw: String,
    /// Resolved module / package path when detectable.
    pub path: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StringLiteral {
    pub value: String,
    pub line: usize,
}

#[derive(Debug, Default, Clone)]
pub struct FileAnalysis {
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    #[allow(dead_code)]
    pub string_literals: Vec<StringLiteral>,
    pub language: String,
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

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

    Ok(FileAnalysis {
        functions,
        classes,
        imports,
        string_literals,
        language: lang_name.to_owned(),
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
        Lang::Unknown => return Ok(vec![]),
    };

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
        let is_strip = crate::sanitizer::has_mcp_strip(fn_text);

        Some(FunctionInfo {
            name: name_text,
            signature,
            body_source: fn_text.to_owned(),
            start_line: fn_node_ts.start_position().row + 1,
            end_line: fn_node_ts.end_position().row + 1,
            is_strip_marked: is_strip,
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
        Lang::Unknown => return Ok(vec![]),
    };

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

        Some(ClassInfo {
            name: name_cap.2.clone(),
            kind: kind.to_owned(),
            start_line: ts_node.start_position().row + 1,
            end_line: ts_node.end_position().row + 1,
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
        Lang::Unknown => return Ok(vec![]),
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
            Lang::Unknown => raw.clone(),
        };

        Some(ImportInfo { raw, path })
    })
}

/// Extract module path from a Python import statement.
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
        if let Some(quote_idx) = after_from.find(|c| c == '\'' || c == '"') {
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
        Lang::Unknown => return Ok(vec![]),
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
