use super::lang::LanguageGrammar;
use super::query::run_named_query;
use super::types::{ImportInfo, ImportKind};
use anyhow::Result;
use tree_sitter::Language;

pub(crate) fn extract_imports(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &dyn LanguageGrammar,
    ts_lang: &Language,
) -> Result<Vec<ImportInfo>> {
    let query_str = match lang.import_query() {
        Some(q) => q,
        None => return Ok(vec![]),
    };

    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let imp = caps.iter().find(|(n, _, _)| *n == "import")?;
        let raw = source[imp.1.byte_range()].trim().to_owned();

        // Extract the module/package path, specialized by language
        let path = match lang.name() {
            "rust" => {
                // For Rust: `use foo::bar::baz;` → path is `use foo::bar::baz;` trimmed
                raw.trim_start_matches("use ")
                    .trim_end_matches(';')
                    .to_owned()
            }
            "python" => {
                // For Python: `from pkg.mod import name` → extract `pkg.mod`
                // or `import pkg.mod` → extract `pkg.mod`
                extract_python_import_path(&raw)
            }
            "javascript" | "typescript" | "tsx" => {
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
            "java" => {
                // For Java: `import com.example.Service;` → path is `com.example.Service`
                raw.trim_start_matches("import ")
                    .trim_end_matches(';')
                    .to_owned()
            }
            "kotlin" => {
                // For Kotlin: `import a.b.C` / `import a.b.*` / `import a.b.C as D`
                // Keep only the imported symbol path/wildcard, excluding alias.
                let normalized = raw.trim_start_matches("import ").trim();
                if let Some((left, _alias)) = normalized.split_once(" as ") {
                    left.trim().to_owned()
                } else {
                    normalized.to_owned()
                }
            }
            "c" => {
                // `#include <stdio.h>` → `stdio.h`, `#include "foo.h"` → `foo.h`
                raw.trim_start_matches("#include")
                    .trim()
                    .trim_matches(|c: char| c == '<' || c == '>' || c == '"')
                    .to_owned()
            }
            "csharp" => {
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
            _ => raw.clone(),
        };

        Some(ImportInfo {
            raw,
            kind: classify_import_kind_from_path(&path, lang.name()),
            path,
            resolved_path: None,
        })
    })
}

/// Classify an import path into a `ImportKind` using only the path string and
/// language heuristics (no file system access). The result may be refined
/// later when the file index is available.
pub fn classify_import_kind_from_path(path: &str, lang_name: &str) -> ImportKind {
    // Relative paths → likely a project-local file
    if path.starts_with("./") || path.starts_with("../") {
        return ImportKind::InternalLocal;
    }
    // Python relative: `from . import foo` or `from .utils import bar`
    if path.starts_with('.') {
        return ImportKind::InternalLocal;
    }
    // Rust project-local references
    if lang_name == "rust"
        && (path.starts_with("crate::")
            || path.starts_with("self::")
            || path.starts_with("super::"))
    {
        return ImportKind::InternalLocal;
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
