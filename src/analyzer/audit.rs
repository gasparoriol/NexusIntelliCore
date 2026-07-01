use super::lang::{EvalMode, LanguageGrammar};
use super::types::{AuditFinding, AuditFindingKind};
use tree_sitter::{Parser, Query, QueryCursor};

/// Run AST-based security checks on `source` for the given `lang`.
///
/// Returns only findings where the tree-sitter query matches an *actual*
/// AST node — not occurrences inside comments or string literals (which
/// are correctly excluded because they're not matched by the structural
/// queries).
///
/// Falls back to an empty vector for languages without tree-sitter support.
pub fn audit_file_ast(source: &str, lang: &dyn LanguageGrammar) -> Vec<AuditFinding> {
    let Some(ts_lang) = lang.tree_sitter_language() else {
        return Vec::new();
    };

    let mut parser = Parser::new();
    if parser.set_language(&ts_lang).is_err() {
        return Vec::new();
    }

    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let source_bytes = source.as_bytes();
    let mut findings: Vec<AuditFinding> = Vec::new();

    // --- Unsafe code (Rust only) ---
    if lang.name() == "rust" {
        for query_str in &[
            crate::audit_queries::RUST_UNSAFE_BLOCK,
            crate::audit_queries::RUST_UNSAFE_FN,
            crate::audit_queries::RUST_INLINE_ASM_QUERY,
            crate::audit_queries::RUST_PANICS,
            crate::audit_queries::RUST_UNSAFE_BLOCK_QUERY,
        ] {
            let Ok(query) = Query::new(&ts_lang, query_str) else {
                continue;
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
    let eval_query_str = lang
        .get_query(EvalMode::Exec)
        .or_else(|| lang.get_query(EvalMode::Basic));
    if let Some(qstr) = eval_query_str {
        if let Ok(query) = Query::new(&ts_lang, qstr) {
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
                        description: format!("{name}() call"),
                    });
                }
            }
        }
    }

    findings
}
