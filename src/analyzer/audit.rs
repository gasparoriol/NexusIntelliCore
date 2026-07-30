use super::lang::{EvalMode, LanguageGrammar};
use super::types::{AuditFinding, AuditFindingKind};
use tree_sitter::{Parser, Query, QueryCursor};

fn push_findings_for_query(
    findings: &mut Vec<AuditFinding>,
    query_str: &str,
    kind: AuditFindingKind,
    description: &str,
    ts_lang: &tree_sitter::Language,
    root: tree_sitter::Node<'_>,
    source_bytes: &[u8],
) {
    let Ok(query) = Query::new(ts_lang, query_str) else {
        return;
    };

    let mut cursor = QueryCursor::new();
    for m in cursor.matches(&query, root, source_bytes) {
        if let Some(cap) = m.captures.first() {
            findings.push(AuditFinding {
                kind: kind.clone(),
                line: cap.node.start_position().row + 1,
                description: description.to_owned(),
            });
        }
    }
}

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

    // --- Dynamic execution and dangerous sinks ---
    match lang.name() {
        "javascript" | "typescript" | "tsx" => {
            push_findings_for_query(
                &mut findings,
                crate::audit_queries::JS_EVAL_QUERY,
                AuditFindingKind::DynamicExecution,
                "eval() call",
                &ts_lang,
                tree.root_node(),
                source_bytes,
            );
            push_findings_for_query(
                &mut findings,
                crate::audit_queries::JS_NEW_FUNCTION_QUERY,
                AuditFindingKind::DynamicExecution,
                "new Function() call",
                &ts_lang,
                tree.root_node(),
                source_bytes,
            );
            push_findings_for_query(
                &mut findings,
                crate::audit_queries::JS_INNER_HTML_ASSIGN_QUERY,
                AuditFindingKind::InsecureAssignment,
                "innerHTML assignment",
                &ts_lang,
                tree.root_node(),
                source_bytes,
            );
        }
        "python" => {
            push_findings_for_query(
                &mut findings,
                crate::audit_queries::PYTHON_EVAL_EXEC_QUERY,
                AuditFindingKind::DynamicExecution,
                "eval/exec call",
                &ts_lang,
                tree.root_node(),
                source_bytes,
            );
            push_findings_for_query(
                &mut findings,
                crate::audit_queries::PYTHON_SUBPROCESS_SHELL_TRUE_QUERY,
                AuditFindingKind::DynamicExecution,
                "subprocess shell=True call",
                &ts_lang,
                tree.root_node(),
                source_bytes,
            );
        }
        _ => {
            let eval_query_str = lang
                .get_query(EvalMode::Exec)
                .or_else(|| lang.get_query(EvalMode::Basic));
            if let Some(qstr) = eval_query_str {
                push_findings_for_query(
                    &mut findings,
                    qstr,
                    AuditFindingKind::DynamicExecution,
                    "dynamic execution call",
                    &ts_lang,
                    tree.root_node(),
                    source_bytes,
                );
            }
        }
    }

    findings
}
