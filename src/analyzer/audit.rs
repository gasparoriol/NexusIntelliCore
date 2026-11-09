use super::lang::LanguageGrammar;
use super::rules;
use super::types::AuditFinding;
use tree_sitter::{Parser, QueryCursor};

/// Run AST-based security checks on `source` for the given `lang`.
///
/// Applies every structural rule registered for the grammar in
/// `analyzer::rules` over a single parse tree. Only real AST nodes match, so
/// occurrences inside comments or string literals are excluded.
///
/// Falls back to an empty vector for languages without tree-sitter support.
pub fn audit_file_ast(source: &str, lang: &dyn LanguageGrammar) -> Vec<AuditFinding> {
    let compiled = rules::rules_for(lang.name());
    // Java path traversal is still the line-based taint pass (migrated in Fase 2).
    let java_taint = lang.name() == "java";
    if compiled.is_empty() && !java_taint {
        return Vec::new();
    }

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
    let mut cursor = QueryCursor::new();
    for rule in compiled {
        for m in cursor.matches(&rule.query, tree.root_node(), source_bytes) {
            // The first capture is the representative node for line reporting.
            if let Some(cap) = m.captures.first() {
                findings.push(AuditFinding {
                    rule: rule.meta,
                    line: cap.node.start_position().row + 1,
                    is_write_sink: false,
                    description: rule.meta.description.to_owned(),
                });
            }
        }
    }

    if java_taint {
        findings.extend(super::java_taint::detect_path_traversal(source));
    }

    findings
}
