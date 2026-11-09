use std::collections::HashSet;

use super::lang::LanguageGrammar;
use super::rules;
use super::taint;
use super::types::AuditFinding;
use tree_sitter::{Parser, QueryCursor};

/// Run AST-based security checks on `source` for the given `lang`.
///
/// Applies every structural rule registered for the grammar in
/// `analyzer::rules` and the taint rules of its pack over a single parse
/// tree. Only real AST nodes match, so occurrences inside comments or string
/// literals are excluded. A structural finding is dropped when a taint
/// finding of the same category exists on the same line (the taint one is
/// more specific and carries the flow).
///
/// Falls back to an empty vector for languages without tree-sitter support.
pub fn audit_file_ast(source: &str, lang: &dyn LanguageGrammar) -> Vec<AuditFinding> {
    let compiled = rules::rules_for(lang.name());
    let has_taint = taint::has_pack(lang.name());
    if compiled.is_empty() && !has_taint {
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
                    flow: None,
                });
            }
        }
    }

    if has_taint {
        let flows = taint::analyze(&tree, source, lang.name());
        let covered: HashSet<(usize, &str)> =
            flows.iter().map(|f| (f.line, f.rule.category)).collect();
        findings.retain(|f| !covered.contains(&(f.line, f.rule.category)));
        findings.extend(flows);
    }

    findings
}
