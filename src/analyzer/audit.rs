use std::collections::HashSet;

use super::lang::LanguageGrammar;
use super::rules;
use super::taint;
use super::types::AuditFinding;
use tree_sitter::{Node, Parser, QueryCursor};

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
        let names = rule.query.capture_names();
        for m in cursor.matches(&rule.query, tree.root_node(), source_bytes) {
            // Report the earliest non-helper capture (`@_x` only feed predicates).
            let earliest = |include_helpers: bool| {
                m.captures
                    .iter()
                    .filter(|c| include_helpers || !names[c.index as usize].starts_with('_'))
                    .map(|c| c.node)
                    .min_by_key(|n| (n.start_byte(), std::cmp::Reverse(n.end_byte())))
            };
            let Some(node) = earliest(false).or_else(|| earliest(true)) else {
                continue;
            };
            if !rule.context.is_empty() && !in_named_context(node, source_bytes, rule.context) {
                continue;
            }
            if !rule.unless_scope.is_empty() {
                let scope = enclosing_function(node).unwrap_or_else(|| tree.root_node());
                let text = scope.utf8_text(source_bytes).unwrap_or_default();
                if rule.unless_scope.iter().any(|marker| text.contains(marker)) {
                    continue;
                }
            }
            findings.push(AuditFinding {
                rule: rule.meta,
                line: node.start_position().row + 1,
                is_write_sink: false,
                description: rule.meta.description.to_owned(),
                flow: None,
            });
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

/// Declarations whose name scopes a context check; the search stops at the
/// first one so a class name does not leak into unrelated methods.
const FUNCTION_KINDS: &[&str] = &[
    "function_definition",
    "function_declaration",
    "function_item",
    "method_declaration",
    "method_definition",
    "constructor_declaration",
    "local_function_statement",
];

/// Fields that name the declaration or target enclosing an expression.
const NAME_FIELDS: &[&str] = &["name", "left", "key", "declarator"];

/// True when the name of an enclosing variable, key, assignment target or
/// function contains one of `words` (case-insensitive).
fn in_named_context(node: Node<'_>, src: &[u8], words: &[&str]) -> bool {
    let mut cur = node.parent();
    while let Some(n) = cur {
        for field in NAME_FIELDS {
            if let Some(name) = n.child_by_field_name(field) {
                let text = name.utf8_text(src).unwrap_or_default().to_ascii_lowercase();
                if words.iter().any(|w| text.contains(w)) {
                    return true;
                }
            }
        }
        if FUNCTION_KINDS.contains(&n.kind()) {
            return false;
        }
        cur = n.parent();
    }
    false
}

fn enclosing_function(node: Node<'_>) -> Option<Node<'_>> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if FUNCTION_KINDS.contains(&n.kind()) {
            return Some(n);
        }
        cur = n.parent();
    }
    None
}
