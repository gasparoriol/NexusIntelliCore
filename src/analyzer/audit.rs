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
/// Taint flows are followed through calls to functions of the same file
/// (summaries, depth [`taint::SUMMARY_DEPTH`]); use [`audit_file_ast_with`]
/// to resolve calls across files.
///
/// Falls back to an empty vector for languages without tree-sitter support.
// Library API and tests; the server binary audits with project-wide summaries.
#[allow(dead_code)]
pub fn audit_file_ast(source: &str, lang: &dyn LanguageGrammar) -> Vec<AuditFinding> {
    audit_tree(source, lang, None)
}

/// Like [`audit_file_ast`], resolving calls with project-wide summaries.
pub fn audit_file_ast_with(
    source: &str,
    lang: &dyn LanguageGrammar,
    summaries: &taint::Summaries,
) -> Vec<AuditFinding> {
    audit_tree(source, lang, Some(summaries))
}

/// Taint summaries of the functions defined in `source`, resolving their own
/// calls with `known` (one round of the project-wide fixpoint).
pub fn summarize_file(
    source: &str,
    lang: &dyn LanguageGrammar,
    known: &taint::Summaries,
) -> Vec<taint::FunctionSummary> {
    if !taint::has_pack(lang.name()) {
        return Vec::new();
    }
    parse(source, lang)
        .map(|tree| taint::summarize(&tree, source, lang.name(), known))
        .unwrap_or_default()
}

fn parse(source: &str, lang: &dyn LanguageGrammar) -> Option<tree_sitter::Tree> {
    let ts_lang = lang.tree_sitter_language()?;
    let mut parser = Parser::new();
    parser.set_language(&ts_lang).ok()?;
    parser.parse(source, None)
}

fn audit_tree(
    source: &str,
    lang: &dyn LanguageGrammar,
    project: Option<&taint::Summaries>,
) -> Vec<AuditFinding> {
    let compiled = rules::rules_for(lang.name());
    let has_taint = taint::has_pack(lang.name());
    if compiled.is_empty() && !has_taint {
        return Vec::new();
    }
    let Some(tree) = parse(source, lang) else {
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
                function: enclosing_function_name(node, source_bytes),
            });
        }
    }

    if has_taint {
        let flows = match project {
            Some(summaries) => taint::analyze(&tree, source, lang.name(), summaries),
            None => taint::analyze_local(&tree, source, lang.name()),
        };
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

/// 1-based inclusive line ranges of Rust inline test code: items marked
/// `#[cfg(test)]`, `#[test]` or `#[tokio::test]` (attributes are the
/// preceding sibling items). Other languages keep tests in separate files.
#[must_use]
pub fn test_code_lines(source: &str, lang: &dyn LanguageGrammar) -> Vec<(usize, usize)> {
    if lang.name() != "rust" {
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
    let src = source.as_bytes();
    let mut ranges = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "mod_item" | "function_item") && has_test_attribute(n, src) {
            ranges.push((n.start_position().row + 1, n.end_position().row + 1));
            continue;
        }
        for i in 0..n.named_child_count() {
            if let Some(c) = n.named_child(i) {
                stack.push(c);
            }
        }
    }
    ranges.sort_unstable();
    ranges
}

fn has_test_attribute(item: Node<'_>, src: &[u8]) -> bool {
    let mut prev = item.prev_named_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => {
                let attr = p.utf8_text(src).unwrap_or_default();
                if attr.contains("cfg(test)")
                    || attr.starts_with("#[test")
                    || attr.contains("::test")
                {
                    return true;
                }
            }
            "line_comment" | "block_comment" => {}
            _ => return false,
        }
        prev = p.prev_named_sibling();
    }
    false
}

/// Anonymous function-like nodes; they take the name they are bound to.
const ANONYMOUS_FUNCTION_KINDS: &[&str] = &[
    "arrow_function",
    "function_expression",
    "lambda_expression",
    "lambda",
    "closure_expression",
    "func_literal",
    "anonymous_function",
    "lambda_literal",
];

/// Name of the function enclosing `node`: the nearest named function, or the
/// variable/key/assignment an anonymous function is bound to.
pub(crate) fn enclosing_function_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        let kind = n.kind();
        if FUNCTION_KINDS.contains(&kind) || ANONYMOUS_FUNCTION_KINDS.contains(&kind) {
            if let Some(name) = declared_name(n, src) {
                return Some(name);
            }
        }
        cur = n.parent();
    }
    None
}

pub(crate) fn declared_name(func: Node<'_>, src: &[u8]) -> Option<String> {
    let text = |n: Node<'_>| n.utf8_text(src).ok().map(str::to_owned);
    if let Some(name) = func.child_by_field_name("name") {
        return text(name);
    }
    if let Some(mut decl) = func.child_by_field_name("declarator") {
        // C: `int *f(void)` nests declarators down to the identifier.
        while let Some(inner) = decl.child_by_field_name("declarator") {
            decl = inner;
        }
        return text(decl);
    }
    if func.kind() == "function_declaration" {
        // Kotlin has no field names: the name is the first simple_identifier.
        let mut cursor = func.walk();
        let found = func
            .named_children(&mut cursor)
            .find(|c| c.kind() == "simple_identifier");
        return found.and_then(text);
    }
    let parent = func.parent()?;
    ["name", "key", "left"]
        .iter()
        .find_map(|f| parent.child_by_field_name(f))
        .filter(|n| *n != func)
        .and_then(text)
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
