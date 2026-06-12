use super::types::{CssRuleInfo, FileAnalysis};
use anyhow::{Context, Result};
use tree_sitter::Parser;

pub(crate) fn parse_css_file(source: &str) -> Result<FileAnalysis> {
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
