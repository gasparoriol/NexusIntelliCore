use super::types::{FileAnalysis, HtmlElementInfo};
use anyhow::{Context, Result};
use tree_sitter::Parser;

pub(crate) fn parse_html_file(source: &str) -> Result<FileAnalysis> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_html::language())
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
pub(crate) fn is_angular_component(tag: &str) -> bool {
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
