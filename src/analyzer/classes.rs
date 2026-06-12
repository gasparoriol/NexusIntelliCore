use super::lang::Lang;
use super::query::run_named_query;
use super::types::ClassInfo;
use super::docs::extract_preceding_comment;
use anyhow::Result;
use tree_sitter::Language;

pub(crate) fn extract_classes(
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
        Lang::JavaScript => {
            "(class_declaration name: (identifier) @name) @cls"
        }
        Lang::TypeScript | Lang::Tsx => {
            "(class_declaration name: (type_identifier) @name) @cls"
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
        Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => return Ok(vec![]),
    };

    let source_lines: Vec<&str> = source.lines().collect();
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

        let start_line = ts_node.start_position().row + 1;
        let doc_comment = extract_preceding_comment(&source_lines, start_line);
        let is_public = is_public_class(&source_lines, start_line, &name_cap.2, lang);

        Some(ClassInfo {
            name: name_cap.2.clone(),
            kind: kind.to_owned(),
            start_line,
            end_line: ts_node.end_position().row + 1,
            doc_comment,
            is_public,
        })
    })
}

/// Determine if a type definition is publicly visible (language-aware heuristic).
pub(crate) fn is_public_class(source_lines: &[&str], start_line: usize, name: &str, lang: &Lang) -> bool {
    let line_text = if start_line > 0 && start_line <= source_lines.len() {
        source_lines[start_line - 1].trim()
    } else {
        ""
    };
    match lang {
        Lang::Rust => line_text.starts_with("pub ") || line_text.starts_with("pub("),
        Lang::Java => line_text.contains("public "),
        Lang::Python => !name.starts_with('_'),
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            !name.starts_with('_') && !line_text.contains("private ")
        }
        Lang::CSharp => line_text.contains("public "),
        Lang::C => true,
        _ => true,
    }
}
