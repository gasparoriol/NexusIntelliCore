use super::docs::extract_preceding_comment;
use super::lang::LanguageGrammar;
use super::query::run_named_query;
use super::types::ClassInfo;
use anyhow::Result;
use tree_sitter::Language;

pub(crate) fn extract_classes(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &dyn LanguageGrammar,
    ts_lang: &Language,
) -> Result<Vec<ClassInfo>> {
    let Some(query_str) = lang.class_query() else {
        return Ok(vec![]);
    };

    let source_lines: Vec<&str> = source.lines().collect();
    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let cls_node = caps.iter().find(|(n, _, _)| *n == "cls")?;
        let name_cap = caps.iter().find(|(n, _, _)| *n == "name")?;

        let ts_node = cls_node.1;
        let raw_kind = ts_node.kind();
        let start_line = ts_node.start_position().row + 1;
        let line_text = if start_line > 0 && start_line <= source_lines.len() {
            source_lines[start_line - 1].trim()
        } else {
            ""
        };
        let kind = match raw_kind {
            "struct_item" | "struct_specifier" | "struct_declaration" => "struct",
            "enum_item" | "enum_declaration" | "enum_specifier" => "enum",
            "impl_item" => "impl",
            "trait_item" => "trait",
            "class_definition" | "class_declaration" => "class",
            "object_declaration" => "object",
            "interface_declaration" => "interface",
            "record_declaration" => "record",
            "annotation_type_declaration" => "@interface",
            "type_declaration" => {
                if line_text.contains(" interface") {
                    "interface"
                } else if line_text.contains(" struct") {
                    "struct"
                } else {
                    "type"
                }
            }
            // C
            "union_specifier" => "union",
            _ => raw_kind,
        };

        let doc_comment = extract_preceding_comment(&source_lines, start_line);
        let is_public = lang.is_public_class(line_text, &name_cap.2);

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
