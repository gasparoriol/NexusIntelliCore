use crate::analyzer::lang::{EvalMode, LanguageGrammar};
use tree_sitter::Language;

pub struct JavaGrammar;

impl LanguageGrammar for JavaGrammar {
    fn name(&self) -> &'static str {
        "java"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["java"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_java::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some(
            "[(method_declaration name: (identifier) @name) @fn \
              (constructor_declaration name: (identifier) @name) @fn]",
        )
    }

    fn class_query(&self) -> Option<&'static str> {
        Some(
            "[(class_declaration name: (identifier) @name) @cls \
              (interface_declaration name: (identifier) @name) @cls \
              (enum_declaration name: (identifier) @name) @cls \
              (record_declaration name: (identifier) @name) @cls \
              (annotation_type_declaration name: (identifier) @name) @cls]",
        )
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(import_declaration) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("(string_literal) @str")
    }

    fn is_public_fn(&self, signature: &str, _name: &str) -> bool {
        signature.contains("public ")
    }

    fn is_public_class(&self, line_text: &str, _name: &str) -> bool {
        line_text.contains("public ")
    }

    fn get_query(&self, mode: EvalMode) -> Option<&'static str> {
        match mode {
            EvalMode::Exec => Some(crate::audit_queries::JAVA_EXEC_QUERY),
            _ => None,
        }
    }
}
