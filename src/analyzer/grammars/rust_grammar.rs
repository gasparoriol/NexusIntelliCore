use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct RustGrammar;

impl LanguageGrammar for RustGrammar {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_rust::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some("(function_item name: (identifier) @name) @fn")
    }

    fn class_query(&self) -> Option<&'static str> {
        Some(
            "[(struct_item name: (type_identifier) @name) @cls \
              (enum_item name: (type_identifier) @name) @cls \
              (impl_item type: (type_identifier) @name) @cls \
              (trait_item name: (type_identifier) @name) @cls]",
        )
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(use_declaration) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("[(string_literal) @str (raw_string_literal) @str]")
    }

    fn is_public_fn(&self, signature: &str, _name: &str) -> bool {
        signature.starts_with("pub ") || signature.starts_with("pub(")
    }

    fn is_public_class(&self, line_text: &str, _name: &str) -> bool {
        line_text.starts_with("pub ") || line_text.starts_with("pub(")
    }
}
