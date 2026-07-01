use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct GoGrammar;

impl LanguageGrammar for GoGrammar {
    fn name(&self) -> &'static str {
        "go"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["go"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_go::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some(
            "[(function_declaration name: (identifier) @name) @fn \
              (method_declaration name: (field_identifier) @name) @fn]",
        )
    }

    fn class_query(&self) -> Option<&'static str> {
        Some("(type_spec name: (type_identifier) @name) @cls")
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(import_declaration) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("[(interpreted_string_literal) @str (raw_string_literal) @str]")
    }

    fn is_public_fn(&self, _signature: &str, name: &str) -> bool {
        name.chars().next().is_some_and(char::is_uppercase)
    }

    fn is_public_class(&self, _line_text: &str, name: &str) -> bool {
        name.chars().next().is_some_and(char::is_uppercase)
    }
}
