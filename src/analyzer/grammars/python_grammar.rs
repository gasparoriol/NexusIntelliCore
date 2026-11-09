use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct PythonGrammar;

impl LanguageGrammar for PythonGrammar {
    fn name(&self) -> &'static str {
        "python"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_python::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some("(function_definition name: (identifier) @name) @fn")
    }

    fn class_query(&self) -> Option<&'static str> {
        Some("(class_definition name: (identifier) @name) @cls")
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("[(import_statement) @import (import_from_statement) @import]")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("(string) @str")
    }

    fn is_public_fn(&self, _signature: &str, name: &str) -> bool {
        !name.starts_with('_')
    }

    fn is_public_class(&self, _line_text: &str, name: &str) -> bool {
        !name.starts_with('_')
    }
}
