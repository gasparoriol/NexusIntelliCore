use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct CGrammar;

impl LanguageGrammar for CGrammar {
    fn name(&self) -> &'static str {
        "c"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_c::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some("(function_definition declarator: (function_declarator declarator: (identifier) @name)) @fn")
    }

    fn class_query(&self) -> Option<&'static str> {
        Some(
            "[(struct_specifier name: (type_identifier) @name) @cls \
              (union_specifier  name: (type_identifier) @name) @cls \
              (enum_specifier   name: (type_identifier) @name) @cls]",
        )
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(preproc_include) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("(string_literal) @str")
    }
}
