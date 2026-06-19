use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct CSharpGrammar;

impl LanguageGrammar for CSharpGrammar {
    fn name(&self) -> &'static str {
        "csharp"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cs"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_c_sharp::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some(
            "[(method_declaration name: (identifier) @name) @fn \
              (constructor_declaration name: (identifier) @name) @fn \
              (operator_declaration) @fn \
              (destructor_declaration name: (identifier) @name) @fn]",
        )
    }

    fn class_query(&self) -> Option<&'static str> {
        Some(
            "[(class_declaration     name: (identifier) @name) @cls \
              (interface_declaration name: (identifier) @name) @cls \
              (struct_declaration    name: (identifier) @name) @cls \
              (enum_declaration      name: (identifier) @name) @cls]",
        )
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(using_directive) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("[(string_literal) @str (verbatim_string_literal) @str]")
    }

    fn is_public_fn(&self, signature: &str, _name: &str) -> bool {
        signature.contains("public ")
    }

    fn is_public_class(&self, line_text: &str, _name: &str) -> bool {
        line_text.contains("public ")
    }
}
