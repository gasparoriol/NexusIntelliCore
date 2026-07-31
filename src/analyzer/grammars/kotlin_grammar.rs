use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct KotlinGrammar;

impl LanguageGrammar for KotlinGrammar {
    fn name(&self) -> &'static str {
        "kotlin"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["kt", "kts"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_kotlin::language())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some("(function_declaration (simple_identifier) @name) @fn")
    }
    fn class_query(&self) -> Option<&'static str> {
        Some(
            "(class_declaration (type_identifier) @name) @cls\n(object_declaration (type_identifier) @name) @cls",
        )
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(import_header) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("(string_literal) @str")
    }

    fn is_public_fn(&self, signature: &str, name: &str) -> bool {
        !name.starts_with('_') && !signature.contains("private ")
    }

    fn is_public_class(&self, line_text: &str, name: &str) -> bool {
        !name.starts_with('_') && !line_text.contains("private ")
    }

    fn get_query(&self, mode: crate::analyzer::lang::EvalMode) -> Option<&'static str> {
        match mode {
            crate::analyzer::lang::EvalMode::Basic => Some(crate::audit_queries::KOTLIN_EVAL),
            crate::analyzer::lang::EvalMode::Exec => Some(crate::audit_queries::KOTLIN_EVAL_QUERY),
        }
    }
}
