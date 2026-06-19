use crate::analyzer::lang::{EvalMode, LanguageGrammar};
use tree_sitter::Language;

pub struct TypeScriptGrammar;

impl LanguageGrammar for TypeScriptGrammar {
    fn name(&self) -> &'static str {
        "typescript"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["ts"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        Some(tree_sitter_typescript::language_typescript())
    }

    fn function_query(&self) -> Option<&'static str> {
        Some(
            "[(function_declaration name: (identifier) @name) @fn \
              (method_definition name: (property_identifier) @name) @fn \
              (method_signature name: (property_identifier) @name) @fn \
              (variable_declarator name: (identifier) @name \
                value: [(arrow_function) (function_expression)]) @fn]",
        )
    }

    fn class_query(&self) -> Option<&'static str> {
        Some("(class_declaration name: (type_identifier) @name) @cls")
    }

    fn import_query(&self) -> Option<&'static str> {
        Some("(import_statement) @import")
    }

    fn string_query(&self) -> Option<&'static str> {
        Some("(string) @str")
    }

    fn is_public_fn(&self, signature: &str, name: &str) -> bool {
        !name.starts_with('_') && !signature.contains("private ") && !signature.contains('#')
    }

    fn is_public_class(&self, line_text: &str, name: &str) -> bool {
        !name.starts_with('_') && !line_text.contains("private ")
    }

    fn get_query(&self, mode: EvalMode) -> Option<&'static str> {
        match mode {
            EvalMode::Basic => Some(crate::audit_queries::JS_EVAL),
            EvalMode::Exec => Some(crate::audit_queries::JS_EVAL_QUERY),
        }
    }
}
