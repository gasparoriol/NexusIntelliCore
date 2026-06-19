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
        None
    }
}
