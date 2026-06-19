use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct CssGrammar;

impl LanguageGrammar for CssGrammar {
    fn name(&self) -> &'static str {
        "css"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["css"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        None
    }

    fn uses_custom_parser(&self) -> bool {
        true
    }
}

pub struct ScssGrammar;

impl LanguageGrammar for ScssGrammar {
    fn name(&self) -> &'static str {
        "scss"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["scss", "sass"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        None
    }

    fn uses_custom_parser(&self) -> bool {
        true
    }
}
