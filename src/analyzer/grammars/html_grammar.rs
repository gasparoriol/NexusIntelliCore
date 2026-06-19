use crate::analyzer::lang::LanguageGrammar;
use tree_sitter::Language;

pub struct HtmlGrammar;

impl LanguageGrammar for HtmlGrammar {
    fn name(&self) -> &'static str {
        "html"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["html", "htm"]
    }

    fn tree_sitter_language(&self) -> Option<Language> {
        None
    }

    fn uses_custom_parser(&self) -> bool {
        true
    }
}
