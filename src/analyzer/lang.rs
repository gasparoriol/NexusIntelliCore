use std::path::Path;
use tree_sitter::Language;

use super::grammars::{
    CGrammar, CSharpGrammar, CssGrammar, HtmlGrammar, JavaGrammar, JavaScriptGrammar,
    KotlinGrammar, PythonGrammar, RustGrammar, ScssGrammar, TsxGrammar, TypeScriptGrammar,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalMode {
    Basic,
    Exec,
}

pub trait LanguageGrammar: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn extensions(&self) -> &'static [&'static str];
    fn tree_sitter_language(&self) -> Option<Language>;

    fn function_query(&self) -> Option<&'static str> {
        None
    }
    fn class_query(&self) -> Option<&'static str> {
        None
    }
    fn import_query(&self) -> Option<&'static str> {
        None
    }
    fn string_query(&self) -> Option<&'static str> {
        None
    }

    fn is_public_fn(&self, _signature: &str, _name: &str) -> bool {
        true
    }
    fn is_public_class(&self, _line_text: &str, _name: &str) -> bool {
        true
    }
    fn uses_custom_parser(&self) -> bool {
        false
    }
    fn get_query(&self, _mode: EvalMode) -> Option<&'static str> {
        None
    }
}

pub static LANGUAGE_REGISTRY: std::sync::LazyLock<Vec<Box<dyn LanguageGrammar>>> =
    std::sync::LazyLock::new(|| {
        // Keep this list sorted by grammar name to make additions (for example, Go)
        // straightforward and easy to review.
        vec![
            Box::new(CGrammar),
            Box::new(CSharpGrammar),
            Box::new(CssGrammar),
            Box::new(HtmlGrammar),
            Box::new(JavaGrammar),
            Box::new(JavaScriptGrammar),
            Box::new(KotlinGrammar),
            Box::new(PythonGrammar),
            Box::new(RustGrammar),
            Box::new(ScssGrammar),
            Box::new(TsxGrammar),
            Box::new(TypeScriptGrammar),
        ]
    });

pub fn detect_grammar(path: &Path) -> Option<&'static dyn LanguageGrammar> {
    let ext = path.extension()?.to_str()?;
    LANGUAGE_REGISTRY
        .iter()
        .find(|g| g.extensions().contains(&ext))
        .map(|g| g.as_ref())
}
