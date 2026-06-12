use std::path::Path;
use tree_sitter::Language;

pub enum Lang {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Java,
    C,
    CSharp,
    Css,
    Scss,
    Sass,
    Html,
    Unknown,
}

pub fn detect_language(path: &Path) -> Lang {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Lang::Rust,
        Some("py") => Lang::Python,
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => Lang::JavaScript,
        Some("ts") => Lang::TypeScript,
        Some("tsx") => Lang::Tsx,
        Some("java") => Lang::Java,
        Some("c") | Some("h") => Lang::C,
        Some("cs") => Lang::CSharp,
        Some("css") => Lang::Css,
        Some("scss") => Lang::Scss,
        Some("sass") => Lang::Sass,
        Some("html") | Some("htm") => Lang::Html,
        _ => Lang::Unknown,
    }
}

pub(crate) fn ts_language(lang: &Lang) -> Option<Language> {
    match lang {
        Lang::Rust => Some(tree_sitter_rust::language()),
        Lang::Python => Some(tree_sitter_python::language()),
        Lang::JavaScript => Some(tree_sitter_javascript::language()),
        Lang::TypeScript => Some(tree_sitter_typescript::language_typescript()),
        Lang::Tsx => Some(tree_sitter_typescript::language_tsx()),
        Lang::Java => Some(tree_sitter_java::language()),
        Lang::C => Some(tree_sitter_c::language()),
        Lang::CSharp => Some(tree_sitter_c_sharp::language()),
        Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => None,
        Lang::Unknown => None,
    }
}

pub(crate) fn lang_name(lang: &Lang) -> &'static str {
    match lang {
        Lang::Rust => "rust",
        Lang::Python => "python",
        Lang::JavaScript => "javascript",
        Lang::TypeScript => "typescript",
        Lang::Tsx => "tsx",
        Lang::Java => "java",
        Lang::C => "c",
        Lang::CSharp => "csharp",
        Lang::Unknown => "unknown",
        // Handled by early returns above — these branches are unreachable at runtime
        Lang::Css => "css",
        Lang::Scss | Lang::Sass => "scss",
        Lang::Html => "html",
    }
}
