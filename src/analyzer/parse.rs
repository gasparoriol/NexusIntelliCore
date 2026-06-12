use super::classes::extract_classes;
use super::css::parse_css_file;
use super::docs::extract_module_doc;
use super::functions::extract_functions;
use super::html::parse_html_file;
use super::imports::extract_imports;
use super::lang::{detect_language, ts_language, lang_name, Lang};
use super::strings::extract_strings;
use super::types::FileAnalysis;
use anyhow::{Context, Result};
use std::path::Path;
use tree_sitter::Parser;

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Parse `path` and return a `FileAnalysis`.
pub fn analyze_file(path: &Path) -> Result<FileAnalysis> {
    // Guard: reject files that are too large
    let metadata = std::fs::metadata(path).with_context(|| format!("Cannot stat {:?}", path))?;
    if metadata.len() > MAX_FILE_SIZE {
        anyhow::bail!(
            "File {:?} exceeds maximum size ({} bytes > {} bytes)",
            path,
            metadata.len(),
            MAX_FILE_SIZE
        );
    }

    let source =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {:?}", path))?;

    let lang = detect_language(path);

    // CSS / SCSS / HTML: dedicated parsers with a different data model — return early
    match &lang {
        Lang::Css => return parse_css_file(&source),
        Lang::Html => return parse_html_file(&source),
        Lang::Scss | Lang::Sass => {
            return Ok(FileAnalysis {
                language: "scss".to_owned(),
                ..Default::default()
            })
        }
        _ => {}
    }

    let ts_lang = match ts_language(&lang) {
        Some(l) => l,
        None => {
            return Ok(FileAnalysis {
                language: "unknown".to_owned(),
                ..Default::default()
            })
        }
    };

    let mut parser = Parser::new();
    parser
        .set_language(ts_lang)
        .context("Failed to set tree-sitter language")?;

    let tree = parser
        .parse(&source, None)
        .context("tree-sitter failed to produce a parse tree")?;

    let root = tree.root_node();

    let functions = extract_functions(root, &source, &lang, &ts_lang)?;
    let classes = extract_classes(root, &source, &lang, &ts_lang)?;
    let imports = extract_imports(root, &source, &lang, &ts_lang)?;
    let string_literals = extract_strings(root, &source, &lang, &ts_lang)?;

    let module_doc = extract_module_doc(&source, &lang);

    Ok(FileAnalysis {
        functions,
        classes,
        imports,
        string_literals,
        language: lang_name(&lang).to_owned(),
        css_rules: None,
        html_elements: None,
        module_doc,
    })
}
