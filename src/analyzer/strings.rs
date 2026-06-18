use super::lang::Lang;
use super::query::run_named_query;
use super::types::StringLiteral;
use anyhow::Result;
use tree_sitter::Language;

pub(crate) fn extract_strings(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &Lang,
    ts_lang: &Language,
) -> Result<Vec<StringLiteral>> {
    let query_str = match lang {
        Lang::Rust => {
            "[(string_literal) @str \
              (raw_string_literal) @str]"
        }
        Lang::Python => "(string) @str",
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => "(string) @str",
        Lang::Java => "(string_literal) @str",
        Lang::C => "(string_literal) @str",
        Lang::CSharp => "[(string_literal) @str (verbatim_string_literal) @str]",
        Lang::Kotlin | Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => {
            return Ok(vec![])
        }
    };

    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let s = caps.iter().find(|(n, _, _)| *n == "str")?;
        Some(StringLiteral {
            value: source[s.1.byte_range()].to_owned(),
            line: s.1.start_position().row + 1,
        })
    })
}
