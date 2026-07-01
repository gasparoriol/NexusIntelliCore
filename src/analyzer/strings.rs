use super::lang::LanguageGrammar;
use super::query::run_named_query;
use super::types::StringLiteral;
use anyhow::Result;
use tree_sitter::Language;

pub(crate) fn extract_strings(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &dyn LanguageGrammar,
    ts_lang: &Language,
) -> Result<Vec<StringLiteral>> {
    let Some(query_str) = lang.string_query() else {
        return Ok(vec![]);
    };

    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        let s = caps.iter().find(|(n, _, _)| *n == "str")?;
        Some(StringLiteral {
            value: source[s.1.byte_range()].to_owned(),
            line: s.1.start_position().row + 1,
        })
    })
}
