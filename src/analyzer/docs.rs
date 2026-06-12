use super::lang::Lang;

/// Extract the doc-comment block immediately preceding the given 1-based line.
///
/// Walks backwards from `before_line - 1`, collecting contiguous comment lines.
/// Stops at the first blank or non-comment line. Returns `None` if nothing found.
///
/// Recognised prefixes: `///`, `//!`, `//`, `#` (Python), `/**`, `/*`, ` *`.
/// This is intentionally line-based rather than AST-based because tree-sitter
/// does not guarantee adjacency between a `line_comment` node and the
/// following declaration.
pub fn extract_preceding_comment(lines: &[&str], before_line: usize) -> Option<String> {
    if before_line < 2 || before_line > lines.len() {
        return None;
    }
    let mut collected: Vec<&str> = Vec::new();
    let mut i = before_line - 1; // start one position above (0-based)
    while i > 0 {
        i -= 1;
        let trimmed = lines[i].trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with("///")
            || trimmed.starts_with("//!")
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/**")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            collected.push(lines[i]);
        } else {
            break;
        }
    }
    if collected.is_empty() {
        return None;
    }
    collected.reverse();
    Some(collected.join("\n"))
}

/// Extract the module-level / file-level documentation comment.
///
/// - **Rust**: consecutive `//!` lines at the top of the file.
/// - **Python**: first triple-quoted string (`"""` or `'''`) at the top.
/// - **JS/TS/Java**: first block-comment block (`/** ... */`) at the top, preceding any
///   non-comment token.
/// - All other languages: `None`.
pub fn extract_module_doc(source: &str, lang: &Lang) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    match lang {
        Lang::Rust => {
            let doc_lines: Vec<&str> = lines
                .iter()
                .take_while(|l| {
                    let t = l.trim();
                    t.starts_with("//!") || t.is_empty()
                })
                .filter(|l| l.trim().starts_with("//!"))
                .copied()
                .collect();
            if doc_lines.is_empty() {
                None
            } else {
                Some(doc_lines.join("\n"))
            }
        }
        Lang::Python => {
            let first = lines.iter().position(|l| !l.trim().is_empty())?;
            let trimmed = lines[first].trim();
            let quote = if trimmed.starts_with("\"\"\"") {
                "\"\"\""
            } else if trimmed.starts_with("'''") {
                "'''"
            } else {
                return None;
            };
            let mut doc = vec![lines[first]];
            // Single-line docstring closes on the same line after the opening
            let rest_of_first = trimmed.get(3..).unwrap_or("");
            if rest_of_first.contains(quote) {
                return Some(doc.join("\n"));
            }
            for line in lines.iter().skip(first + 1) {
                doc.push(line);
                if line.contains(quote) {
                    break;
                }
            }
            Some(doc.join("\n"))
        }
        Lang::Java | Lang::TypeScript | Lang::Tsx | Lang::JavaScript => {
            let first = lines.iter().position(|l| !l.trim().is_empty())?;
            let trimmed = lines[first].trim();
            if !trimmed.starts_with("/**") && !trimmed.starts_with("/*") {
                return None;
            }
            let mut doc = vec![lines[first]];
            if !trimmed.contains("*/") {
                for line in lines.iter().skip(first + 1) {
                    doc.push(line);
                    if line.contains("*/") {
                        break;
                    }
                }
            }
            Some(doc.join("\n"))
        }
        _ => None,
    }
}
