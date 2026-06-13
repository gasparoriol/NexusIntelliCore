use std::path::Path;

pub(super) fn doc_comment_first_line(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let cleaned = strip_doc_prefix(line);
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    })
}

pub(super) fn relative_path_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn strip_doc_prefix(line: &str) -> String {
    line.trim()
        .trim_start_matches("//!")
        .trim_start_matches("///")
        .trim_start_matches("//")
        .trim_start_matches('#')
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::doc_comment_first_line;

    #[test]
    fn extracts_first_non_empty_doc_line() {
        let text = "\n//! summary\n//! more";
        assert_eq!(doc_comment_first_line(text).as_deref(), Some("summary"));
    }

    #[test]
    fn strips_common_comment_prefixes() {
        let text = "\n/// heading\n// body";
        assert_eq!(doc_comment_first_line(text).as_deref(), Some("heading"));
    }
}
