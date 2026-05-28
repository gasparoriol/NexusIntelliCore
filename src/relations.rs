/// Angular component relation extractor.
///
/// Parses `@Component({ selector, templateUrl, styleUrls })` decorators from
/// TypeScript files using regex (not AST) to resolve the TS → HTML → CSS graph.
///
/// Limitations (v1):
/// • `styleUrls` with dynamic expressions (`getStyles()`) are not resolved.
/// • Spreads inside `styleUrls` (`[...base, './local.css']`) are not resolved.
/// • Inline `template:` / `styles:` fields are not parsed.
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

static RE_SELECTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"selector\s*:\s*['"]([^'"]+)['"]"#).unwrap());

static RE_TEMPLATE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"templateUrl\s*:\s*['"]([^'"]+)['"]"#).unwrap());

static RE_STYLE_URLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"styleUrls\s*:\s*\[([^\]]+)\]"#).unwrap());

static RE_STYLE_URL_ITEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([^'"]+)['"]"#).unwrap());

/// Resolved Angular component relationships extracted from a `.ts` file.
#[derive(Debug)]
pub struct AngularComponentInfo {
    /// Path of the TypeScript component file.
    #[allow(dead_code)]
    pub ts_file: PathBuf,
    /// Value of `selector: '...'` in `@Component`.
    pub selector: Option<String>,
    /// Resolved path of `templateUrl: '...'`, if present.
    pub template_file: Option<PathBuf>,
    /// Resolved paths from `styleUrls: [...]`.
    pub style_files: Vec<PathBuf>,
}

/// Parse the `@Component` decorator from `source` and return resolved file paths.
///
/// Returns `None` if no `@Component` decorator is found.
pub fn extract_component_info(ts_file: &Path, source: &str) -> Option<AngularComponentInfo> {
    if !source.contains("@Component") {
        return None;
    }

    let component_start = source.find("@Component")?;
    let decorator_block = &source[component_start..];
    let block_end = find_decorator_end(decorator_block)?;
    let decorator = &decorator_block[..block_end];

    let selector = RE_SELECTOR
        .captures(decorator)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned());

    let template_file = RE_TEMPLATE_URL
        .captures(decorator)
        .and_then(|c| c.get(1))
        .map(|m| resolve_relative(ts_file, m.as_str()));

    let style_files: Vec<PathBuf> = RE_STYLE_URLS
        .captures(decorator)
        .and_then(|c| c.get(1))
        .map(|urls_match| {
            RE_STYLE_URL_ITEM
                .captures_iter(urls_match.as_str())
                .filter_map(|c| c.get(1))
                .map(|m| resolve_relative(ts_file, m.as_str()))
                .collect()
        })
        .unwrap_or_default();

    Some(AngularComponentInfo {
        ts_file: ts_file.to_path_buf(),
        selector,
        template_file,
        style_files,
    })
}

/// Resolve a path relative to the directory of `base`, normalizing `..` components.
fn resolve_relative(base: &Path, rel: &str) -> PathBuf {
    let dir = base.parent().unwrap_or(Path::new("."));
    normalize_path(&dir.join(rel))
}

/// Normalize a path by resolving `..` and `.` components without touching the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
    let mut components: Vec<std::path::Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Pop the last component only if it's a normal directory
                let popped = components
                    .last()
                    .map(|c| matches!(c, std::path::Component::Normal(_)))
                    .unwrap_or(false);
                if popped {
                    components.pop();
                } else {
                    components.push(component);
                }
            }
            std::path::Component::CurDir => {} // skip `.`
            other => components.push(other),
        }
    }
    components.iter().collect()
}

/// Find the end of an `@Component(...)` block by counting parenthesis depth.
/// Handles string literals so inner parens inside strings are not counted.
fn find_decorator_end(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut string_char = ' ';

    for (i, ch) in s.char_indices() {
        if in_string {
            if ch == string_char {
                in_string = false;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                in_string = true;
                string_char = ch;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const COMPONENT_MULTILINE: &str = r#"
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-hero',
  templateUrl: './hero.component.html',
  styleUrls: ['./hero.component.css', '../shared/common.css']
})
export class HeroComponent implements OnInit {}
"#;

    const COMPONENT_COMPACT: &str = r#"
@Component({ selector: 'app-dash', templateUrl: './dash.html', styleUrls: ['./dash.css'] })
export class DashComponent {}
"#;

    const COMPONENT_INLINE: &str = r#"
@Component({ selector: 'app-inline', template: '<div>hello</div>' })
export class InlineComponent {}
"#;

    #[test]
    fn test_extract_multiline_decorator() {
        let path = PathBuf::from("/app/src/hero/hero.component.ts");
        let info =
            extract_component_info(&path, COMPONENT_MULTILINE).expect("Should find @Component");
        assert_eq!(info.selector.as_deref(), Some("app-hero"));
        assert_eq!(
            info.template_file,
            Some(PathBuf::from("/app/src/hero/hero.component.html"))
        );
        assert_eq!(info.style_files.len(), 2);
        assert_eq!(
            info.style_files[0],
            PathBuf::from("/app/src/hero/hero.component.css")
        );
        assert_eq!(
            info.style_files[1],
            PathBuf::from("/app/src/shared/common.css")
        );
    }

    #[test]
    fn test_extract_compact_decorator() {
        let path = PathBuf::from("/app/src/dash/dash.component.ts");
        let info =
            extract_component_info(&path, COMPONENT_COMPACT).expect("Should find @Component");
        assert_eq!(info.selector.as_deref(), Some("app-dash"));
        assert_eq!(
            info.template_file,
            Some(PathBuf::from("/app/src/dash/dash.html"))
        );
        assert_eq!(info.style_files.len(), 1);
    }

    #[test]
    fn test_extract_inline_no_template_url() {
        let path = PathBuf::from("/app/src/inline.component.ts");
        let info = extract_component_info(&path, COMPONENT_INLINE).expect("Should find @Component");
        assert_eq!(info.selector.as_deref(), Some("app-inline"));
        assert!(info.template_file.is_none());
        assert!(info.style_files.is_empty());
    }

    #[test]
    fn test_no_component_decorator() {
        let path = PathBuf::from("/app/src/service.ts");
        let source = "export class HeroService { load() {} }";
        assert!(extract_component_info(&path, source).is_none());
    }

    #[test]
    fn test_resolve_relative() {
        let base = PathBuf::from("/app/src/hero/hero.component.ts");
        assert_eq!(
            resolve_relative(&base, "./hero.component.html"),
            PathBuf::from("/app/src/hero/hero.component.html")
        );
        assert_eq!(
            resolve_relative(&base, "../shared/common.css"),
            PathBuf::from("/app/src/shared/common.css")
        );
    }
}
