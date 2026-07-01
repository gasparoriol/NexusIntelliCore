mod level1;
mod level2;
mod pool;
mod types;

use std::collections::BTreeSet;
use std::fmt::Write as _;

pub use pool::LintPool;
pub use types::{LintDiagnostic, LintResult, Severity};

pub fn render_lint_summary(result: &LintResult) -> Option<String> {
    if result.diagnostics.is_empty() {
        return None;
    }

    let mut out = String::from("\n\n// Lint results:");
    for diagnostic in &result.diagnostics {
        let _ = write!(
            out,
            "\n// [{}] L{}:{} {}{}",
            diagnostic.severity.as_str(),
            diagnostic.line,
            diagnostic.column,
            diagnostic.message,
            diagnostic
                .rule_id
                .as_deref()
                .map(|rule| format!(" ({rule})"))
                .unwrap_or_default()
        );
    }

    if !result.sources.is_empty() {
        let _ = write!(out, "\n// Sources: {}", result.sources.join(", "));
    }

    Some(out)
}

pub fn render_lint_summary_scoped(
    result: &LintResult,
    start_line: usize,
    end_line: usize,
    max_items: usize,
) -> Option<String> {
    if result.diagnostics.is_empty() || max_items == 0 {
        return None;
    }

    let scoped = result
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            let line = diagnostic.line as usize;
            line >= start_line && line <= end_line
        })
        .collect::<Vec<_>>();

    if scoped.is_empty() {
        return None;
    }

    let mut out = String::from("\n\n// Lint results:");
    for diagnostic in scoped.iter().take(max_items) {
        let _ = write!(
            out,
            "\n// [{}] L{}:{} {}{}",
            diagnostic.severity.as_str(),
            diagnostic.line,
            diagnostic.column,
            diagnostic.message,
            diagnostic
                .rule_id
                .as_deref()
                .map(|rule| format!(" ({rule})"))
                .unwrap_or_default()
        );
    }

    if scoped.len() > max_items {
        let _ = write!(
            out,
            "\n// ... and {} more diagnostics in symbol range",
            scoped.len() - max_items
        );
    }

    let scoped_sources = scoped
        .iter()
        .map(|diagnostic| diagnostic.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !scoped_sources.is_empty() {
        let _ = write!(out, "\n// Sources: {}", scoped_sources.join(", "));
    }

    Some(out)
}
