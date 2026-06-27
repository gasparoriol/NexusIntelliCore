use anyhow::Result;
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

const ANGULAR_LINT_MAX_ITEMS: usize = 5;

pub(super) async fn analyze_angular_component(component_path: &str) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let ts_path = match state.validate_path(Path::new(component_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {}", e))),
    };

    let index = state.index().await?;
    if index.is_restricted(&ts_path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied by .mcpignore policy: {}",
            component_path
        ))]));
    }
    drop(index);

    // Read TS source and extract @Component decorator
    let ts_path_clone = ts_path.clone();
    let source =
        match tokio::task::spawn_blocking(move || std::fs::read_to_string(&ts_path_clone)).await? {
            Ok(s) => s,
            Err(e) => {
                return Ok(error_response(format!(
                    "Cannot read {}: {}",
                    component_path, e
                )))
            }
        };

    let info = match crate::relations::extract_component_info(&ts_path, &source) {
        Some(i) => i,
        None => {
            return Ok(tool_response(vec![text_content(format!(
                "No @Component decorator found in {}.\n\
                 This file does not appear to be an Angular component.",
                component_path
            ))]))
        }
    };

    // Analyse the .ts file itself (for class names / methods)
    let ts_analysis = state.get_analysis(&ts_path).await.ok();
    let component_lint = if state.lint_pool().enabled() {
        match ts_analysis.as_ref() {
            Some(analysis) => {
                Some(build_lint_section(state, &ts_path, analysis, ANGULAR_LINT_MAX_ITEMS).await)
            }
            None => None,
        }
    } else {
        None
    };

    // Analyse the template file (HTML)
    let template_analysis = if let Some(ref tmpl_path) = info.template_file {
        match state.validate_path(tmpl_path) {
            Ok(valid_path) => state
                .get_analysis(&valid_path)
                .await
                .ok()
                .map(|analysis| (valid_path, analysis)),
            Err(_) => None,
        }
    } else {
        None
    };

    // Analyse each style file (CSS / SCSS detected-only)
    let mut style_analyses: Vec<(String, std::path::PathBuf, crate::analyzer::FileAnalysis)> =
        Vec::new();
    for style_path in &info.style_files {
        if let Ok(valid_path) = state.validate_path(style_path) {
            if let Ok(analysis) = state.get_analysis(&valid_path).await {
                style_analyses.push((style_path.display().to_string(), valid_path, analysis));
            }
        }
    }

    // --- Build response ---

    let mut component_section = Map::new();
    component_section.insert("ts_file".to_string(), json!(component_path));
    component_section.insert("selector".to_string(), json!(info.selector));
    component_section.insert(
        "class".to_string(),
        json!(ts_analysis
            .as_ref()
            .and_then(|a| a.classes.first())
            .map(|c| c.name.as_str())),
    );
    component_section.insert(
        "template_file".to_string(),
        json!(info.template_file.as_ref().map(|p| p.display().to_string())),
    );
    component_section.insert(
        "style_files".to_string(),
        json!(info
            .style_files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()),
    );
    if let Some(lint) = component_lint {
        component_section.insert("lint".to_string(), lint);
    }

    let template_section = if let Some((template_path, tmpl)) = template_analysis.as_ref() {
        let elements: Vec<_> = tmpl
            .html_elements
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|e| {
                json!({
                    "tag": e.tag_name,
                    "is_component": e.is_angular_component,
                    "classes": e.class_names,
                    "inputs": e.input_bindings,
                    "outputs": e.output_bindings,
                    "line": e.start_line,
                })
            })
            .collect();

        let angular_components: Vec<_> = tmpl
            .html_elements
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|e| e.is_angular_component)
            .map(|e| e.tag_name.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let css_classes: Vec<_> = tmpl
            .html_elements
            .as_deref()
            .unwrap_or_default()
            .iter()
            .flat_map(|e| e.class_names.iter())
            .map(|s| s.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let mut template_section = Map::new();
        template_section.insert("elements".to_string(), json!(elements));
        template_section.insert(
            "angular_components_used".to_string(),
            json!(angular_components),
        );
        template_section.insert("css_classes_used".to_string(), json!(css_classes));
        if state.lint_pool().enabled() {
            template_section.insert(
                "lint".to_string(),
                build_lint_section(state, template_path, tmpl, ANGULAR_LINT_MAX_ITEMS).await,
            );
        }
        Some(Value::Object(template_section))
    } else {
        None
    };

    let mut styles_section = Vec::with_capacity(style_analyses.len());
    for (path_str, path_buf, analysis) in &style_analyses {
        let selectors: Vec<_> = analysis
            .css_rules
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|r| {
                json!({
                    "selector": r.selector,
                    "properties": r.properties,
                    "lines": format!("{}-{}", r.start_line, r.end_line),
                    "media": r.media_query,
                })
            })
            .collect();
        let mut style_section = Map::new();
        style_section.insert("file".to_string(), json!(path_str));
        style_section.insert("language".to_string(), json!(analysis.language));
        style_section.insert("selectors".to_string(), json!(selectors));
        if state.lint_pool().enabled() {
            style_section.insert(
                "lint".to_string(),
                build_lint_section(state, path_buf, analysis, ANGULAR_LINT_MAX_ITEMS).await,
            );
        }
        styles_section.push(Value::Object(style_section));
    }

    let result = json!({
        "component": component_section,
        "template": template_section,
        "styles": styles_section,
    });

    let policy = privacy_gateway::PrivacyPolicy::default();
    let result_str = serde_json::to_string_pretty(&result).unwrap_or_default();
    let (sanitized, _) = privacy_gateway::sanitize_output_text(&result_str, &policy);

    Ok(tool_response(vec![text_content(sanitized)]))
}

async fn build_lint_section(
    state: &crate::state::ServerState,
    path: &Path,
    analysis: &crate::analyzer::FileAnalysis,
    max_items: usize,
) -> Value {
    let lint_result = state.lint_pool().get_or_schedule(path, analysis).await;
    let total = lint_result.diagnostics.len();
    let diagnostics = lint_result
        .diagnostics
        .iter()
        .take(max_items)
        .map(|diagnostic| {
            json!({
                "line": diagnostic.line,
                "column": diagnostic.column,
                "severity": diagnostic.severity.as_str(),
                "message": diagnostic.message,
                "rule_id": diagnostic.rule_id,
                "source": diagnostic.source,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "enabled": state.lint_pool().enabled(),
        "file": path.display().to_string(),
        "diagnostic_count": total,
        "omitted_diagnostics": total.saturating_sub(max_items),
        "diagnostics": diagnostics,
        "sources": lint_result.sources,
        "error": lint_result.error,
    })
}
