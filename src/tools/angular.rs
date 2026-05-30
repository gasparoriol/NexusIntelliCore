use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};

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

    // Analyse the template file (HTML)
    let template_analysis = if let Some(ref tmpl_path) = info.template_file {
        match state.validate_path(tmpl_path) {
            Ok(valid_path) => state.get_analysis(&valid_path).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    // Analyse each style file (CSS / SCSS detected-only)
    let mut style_analyses: Vec<(String, crate::analyzer::FileAnalysis)> = Vec::new();
    for style_path in &info.style_files {
        if let Ok(valid_path) = state.validate_path(style_path) {
            if let Ok(analysis) = state.get_analysis(&valid_path).await {
                style_analyses.push((style_path.display().to_string(), analysis));
            }
        }
    }

    // --- Build response ---

    let component_section = json!({
        "ts_file": component_path,
        "selector": info.selector,
        "class": ts_analysis.as_ref()
            .and_then(|a| a.classes.first())
            .map(|c| c.name.as_str()),
        "template_file": info.template_file.as_ref().map(|p| p.display().to_string()),
        "style_files": info.style_files.iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
    });

    let template_section = template_analysis.as_ref().map(|tmpl| {
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

        json!({
            "elements": elements,
            "angular_components_used": angular_components,
            "css_classes_used": css_classes,
        })
    });

    let styles_section: Vec<_> = style_analyses
        .iter()
        .map(|(path_str, analysis)| {
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
            json!({
                "file": path_str,
                "language": analysis.language,
                "selectors": selectors,
            })
        })
        .collect();

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
