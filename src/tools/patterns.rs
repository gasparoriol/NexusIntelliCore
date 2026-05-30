use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

pub(super) async fn search_design_patterns(file_path: Option<&str>) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let index = state.index().await?;

    let files: Vec<_> = if let Some(fp) = file_path {
        vec![std::path::PathBuf::from(fp)]
    } else {
        index.allowed_files.clone()
    };
    drop(index);

    let mut all_patterns: Vec<analyzer::PatternMatch> = Vec::new();

    for file in &files {
        let path = match state.validate_path(file) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let index_read = state.index().await?;
        if index_read.is_restricted(&path) {
            drop(index_read);
            continue;
        }
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        let analysis = match state.get_analysis(&path).await {
            Ok(a) => a,
            Err(_) => continue,
        };
        let mut found = analyzer::detect_patterns(&analysis, &rel);
        all_patterns.append(&mut found);
    }

    if all_patterns.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No well-known design patterns detected in the analysed files.".to_owned(),
        )]));
    }

    // Group by pattern name
    let mut grouped: BTreeMap<String, Vec<&analyzer::PatternMatch>> = BTreeMap::new();
    for p in &all_patterns {
        grouped.entry(p.pattern.clone()).or_default().push(p);
    }

    let mut out = String::from("# Design Patterns Detected\n\n");
    for (pattern, items) in &grouped {
        out.push_str(&format!("## {}\n", pattern));
        for item in items {
            out.push_str(&format!(
                "  • {} (line {}): {}\n",
                item.file, item.line, item.evidence
            ));
        }
        out.push('\n');
    }

    // Sanitize patterns output through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_output, _redactions) = privacy_gateway::sanitize_output_text(&out, &policy);

    Ok(tool_response(vec![text_content(sanitized_output)]))
}
