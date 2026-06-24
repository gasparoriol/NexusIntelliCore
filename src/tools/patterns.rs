use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Instant;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

const DEFAULT_MAX_FILES: usize = 100;
const DEFAULT_MAX_MATCHES: usize = 200;
const MAX_RESPONSE_BYTES: usize = 25 * 1024;

#[derive(Debug, Clone)]
struct QueryParams {
    mode: String,
    file_path: Option<String>,
    scope_path: Option<String>,
    max_files: usize,
    max_matches: usize,
    sort_by: String,
}

impl QueryParams {
    fn from_args(args: &Value) -> Self {
        Self {
            mode: args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("summary")
                .to_string(),
            file_path: args
                .get("file_path")
                .and_then(|v| v.as_str())
                .map(String::from),
            scope_path: args
                .get("scope_path")
                .and_then(|v| v.as_str())
                .map(String::from),
            max_files: args
                .get("max_files")
                .and_then(|v| v.as_u64())
                .map(|n| (n as usize).min(500))
                .unwrap_or(DEFAULT_MAX_FILES),
            max_matches: args
                .get("max_matches")
                .and_then(|v| v.as_u64())
                .map(|n| (n as usize).min(2000))
                .unwrap_or(DEFAULT_MAX_MATCHES),
            sort_by: args
                .get("sort_by")
                .and_then(|v| v.as_str())
                .unwrap_or("pattern")
                .to_string(),
        }
    }
}

fn sort_patterns(items: &mut [analyzer::PatternMatch], sort_by: &str) {
    match sort_by {
        "file" => items.sort_by(|a, b| a.file.cmp(&b.file).then_with(|| a.line.cmp(&b.line))),
        "line" => items.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.file.cmp(&b.file))),
        _ => items.sort_by(|a, b| {
            a.pattern
                .cmp(&b.pattern)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        }),
    }
}

fn ensure_budget(mut payload: Value, max_bytes: usize) -> (Value, usize, bool, Option<String>) {
    let mut bytes = serde_json::to_string(&payload)
        .map(|s| s.len())
        .unwrap_or(0);
    if bytes <= max_bytes {
        return (payload, bytes, false, None);
    }

    loop {
        bytes = serde_json::to_string(&payload)
            .map(|s| s.len())
            .unwrap_or(0);
        if bytes <= max_bytes {
            return (
                payload,
                bytes,
                true,
                Some("response_bytes_limit_matches_trimmed".to_string()),
            );
        }

        let removed = payload
            .get_mut("matches")
            .and_then(|v| v.as_array_mut())
            .and_then(|arr| arr.pop())
            .is_some();

        if !removed {
            bytes = serde_json::to_string(&payload)
                .map(|s| s.len())
                .unwrap_or(0);
            return (
                payload,
                bytes,
                true,
                Some("response_bytes_limit".to_string()),
            );
        }
    }
}

pub(super) async fn search_design_patterns(args: &Value) -> Result<Value> {
    let start = Instant::now();
    let params = QueryParams::from_args(args);
    let state = crate::state::ServerState::get();
    let index = state.index().await?;

    let files: Vec<_> = if let Some(fp) = params.file_path.as_deref() {
        vec![std::path::PathBuf::from(fp)]
    } else {
        let all = index.allowed_files.clone();
        if let Some(scope) = params.scope_path.as_deref() {
            all.into_iter()
                .filter(|f| f.to_string_lossy().contains(scope))
                .collect()
        } else {
            all
        }
    };
    drop(index);

    let mut all_patterns: Vec<analyzer::PatternMatch> = Vec::new();
    let mut files_scanned = 0usize;

    for file in files.iter().take(params.max_files) {
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
        files_scanned += 1;
        let mut found = analyzer::detect_patterns(&analysis, &rel);
        all_patterns.append(&mut found);
    }

    let total_matches = all_patterns.len();

    if all_patterns.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No well-known design patterns detected in the analysed files.".to_owned(),
        )]));
    }

    sort_patterns(&mut all_patterns, &params.sort_by);

    let mut by_pattern: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_file: BTreeMap<String, usize> = BTreeMap::new();
    for p in &all_patterns {
        *by_pattern.entry(p.pattern.clone()).or_insert(0) += 1;
        *by_file.entry(p.file.clone()).or_insert(0) += 1;
    }

    let max_returned = if params.mode == "summary" {
        params.max_matches.min(100)
    } else {
        params.max_matches
    };

    let matches: Vec<Value> = all_patterns
        .iter()
        .take(max_returned)
        .map(|p| {
            json!({
                "pattern": p.pattern,
                "file": p.file,
                "line": p.line,
                "evidence": p.evidence,
            })
        })
        .collect();

    let top_patterns: Vec<Value> = by_pattern
        .iter()
        .map(|(pattern, count)| json!({"pattern": pattern, "count": count}))
        .collect();

    let top_files: Vec<Value> = by_file
        .iter()
        .map(|(file, count)| json!({"file": file, "count": count}))
        .collect();

    let payload = json!({
        "mode": params.mode,
        "matches": matches,
        "summary": {
            "total_matches": total_matches,
            "by_pattern": top_patterns,
            "top_files": top_files,
        },
        "meta": {
            "applied_filters": {
                "file_path": params.file_path,
                "scope_path": params.scope_path,
                "sort_by": params.sort_by,
            },
            "applied_limits": {
                "max_files": params.max_files,
                "max_matches": params.max_matches,
                "response_budget_bytes": MAX_RESPONSE_BYTES,
            },
            "truncated": false,
            "truncation_reason": Value::Null,
        }
    });

    let (mut budgeted, response_bytes, truncated, truncation_reason) =
        ensure_budget(payload, MAX_RESPONSE_BYTES);

    let matches_returned = budgeted
        .get("matches")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    if let Some(meta) = budgeted.get_mut("meta").and_then(|v| v.as_object_mut()) {
        meta.insert("truncated".to_string(), Value::Bool(truncated));
        meta.insert(
            "truncation_reason".to_string(),
            truncation_reason.map(Value::String).unwrap_or(Value::Null),
        );
        meta.insert(
            "metrics".to_string(),
            json!({
                "files_scanned": files_scanned,
                "matches_found": total_matches,
                "matches_returned": matches_returned,
                "response_bytes": response_bytes,
                "truncated": truncated,
                "duration_ms": start.elapsed().as_millis() as u64,
            }),
        );
    }

    let out = serde_json::to_string(&budgeted).unwrap_or_else(|_| "{}".to_string());

    // Sanitize patterns output through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_output, _redactions) = privacy_gateway::sanitize_output_text(&out, &policy);

    Ok(tool_response(vec![text_content(sanitized_output)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_params_defaults() {
        let args = json!({});
        let p = QueryParams::from_args(&args);
        assert_eq!(p.mode, "summary");
        assert_eq!(p.max_files, DEFAULT_MAX_FILES);
        assert_eq!(p.max_matches, DEFAULT_MAX_MATCHES);
        assert_eq!(p.sort_by, "pattern");
    }

    #[test]
    fn test_sort_patterns_by_file() {
        let mut items = vec![
            analyzer::PatternMatch {
                pattern: "Factory".into(),
                evidence: "e1".into(),
                file: "z.rs".into(),
                line: 20,
            },
            analyzer::PatternMatch {
                pattern: "Builder".into(),
                evidence: "e2".into(),
                file: "a.rs".into(),
                line: 10,
            },
        ];
        sort_patterns(&mut items, "file");
        assert_eq!(items[0].file, "a.rs");
    }

    #[test]
    fn test_ensure_budget_trims_matches() {
        let payload = json!({
            "matches": [
                {"pattern": "Factory", "file": "a.rs", "line": 1, "evidence": "x"},
                {"pattern": "Builder", "file": "b.rs", "line": 2, "evidence": "y"},
                {"pattern": "Observer", "file": "c.rs", "line": 3, "evidence": "z"}
            ],
            "meta": {}
        });
        let (_trimmed, bytes, truncated, _reason) = ensure_budget(payload, 120);
        assert!(truncated);
        assert!(bytes <= 120);
    }
}
