/// The six MCP tools exposed by this server.
///
/// All tool outputs pass through the Phase-4 Privacy Gateway before being
/// returned: secrets are redacted, @mcp-strip function bodies are replaced
/// with a placeholder, and sensitive comments are removed.
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::Result;
use petgraph::Graph;
use serde_json::{json, Value};

use crate::analyzer;
use crate::indexer::FileIndex;
use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};
use crate::sanitizer;

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

/// JSON Schema definitions returned by `tools/list`.
pub fn tool_definitions() -> Value {
    json!([
        {
            "name": "get_project_structure",
            "description": "Returns the project directory tree. Files protected by .mcpignore are labelled '(Acceso Restringido)' and their contents are never exposed.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_file_outline",
            "description": "Returns a structural map of a file: class names, function signatures, and imports. Restricted files return an access-denied notice.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to outline"
                    }
                },
                "required": ["file_path"]
            }
        },
        {
            "name": "inspect_symbol",
            "description": "Returns the source of a specific function or method. The output passes through the full Phase-4 sanitization pipeline.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file containing the symbol"
                    },
                    "symbol_name": {
                        "type": "string",
                        "description": "Exact name of the function or method to inspect"
                    }
                },
                "required": ["file_path", "symbol_name"]
            }
        },
        {
            "name": "get_dependencies_graph",
            "description": "Analyses import/use statements across the project and returns a JSON dependency graph (nodes = files, edges = import relationships).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "search_design_patterns",
            "description": "Heuristically detects common design patterns (Singleton, Builder, Factory, Observer, Repository, Strategy) across the project or in a single file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Optional: restrict analysis to a single file"
                    }
                },
                "required": []
            }
        },
        {
            "name": "audit_security_measures",
            "description": "Scans the project for security issues: hardcoded secrets, unsafe code blocks, eval/exec calls, and SQL-injection risks. Detected secret VALUES are never returned — only their type and line number are reported.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "refresh_index",
            "description": "Rebuilds the project file index from disk and clears the AST cache. Use this when files are added/removed or to free memory. Returns statistics on files indexed and cache cleared.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_server_stats",
            "description": "Returns server statistics: AST cache size, index metadata, and uptime. Debug-only tool (requires RUST_LOG=debug).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    ])
}

/// Dispatch a `tools/call` request to the appropriate handler.
pub async fn dispatch_tool(name: &str, args: Value) -> Result<Value> {
    match name {
        "get_project_structure" => get_project_structure().await,
        "get_file_outline" => {
            let file = require_str(&args, "file_path")?;
            get_file_outline(file).await
        }
        "inspect_symbol" => {
            let file = require_str(&args, "file_path")?;
            let symbol = require_str(&args, "symbol_name")?;
            inspect_symbol(file, symbol).await
        }
        "get_dependencies_graph" => get_dependencies_graph().await,
        "search_design_patterns" => {
            let file = args.get("file_path").and_then(|v| v.as_str());
            search_design_patterns(file).await
        }
        "audit_security_measures" => audit_security_measures().await,
        "refresh_index" => refresh_index().await,
        "get_server_stats" => get_server_stats().await,
        other => Ok(error_response(format!("Unknown tool: {}", other))),
    }
}

// ---------------------------------------------------------------------------
// Tool 1 — get_project_structure
// ---------------------------------------------------------------------------

async fn get_project_structure() -> Result<Value> {
    let state = crate::state::ServerState::get();
    let index = state.index().await?;
    let tree = index.render_tree();

    let summary = format!(
        "Project root: {}\nAllowed files: {}\nRestricted files: {}\n\n{}",
        state.root().display(),
        index.allowed_files.len(),
        index.restricted_files.len(),
        tree
    );

    // Sanitize structure output through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_summary, _redactions) = privacy_gateway::sanitize_output_text(&summary, &policy);

    Ok(tool_response(vec![text_content(sanitized_summary)]))
}

// ---------------------------------------------------------------------------
// Tool 2 — get_file_outline
// ---------------------------------------------------------------------------

async fn get_file_outline(file_path: &str) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {}", e))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied by .mcpignore policy: {}\n\
             The file exists but its implementation cannot be exposed to the LLM.",
            file_path
        ))]));
    }
    drop(index);

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {}", e))),
    };

    let mut out = String::new();
    out.push_str(&format!(
        "# File outline: {}\nLanguage: {}\n\n",
        file_path, analysis.language
    ));

    // Imports
    if !analysis.imports.is_empty() {
        out.push_str("## Imports\n");
        let policy = privacy_gateway::PrivacyPolicy::default();
        for imp in &analysis.imports {
            // Sanitize import strings (may contain internal hostnames, etc.)
            let (sanitized_import, _redactions) =
                privacy_gateway::sanitize_import(&imp.raw, &policy);
            out.push_str(&format!("  {}\n", sanitized_import));
        }
        out.push('\n');
    }

    // Classes / structs / traits
    if !analysis.classes.is_empty() {
        out.push_str("## Types\n");
        for cls in &analysis.classes {
            out.push_str(&format!(
                "  {} {} (lines {}-{})\n",
                cls.kind, cls.name, cls.start_line, cls.end_line
            ));
        }
        out.push('\n');
    }

    // Functions
    if !analysis.functions.is_empty() {
        out.push_str("## Functions / Methods\n");
        for func in &analysis.functions {
            if func.is_strip_marked {
                out.push_str(&format!(
                    "  {} — [implementation restricted by @mcp-strip] (lines {}-{})\n",
                    func.signature, func.start_line, func.end_line
                ));
            } else {
                out.push_str(&format!(
                    "  {} (lines {}-{})\n",
                    func.signature, func.start_line, func.end_line
                ));
            }
        }
    }

    // Sanitize the entire outline through the Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_outline, _redactions) = privacy_gateway::sanitize_file_outline(&out, &policy);

    Ok(tool_response(vec![text_content(sanitized_outline)]))
}

// ---------------------------------------------------------------------------
// Tool 3 — inspect_symbol
// ---------------------------------------------------------------------------

async fn inspect_symbol(file_path: &str, symbol_name: &str) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let path = match state.validate_path(Path::new(file_path)) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(format!("Access denied: {}", e))),
    };

    let index = state.index().await?;
    if index.is_restricted(&path) {
        return Ok(tool_response(vec![text_content(format!(
            "⚠ Access denied: {} is protected by .mcpignore.\n\
             The symbol '{}' exists but cannot be inspected.",
            file_path, symbol_name
        ))]));
    }
    drop(index);

    let analysis = match state.get_analysis(&path).await {
        Ok(a) => a,
        Err(e) => return Ok(error_response(format!("Analysis error: {}", e))),
    };

    let func = match analysis.functions.iter().find(|f| f.name == symbol_name) {
        Some(f) => f,
        None => {
            return Ok(tool_response(vec![text_content(format!(
                "Symbol '{}' not found in {}.\n\
                 Available functions: {}",
                symbol_name,
                file_path,
                analysis
                    .functions
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))]))
        }
    };

    // Phase 4 — Apply Privacy Gateway sanitization pipeline
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_code, redactions) = privacy_gateway::sanitize_function_source(
        &func.body_source,
        &func.signature,
        &analysis.language,
        &policy,
    );

    let mut out = format!(
        "// Symbol: {} in {}\n// Lines {}-{}\n\n{}",
        symbol_name, file_path, func.start_line, func.end_line, sanitized_code
    );

    if !redactions.is_empty() {
        out.push_str(&format!(
            "\n\n// ⚠ MCP Privacy Gateway: the following were redacted: {}",
            redactions.join(", ")
        ));
    }

    Ok(tool_response(vec![text_content(out)]))
}

// ---------------------------------------------------------------------------
// Tool 4 — get_dependencies_graph
// ---------------------------------------------------------------------------

async fn get_dependencies_graph() -> Result<Value> {
    let state = crate::state::ServerState::get();
    let index = state.index().await?;

    // node_id → file path (relative)
    let mut node_map: HashMap<String, u32> = HashMap::new();
    let mut graph: Graph<String, ()> = Graph::new();

    // Closure to get-or-create a node
    let mut get_node = |g: &mut Graph<String, ()>, key: &str| -> u32 {
        if let Some(&idx) = node_map.get(key) {
            idx
        } else {
            let idx = g.add_node(key.to_owned()).index() as u32;
            node_map.insert(key.to_owned(), idx);
            idx
        }
    };

    let allowed_files = index.allowed_files.clone();
    drop(index);

    for file in &allowed_files {
        let path = match state.validate_path(file) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        let analysis = match state.get_analysis(&path).await {
            Ok(a) => a,
            Err(_) => continue,
        };

        let src_idx = get_node(&mut graph, &rel);

        let index_read = state.index().await?;
        for imp in &analysis.imports {
            // Normalise the import path to a candidate file path
            let target = resolve_import_path(&imp.path, &rel, &index_read);
            let tgt_idx = get_node(&mut graph, &target);
            if src_idx != tgt_idx {
                use petgraph::graph::NodeIndex;
                graph.add_edge(
                    NodeIndex::new(src_idx as usize),
                    NodeIndex::new(tgt_idx as usize),
                    (),
                );
            }
        }
        drop(index_read);
    }

    // Serialise to JSON.
    // Nodes are objects with an "id" field so the Privacy Gateway can locate
    // and sanitize the path strings. Edges use "source"/"target" for the same
    // reason — bare-string or "from"/"to" schemas were silently skipped by the
    // sanitizer because the field names didn't match.
    let nodes: Vec<Value> = graph.node_weights().map(|s| json!({ "id": s })).collect();
    let edges: Vec<Value> = graph
        .edge_indices()
        .map(|e| {
            let (a, b) = graph.edge_endpoints(e).unwrap();
            json!({
                "source": graph[a],
                "target": graph[b]
            })
        })
        .collect();

    let result = json!({
        "nodes": nodes,
        "edges": edges,
        "node_count": nodes.len(),
        "edge_count": edges.len()
    });

    // Sanitize the graph JSON through the Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_graph, _redactions) =
        privacy_gateway::sanitize_dependency_graph(&result, &policy);

    Ok(tool_response(vec![text_content(
        serde_json::to_string_pretty(&sanitized_graph).unwrap_or_default(),
    )]))
}

/// Attempt to map an import path to a relative file path within the project.
///
/// - For Rust: `foo::bar` → search for `foo/bar`
/// - For Python/Java: `pkg.mod` → search for `pkg/mod`
/// - For JS/TS: preserve path as-is (`./utils/parser.ts` stays as-is, no transformation)
fn resolve_import_path(import_path: &str, _from_file: &str, index: &FileIndex) -> String {
    let normalised = if import_path.starts_with("./") || import_path.starts_with("../") {
        // JS/TS relative import — preserve as-is (already has `/`)
        import_path.to_owned()
    } else if import_path.contains("::") {
        // Rust namespace separator
        import_path.replace("::", "/")
    } else if import_path.contains(".") && !import_path.contains("/") {
        // Python or Java package notation (dots without any slashes yet)
        // Only replace dots that separate package components, not file extensions
        import_path.replace(".", "/")
    } else {
        // Already looks like a path or unknown format
        import_path.to_owned()
    }
    .trim_matches('/')
    .to_owned();

    // Try to find a matching file in the allowed list
    for file in &index.allowed_files {
        let rel = index.relative(file).to_string_lossy().into_owned();
        let stem = rel
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");
        if stem.ends_with(&normalised) || rel.contains(&normalised) {
            return rel;
        }
    }

    // Return the normalized path if no file matched
    normalised
}

// ---------------------------------------------------------------------------
// Tool 5 — search_design_patterns
// ---------------------------------------------------------------------------

async fn search_design_patterns(file_path: Option<&str>) -> Result<Value> {
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

// ---------------------------------------------------------------------------
// Tool 6 — audit_security_measures
// ---------------------------------------------------------------------------

async fn audit_security_measures() -> Result<Value> {
    let state = crate::state::ServerState::get();
    let index = state.index().await?;

    #[derive(Default)]
    struct Report {
        secrets: Vec<String>,       // (file, line, secret_type) — NO values
        unsafe_blocks: Vec<String>, // Rust unsafe
        eval_calls: Vec<String>,    // Python/JS eval/exec
        sql_risks: Vec<String>,     // potential SQL injection
    }

    let mut report = Report::default();
    let allowed_files = index.allowed_files.clone();
    let restricted_len = index.restricted_files.len();
    drop(index);

    for file in &allowed_files {
        let path = match state.validate_path(file) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        // Read the file in a spawn_blocking block to avoid blocking the event loop
        let path_clone = path.clone();
        let source = match tokio::task::spawn_blocking(move || std::fs::read_to_string(&path_clone))
            .await?
        {
            Ok(s) => s,
            Err(_) => continue,
        };

        // 4.1 — secret detection (report location, NEVER the value)
        for (secret_type, line) in sanitizer::detect_all_secrets(&source) {
            report.secrets.push(format!(
                "  ⚠ [{}] detected in {} at line {}",
                secret_type, rel, line
            ));
        }

        // Unsafe blocks (Rust)
        for (lineno, line) in source.lines().enumerate() {
            let lineno = lineno + 1;
            if line.contains("unsafe {") || line.contains("unsafe fn") {
                report
                    .unsafe_blocks
                    .push(format!("  ⚠ Unsafe block in {} at line {}", rel, lineno));
            }

            // eval / exec calls (Python / JS)
            if line.contains("eval(") || line.contains("exec(") {
                report
                    .eval_calls
                    .push(format!("  ⚠ eval/exec call in {} at line {}", rel, lineno));
            }

            // Naive SQL injection risk: string concatenation inside a SQL-like call
            let lower = line.to_lowercase();
            if (lower.contains("select ") || lower.contains("insert ") || lower.contains("delete "))
                && (line.contains('+') || line.contains("format!") || line.contains("concat"))
            {
                report.sql_risks.push(format!(
                    "  ⚠ Potential SQL injection via string concatenation in {} at line {}",
                    rel, lineno
                ));
            }
        }
    }

    let mut out = String::from("# Security Audit Report\n\n");

    out.push_str(&format!(
        "Files scanned: {}\nRestricted files (not scanned): {}\n\n",
        allowed_files.len(),
        restricted_len
    ));

    // Secrets section
    out.push_str("## Hardcoded Secrets\n");
    if report.secrets.is_empty() {
        out.push_str("  ✓ No hardcoded secrets detected.\n");
    } else {
        out.push_str("  NOTE: Secret values are NEVER included in this report. Only type and location are shown.\n");
        for s in &report.secrets {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // Unsafe code
    out.push_str("## Unsafe Code Blocks (Rust)\n");
    if report.unsafe_blocks.is_empty() {
        out.push_str("  ✓ No unsafe blocks detected.\n");
    } else {
        for s in &report.unsafe_blocks {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // eval/exec
    out.push_str("## Dynamic Code Execution (eval/exec)\n");
    if report.eval_calls.is_empty() {
        out.push_str("  ✓ No eval/exec calls detected.\n");
    } else {
        for s in &report.eval_calls {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // SQL injection
    out.push_str("## SQL Injection Risks\n");
    if report.sql_risks.is_empty() {
        out.push_str("  ✓ No SQL injection patterns detected.\n");
    } else {
        for s in &report.sql_risks {
            out.push_str(s);
            out.push('\n');
        }
    }

    // Summary
    let total_issues = report.secrets.len()
        + report.unsafe_blocks.len()
        + report.eval_calls.len()
        + report.sql_risks.len();
    out.push_str(&format!(
        "\n## Summary\nTotal issues found: {}\n",
        total_issues
    ));

    // Sanitize security report through Privacy Gateway (extra validation layer)
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_report, _redactions) = privacy_gateway::sanitize_security_report(&out, &policy);

    Ok(tool_response(vec![text_content(sanitized_report)]))
}

// ---------------------------------------------------------------------------
// Tool 7 — refresh_index
// ---------------------------------------------------------------------------

/// Rebuilds the project file index from disk and clears the AST cache.
/// Use this when files are added/removed or to free memory.
async fn refresh_index() -> Result<Value> {
    let state = crate::state::ServerState::get();

    // Rebuild index and clear cache
    let (files_found, cache_cleared) = match state.refresh_index().await {
        Ok((files, cleared)) => (files, cleared),
        Err(e) => return Ok(error_response(format!("Index rebuild failed: {}", e))),
    };

    let msg = format!(
        "Index refreshed successfully:\n\
         • Files indexed: {}\n\
         • AST cache entries cleared: {}\n\
         \n\
         The project index and AST cache are now up-to-date with the current filesystem state.",
        files_found, cache_cleared
    );

    Ok(tool_response(vec![text_content(msg)]))
}

// ---------------------------------------------------------------------------
// Tool 8 — get_server_stats
// ---------------------------------------------------------------------------

/// Returns server statistics: cache size, index metadata, uptime.
/// Debug-only tool (requires RUST_LOG=debug).
async fn get_server_stats() -> Result<Value> {
    // Check if debug logging is enabled
    if std::env::var("RUST_LOG")
        .ok()
        .map(|s| !s.contains("debug"))
        .unwrap_or(true)
    {
        return Ok(tool_response(vec![text_content(
            "⚠ get_server_stats is only available in debug mode.\n\
             Enable with: RUST_LOG=debug or higher (trace)"
                .to_string(),
        )]));
    }

    let state = crate::state::ServerState::get();
    let (cache_entries, cache_max) = state.get_cache_stats().await;
    let index = state.index().await?;

    let stats_json = json!({
        "cache": {
            "entries": cache_entries,
            "max_entries": cache_max,
            "utilization_percent": if cache_max > 0 { (cache_entries * 100) / cache_max } else { 0 }
        },
        "index": {
            "allowed_files": index.allowed_files.len(),
            "restricted_files": index.restricted_files.len(),
            "total_files": index.allowed_files.len() + index.restricted_files.len()
        },
        "root": state.root().display().to_string()
    });

    let msg = format!(
        "## Server Statistics\n\n\
         ### AST Cache\n\
         - Entries: {}/{} ({:.1}% full)\n\
         \n\
         ### Project Index\n\
         - Allowed files: {}\n\
         - Restricted files: {}\n\
         - Total files: {}\n\
         \n\
         ### Configuration\n\
         - Root: {}\n\
         \n\
         **Raw JSON:**\n\
         ```json\n\
         {}\n\
         ```",
        cache_entries,
        cache_max,
        if cache_max > 0 {
            (cache_entries as f64 / cache_max as f64) * 100.0
        } else {
            0.0
        },
        index.allowed_files.len(),
        index.restricted_files.len(),
        index.allowed_files.len() + index.restricted_files.len(),
        state.root().display(),
        serde_json::to_string_pretty(&stats_json)?
    );

    Ok(tool_response(vec![text_content(msg)]))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {}", key))
}
