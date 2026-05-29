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
        },
        {
            "name": "analyze_angular_component",
            "description": "Analyses an Angular component (*.component.ts) and returns the resolved TS → HTML → CSS graph: selector, class name, template elements, Angular components used, CSS classes referenced, and style selectors.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "component_path": {
                        "type": "string",
                        "description": "Absolute path to the Angular *.component.ts file"
                    }
                },
                "required": ["component_path"]
            }
        },
        {
            "name": "get_module_summary",
            "description": "Generates a functional summary of a source file: module-level documentation, public and private symbols with their doc comments, and a breakdown of external vs internal imports. Useful for understanding the purpose and API surface of a module without reading its full source.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the source file to summarize"
                    },
                    "public_only": {
                        "type": "boolean",
                        "description": "If true, only include publicly visible symbols (default: false)"
                    }
                },
                "required": ["file_path"]
            }
        },
        {
            "name": "generate_project_docs",
            "description": "Analyses the indexed project and generates user-facing Markdown documentation: what the application does, how to use it, its public API surface, and inferred practical use cases. Designed for the end-user of the analysed application, not for the developer modifying its source code.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sections": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["overview", "usage", "api", "use_cases"]
                        },
                        "description": "Sections to include. Defaults to all four: overview, usage, api, use_cases."
                    },
                    "public_only": {
                        "type": "boolean",
                        "description": "If true, omit private symbols from the API section (default: true)."
                    },
                    "max_files": {
                        "type": "integer",
                        "description": "Maximum number of source files to analyse. Default: 50. Server-side ceiling: 150.",
                        "minimum": 1
                    },
                    "language": {
                        "type": "string",
                        "enum": ["en", "es"],
                        "description": "Language for generated headings and inferred descriptions (default: en). Does not translate doc-comments."
                    }
                },
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
        "analyze_angular_component" => {
            let path = require_str(&args, "component_path")?;
            analyze_angular_component(path).await
        }
        "get_module_summary" => {
            let file = require_str(&args, "file_path")?;
            let public_only = args
                .get("public_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            get_module_summary(file, public_only).await
        }
        "generate_project_docs" => {
            let sections: Vec<String> = args
                .get("sections")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| {
                    vec![
                        "overview".into(),
                        "usage".into(),
                        "api".into(),
                        "use_cases".into(),
                    ]
                });
            let public_only = args
                .get("public_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let max_files = args
                .get("max_files")
                .and_then(|v| v.as_u64())
                .map(|n| (n as usize).min(150))
                .unwrap_or(50);
            let language = args
                .get("language")
                .and_then(|v| v.as_str())
                .unwrap_or("en")
                .to_owned();
            generate_project_docs(sections, public_only, max_files, &language).await
        }
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

    // CSS selectors
    if let Some(css_rules) = &analysis.css_rules {
        if !css_rules.is_empty() {
            out.push_str("## CSS Selectors\n");
            for rule in css_rules {
                let media = rule
                    .media_query
                    .as_deref()
                    .map(|q| format!(" [@media {}]", q))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  {} ({} props, lines {}-{}){}\n",
                    rule.selector,
                    rule.properties.len(),
                    rule.start_line,
                    rule.end_line,
                    media
                ));
            }
            out.push('\n');
        }
    }

    // HTML elements
    if let Some(html_elements) = &analysis.html_elements {
        let components: Vec<_> = html_elements
            .iter()
            .filter(|e| e.is_angular_component)
            .map(|e| e.tag_name.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let all_classes: Vec<_> = html_elements
            .iter()
            .flat_map(|e| e.class_names.iter())
            .map(|s| s.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        if !components.is_empty() {
            out.push_str("## Angular Components Used\n");
            for c in &components {
                out.push_str(&format!("  {}\n", c));
            }
            out.push('\n');
        }
        if !all_classes.is_empty() {
            out.push_str("## CSS Classes Referenced\n");
            for cls in &all_classes {
                out.push_str(&format!("  .{}\n", cls));
            }
            out.push('\n');
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
// Tool 9 — analyze_angular_component
// ---------------------------------------------------------------------------

async fn analyze_angular_component(component_path: &str) -> Result<Value> {
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

// ---------------------------------------------------------------------------
// Tool 10 — get_module_summary
// ---------------------------------------------------------------------------

async fn get_module_summary(file_path: &str, public_only: bool) -> Result<Value> {
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

    let policy = privacy_gateway::PrivacyPolicy::default();
    let mut out = String::new();

    // --- Header ---
    out.push_str(&format!(
        "# Module summary: {}\nLanguage: {}\n\n",
        file_path, analysis.language
    ));

    // --- Module-level doc ---
    if let Some(ref mdoc) = analysis.module_doc {
        let (clean, _) = privacy_gateway::sanitize_doc_comment(mdoc, &policy);
        out.push_str("## Module documentation\n");
        for line in clean.lines() {
            out.push_str(&format!("  {}\n", line));
        }
        out.push('\n');
    }

    // --- Functions ---
    let public_fns: Vec<_> = analysis.functions.iter().filter(|f| f.is_public).collect();
    let private_fns: Vec<_> = analysis.functions.iter().filter(|f| !f.is_public).collect();

    if !public_fns.is_empty() {
        out.push_str(&format!("## Public functions ({})\n", public_fns.len()));
        for func in &public_fns {
            if func.is_strip_marked {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n  [implementation restricted by @mcp-strip]\n",
                    func.signature, func.start_line, func.end_line
                ));
            } else {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n",
                    func.signature, func.start_line, func.end_line
                ));
            }
            if let Some(ref doc) = func.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    }

    if !private_fns.is_empty() && !public_only {
        out.push_str(&format!("## Private functions ({})\n", private_fns.len()));
        for func in &private_fns {
            if func.is_strip_marked {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n  [implementation restricted by @mcp-strip]\n",
                    func.signature, func.start_line, func.end_line
                ));
            } else {
                out.push_str(&format!(
                    "### {}  [lines {}-{}]\n",
                    func.signature, func.start_line, func.end_line
                ));
            }
            if let Some(ref doc) = func.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    } else if !private_fns.is_empty() && public_only {
        let names: Vec<&str> = private_fns.iter().map(|f| f.name.as_str()).collect();
        out.push_str(&format!(
            "## Private functions ({}) — hidden (public_only=true)\n  {}\n\n",
            private_fns.len(),
            names.join(", ")
        ));
    }

    if analysis.functions.is_empty() {
        out.push_str("## Functions\n  (none found)\n\n");
    }

    // --- Types ---
    let public_types: Vec<_> = analysis.classes.iter().filter(|c| c.is_public).collect();
    let private_types: Vec<_> = analysis.classes.iter().filter(|c| !c.is_public).collect();

    if !public_types.is_empty() {
        out.push_str(&format!("## Public types ({})\n", public_types.len()));
        for cls in &public_types {
            out.push_str(&format!(
                "### {} {}  [lines {}-{}]\n",
                cls.kind, cls.name, cls.start_line, cls.end_line
            ));
            if let Some(ref doc) = cls.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    }

    if !private_types.is_empty() && !public_only {
        out.push_str(&format!("## Private types ({})\n", private_types.len()));
        for cls in &private_types {
            out.push_str(&format!(
                "### {} {}  [lines {}-{}]\n",
                cls.kind, cls.name, cls.start_line, cls.end_line
            ));
            if let Some(ref doc) = cls.doc_comment {
                let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
                for line in clean.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            } else {
                out.push_str("  (no documentation)\n");
            }
            out.push('\n');
        }
    } else if !private_types.is_empty() && public_only {
        let names: Vec<&str> = private_types.iter().map(|c| c.name.as_str()).collect();
        out.push_str(&format!(
            "## Private types ({}) — hidden (public_only=true)\n  {}\n\n",
            private_types.len(),
            names.join(", ")
        ));
    }

    // --- Imports: split external vs internal ---
    if !analysis.imports.is_empty() {
        let mut external: Vec<String> = Vec::new();
        let mut internal: Vec<String> = Vec::new();

        for imp in &analysis.imports {
            let (clean, _) = privacy_gateway::sanitize_import(&imp.raw, &policy);
            // Heuristic: internal imports start with crate::, self::, super::,
            // ./, ../ or match the language's own-project pattern.
            let is_internal = imp.path.starts_with("crate::")
                || imp.path.starts_with("self::")
                || imp.path.starts_with("super::")
                || imp.path.starts_with("./")
                || imp.path.starts_with("../");
            if is_internal {
                internal.push(clean);
            } else {
                external.push(clean);
            }
        }

        if !external.is_empty() {
            out.push_str("## External imports\n");
            for imp in &external {
                out.push_str(&format!("  {}\n", imp));
            }
            out.push('\n');
        }
        if !internal.is_empty() {
            out.push_str("## Internal imports\n");
            for imp in &internal {
                out.push_str(&format!("  {}\n", imp));
            }
            out.push('\n');
        }
    }

    // Note for Python (V1 limitation)
    if analysis.language == "python" {
        out.push_str(
            "---\n\
             ⚠ Note: Python function docstrings (inside function bodies) are not \
             extracted in V1. Only `#`-style comments preceding the `def` line \
             are shown as documentation.\n",
        );
    }

    // Final sanitization pass on the entire output
    let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
    Ok(tool_response(vec![text_content(sanitized_out)]))
}

// ---------------------------------------------------------------------------
// Tool 11 — generate_project_docs
// ---------------------------------------------------------------------------

async fn generate_project_docs(
    sections: Vec<String>,
    public_only: bool,
    max_files: usize,
    language: &str,
) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let policy = privacy_gateway::PrivacyPolicy::default();

    // --- Phase 1: build index and select files ---
    let index = state.index().await?;
    let root = state.root().to_path_buf();
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Project")
        .to_owned();

    let all_files = index.allowed_files.clone();
    drop(index);

    if all_files.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No accessible files found. The project may be fully restricted by .mcpignore."
                .to_owned(),
        )]));
    }

    // Prioritise files by depth (shallower = more likely to be core modules)
    let mut sorted_files = all_files.clone();
    sorted_files.sort_by_key(|p| {
        p.strip_prefix(&root)
            .map(|rel| rel.components().count())
            .unwrap_or(usize::MAX)
    });
    sorted_files.truncate(max_files);

    // --- Phase 2: collect FileAnalysis for each selected file ---
    let mut analyses: Vec<(std::path::PathBuf, analyzer::FileAnalysis)> = Vec::new();
    for path in &sorted_files {
        match state.get_analysis(path).await {
            Ok(a) => analyses.push((path.clone(), a)),
            Err(_) => {} // skip unreadable files silently
        }
    }

    if analyses.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No files could be analysed. Check that the project contains supported source files."
                .to_owned(),
        )]));
    }

    // --- Phase 3: detect entrypoints and infer use cases (on in-memory data) ---
    let entrypoints = analyzer::detect_entrypoints(&analyses);
    let inferred_cases = analyzer::infer_use_cases(&analyses);

    // --- Phase 4: build output ---
    let (h1, h2, h3, lbl_overview, lbl_usage, lbl_api, lbl_use_cases, lbl_no_doc, lbl_truncated) =
        if language == "es" {
            (
                "#", "##", "###",
                "Descripción general",
                "Cómo usar la aplicación",
                "API pública",
                "Casos de uso",
                "(sin documentación)",
                "> ⚠ Salida truncada: se alcanzó el límite de 2 MB. Usa `get_module_summary` en ficheros individuales para la referencia completa de la API.",
            )
        } else {
            (
                "#", "##", "###",
                "Overview",
                "How to use it",
                "Public API",
                "Use cases",
                "(undocumented)",
                "> ⚠ Output truncated: 2 MB limit reached. Use `get_module_summary` on individual files for the full API reference.",
            )
        };

    const OUTPUT_LIMIT: usize = 2 * 1024 * 1024; // 2 MB

    let mut out = String::new();
    out.push_str(&format!("{h1} {project_name}\n\n"));

    let want = |s: &str| sections.iter().any(|sec| sec == s);

    // --- Section: Overview ---
    if want("overview") {
        out.push_str(&format!("{h2} {lbl_overview}\n\n"));

        // Languages used
        let mut lang_counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (_, a) in &analyses {
            *lang_counts.entry(a.language.clone()).or_insert(0) += 1;
        }
        let lang_list: Vec<String> = lang_counts
            .iter()
            .map(|(l, n)| format!("{} ({})", l, n))
            .collect();
        out.push_str(&format!("**Languages:** {}\n\n", lang_list.join(", ")));

        // Total public symbols
        let total_pub_fns: usize = analyses
            .iter()
            .map(|(_, a)| a.functions.iter().filter(|f| f.is_public).count())
            .sum();
        let total_pub_types: usize = analyses
            .iter()
            .map(|(_, a)| a.classes.iter().filter(|c| c.is_public).count())
            .sum();
        let documented_fns: usize = analyses
            .iter()
            .map(|(_, a)| {
                a.functions
                    .iter()
                    .filter(|f| f.is_public && f.doc_comment.is_some())
                    .count()
            })
            .sum();
        out.push_str(&format!(
            "**Public symbols:** {} functions, {} types ({} documented)\n\n",
            total_pub_fns, total_pub_types, documented_fns
        ));

        // Best module-level doc found
        let best_doc = analyses
            .iter()
            .filter_map(|(_, a)| a.module_doc.as_ref().map(|d| d.as_str()))
            .next();

        if let Some(doc) = best_doc {
            let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
            out.push_str(&clean);
            out.push_str("\n\n");
        } else if language == "es" {
            out.push_str(
                "> No se encontró documentación a nivel de módulo. La siguiente descripción se \
                 infiere de la estructura del proyecto y los nombres de los símbolos.\n\n",
            );
        } else {
            out.push_str(
                "> No module-level documentation found. The following is inferred from the \
                 project structure and symbol names.\n\n",
            );
        }

        // Files analysed note
        if sorted_files.len() < all_files.len() {
            let note = if language == "es" {
                format!(
                    "> Nota: se analizaron {} de {} ficheros accesibles (límite `max_files`).\n\n",
                    sorted_files.len(),
                    all_files.len()
                )
            } else {
                format!(
                    "> Note: analysed {} of {} accessible files (`max_files` limit).\n\n",
                    sorted_files.len(),
                    all_files.len()
                )
            };
            out.push_str(&note);
        }
    }

    // --- Section: Usage ---
    if want("usage") {
        out.push_str(&format!("{h2} {lbl_usage}\n\n"));

        if entrypoints.is_empty() {
            if language == "es" {
                out.push_str(
                    "No se pudieron determinar los puntos de entrada mediante análisis estático.\n\n",
                );
            } else {
                out.push_str("Entry points could not be determined from static analysis.\n\n");
            }
        }

        for ep in &entrypoints {
            match &ep.kind {
                analyzer::EntrypointKind::MainFunction => {
                    let file_name = ep
                        .file
                        .strip_prefix(&root)
                        .unwrap_or(&ep.file)
                        .display()
                        .to_string();
                    if let Some(ref sig) = ep.signature {
                        let (clean_sig, _) = privacy_gateway::sanitize_output_text(sig, &policy);
                        out.push_str(&format!(
                            "{h3} Binary executable\n\n\
                             Entry point: `{}` in `{}`\n\n\
                             ```\n{}\n```\n\n",
                            ep.symbol.as_deref().unwrap_or("main"),
                            file_name,
                            clean_sig
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} Executable entry point\n\n\
                             `{}` in `{}`\n\n",
                            ep.symbol.as_deref().unwrap_or("main"),
                            file_name
                        ));
                    }
                }
                analyzer::EntrypointKind::CliFramework(name) => {
                    let file_name = ep
                        .file
                        .strip_prefix(&root)
                        .unwrap_or(&ep.file)
                        .display()
                        .to_string();
                    if language == "es" {
                        out.push_str(&format!(
                            "{h3} Interfaz de línea de comandos ({})\n\n\
                             Se detectó el framework CLI **{}** en `{}`.\n\n",
                            name, name, file_name
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} Command-line interface ({})\n\n\
                             CLI framework **{}** detected in `{}`.\n\n",
                            name, name, file_name
                        ));
                    }
                }
                analyzer::EntrypointKind::HttpFramework(name) => {
                    let file_name = ep
                        .file
                        .strip_prefix(&root)
                        .unwrap_or(&ep.file)
                        .display()
                        .to_string();
                    if language == "es" {
                        out.push_str(&format!(
                            "{h3} Servidor HTTP ({})\n\n\
                             Se detectó el framework HTTP **{}** en `{}`.\n\n",
                            name, name, file_name
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} HTTP server ({})\n\n\
                             HTTP framework **{}** detected in `{}`.\n\n",
                            name, name, file_name
                        ));
                    }
                }
                analyzer::EntrypointKind::LibraryCrate => {
                    if language == "es" {
                        out.push_str(&format!(
                            "{h3} Librería / módulo reutilizable\n\n\
                             No se encontró función `main`. Este proyecto expone una API pública \
                             pensada para ser importada como dependencia.\n\n"
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} Library / reusable module\n\n\
                             No `main` function found. This project exposes a public API \
                             designed to be imported as a dependency.\n\n"
                        ));
                    }
                }
            }
        }
    }

    // --- Section: API ---
    if want("api") {
        out.push_str(&format!("{h2} {lbl_api}\n\n"));

        // Group analyses by file; skip files with no public symbols
        let mut api_entry_count = 0usize;
        const MAX_API_ENTRIES: usize = 30;

        'files: for (path, analysis) in &analyses {
            let pub_fns: Vec<_> = if public_only {
                analysis.functions.iter().filter(|f| f.is_public).collect()
            } else {
                analysis.functions.iter().collect()
            };
            let pub_types: Vec<_> = if public_only {
                analysis.classes.iter().filter(|c| c.is_public).collect()
            } else {
                analysis.classes.iter().collect()
            };

            if pub_fns.is_empty() && pub_types.is_empty() {
                continue;
            }

            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string();

            out.push_str(&format!("{h3} `{}`\n\n", rel));

            // Module doc as a brief description
            if let Some(ref mdoc) = analysis.module_doc {
                let first_line = mdoc
                    .lines()
                    .find(|l| {
                        let t = l
                            .trim()
                            .trim_start_matches("//!")
                            .trim_start_matches("///")
                            .trim_start_matches("//")
                            .trim();
                        !t.is_empty()
                    })
                    .map(|l| {
                        l.trim()
                            .trim_start_matches("//!")
                            .trim_start_matches("///")
                            .trim_start_matches("//")
                            .trim()
                            .to_owned()
                    })
                    .unwrap_or_default();
                if !first_line.is_empty() {
                    let (clean, _) = privacy_gateway::sanitize_doc_comment(&first_line, &policy);
                    out.push_str(&format!("{}\n\n", clean));
                }
            }

            // Types table
            if !pub_types.is_empty() {
                out.push_str("| Type | Kind | Description |\n|---|---|---|\n");
                for cls in &pub_types {
                    let desc = cls
                        .doc_comment
                        .as_ref()
                        .and_then(|d| {
                            d.lines()
                                .find(|l| {
                                    let t = l
                                        .trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim();
                                    !t.is_empty()
                                })
                                .map(|l| {
                                    l.trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim()
                                        .to_owned()
                                })
                        })
                        .unwrap_or_else(|| lbl_no_doc.to_owned());
                    let (clean_desc, _) = privacy_gateway::sanitize_doc_comment(&desc, &policy);
                    out.push_str(&format!(
                        "| `{}` | {} | {} |\n",
                        cls.name, cls.kind, clean_desc
                    ));
                    api_entry_count += 1;
                    if api_entry_count >= MAX_API_ENTRIES {
                        out.push_str(&format!(
                            "\n> ⚠ API section truncated at {} entries. Use `get_module_summary` for the full list.\n\n",
                            MAX_API_ENTRIES
                        ));
                        break 'files;
                    }
                }
                out.push('\n');
            }

            // Functions table
            if !pub_fns.is_empty() {
                out.push_str("| Function | Description |\n|---|---|\n");
                for func in &pub_fns {
                    let desc = func
                        .doc_comment
                        .as_ref()
                        .and_then(|d| {
                            d.lines()
                                .find(|l| {
                                    let t = l
                                        .trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim();
                                    !t.is_empty()
                                })
                                .map(|l| {
                                    l.trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim()
                                        .to_owned()
                                })
                        })
                        .unwrap_or_else(|| lbl_no_doc.to_owned());
                    let (clean_sig, _) =
                        privacy_gateway::sanitize_output_text(&func.signature, &policy);
                    let (clean_desc, _) = privacy_gateway::sanitize_doc_comment(&desc, &policy);
                    let strip_note = if func.is_strip_marked {
                        " `[restricted]`"
                    } else {
                        ""
                    };
                    out.push_str(&format!(
                        "| `{}`{} | {} |\n",
                        clean_sig, strip_note, clean_desc
                    ));
                    api_entry_count += 1;
                    if api_entry_count >= MAX_API_ENTRIES {
                        out.push_str(&format!(
                            "\n> ⚠ API section truncated at {} entries. Use `get_module_summary` for the full list.\n\n",
                            MAX_API_ENTRIES
                        ));
                        break 'files;
                    }
                }
                out.push('\n');
            }

            // Size guard: bail before the output grows unbounded
            if out.len() > OUTPUT_LIMIT {
                out.push_str(lbl_truncated);
                out.push('\n');
                // Final sanitization and return early
                let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
                return Ok(tool_response(vec![text_content(sanitized_out)]));
            }
        }
    }

    // --- Section: Use cases ---
    if want("use_cases") {
        if !inferred_cases.is_empty() {
            out.push_str(&format!("{h2} {lbl_use_cases}\n\n"));
            for uc in &inferred_cases {
                let confidence_label = match uc.confidence {
                    analyzer::UseCaseConfidence::High => "",
                    analyzer::UseCaseConfidence::Medium => " *(inferred)*",
                    analyzer::UseCaseConfidence::Low => " *(low confidence)*",
                };
                out.push_str(&format!(
                    "{h3} {}{}\n\n{}\n\n",
                    uc.title, confidence_label, uc.description
                ));
            }
        } else if language == "es" {
            out.push_str(&format!("{h2} {lbl_use_cases}\n\n"));
            out.push_str(
                "> No se pudieron inferir casos de uso con suficiente confianza a partir de \
                 la documentación disponible. Usa `get_module_summary` en los módulos \
                 principales para obtener la API detallada.\n\n",
            );
        } else {
            out.push_str(&format!("{h2} {lbl_use_cases}\n\n"));
            out.push_str(
                "> Use cases could not be reliably inferred from available documentation. \
                 Use `get_module_summary` on core modules for the detailed API.\n\n",
            );
        }
    }

    // --- Final output size check and sanitization ---
    if out.len() > OUTPUT_LIMIT {
        // Truncate at a safe boundary and append notice
        let mut truncated = out[..OUTPUT_LIMIT].to_owned();
        truncated.push_str("\n\n");
        truncated.push_str(lbl_truncated);
        out = truncated;
    }

    let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
    Ok(tool_response(vec![text_content(sanitized_out)]))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {}", key))
}
