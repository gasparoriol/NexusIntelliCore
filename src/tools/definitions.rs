use serde_json::{json, Value};

pub struct ToolDefinition {
    pub name: &'static str,
    pub cacheable: bool,
    pub expensive: bool,
    pub schema: fn() -> Value,
}

pub fn all_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "get_project_structure",
            cacheable: true,
            expensive: true,
            schema: schema_get_project_structure,
        },
        ToolDefinition {
            name: "get_file_outline",
            cacheable: true,
            expensive: false,
            schema: schema_get_file_outline,
        },
        ToolDefinition {
            name: "inspect_symbol",
            cacheable: true,
            expensive: false,
            schema: schema_inspect_symbol,
        },
        ToolDefinition {
            name: "lint_file",
            cacheable: false,
            expensive: true,
            schema: schema_lint_file,
        },
        ToolDefinition {
            name: "get_dependencies_graph",
            cacheable: true,
            expensive: true,
            schema: schema_get_dependencies_graph,
        },
        ToolDefinition {
            name: "search_design_patterns",
            cacheable: true,
            expensive: true,
            schema: schema_search_design_patterns,
        },
        ToolDefinition {
            name: "audit_security_measures",
            cacheable: true,
            expensive: true,
            schema: schema_audit_security_measures,
        },
        ToolDefinition {
            name: "refresh_index",
            cacheable: false,
            expensive: true,
            schema: schema_refresh_index,
        },
        ToolDefinition {
            name: "get_server_stats",
            cacheable: false,
            expensive: false,
            schema: schema_get_server_stats,
        },
        ToolDefinition {
            name: "get_module_summary",
            cacheable: true,
            expensive: false,
            schema: schema_get_module_summary,
        },
        ToolDefinition {
            name: "generate_project_docs",
            cacheable: true,
            expensive: true,
            schema: schema_generate_project_docs,
        },
    ]
}

pub fn angular_tool_definitions() -> ToolDefinition {
    ToolDefinition {
        name: "analyze_angular_component",
        cacheable: true,
        expensive: false,
        schema: schema_analyze_angular_component,
    }
}

pub fn schema_get_project_structure() -> Value {
    json!({
        "name": "get_project_structure",
        "description": "Returns the project directory tree. Files protected by .mcpignore are labelled '(Acceso Restringido)' and their contents are never exposed.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn schema_get_file_outline() -> Value {
    json!({
        "name": "get_file_outline",
        "description": "Returns a structural map of a file: class names, canonical function/method identifiers, signatures, and imports. The canonical identifier can be passed directly to inspect_symbol with match_mode='qualified'. Restricted files return an access-denied notice. WARNING: Use to retrieve the structural map of imports and declarations. DO NOT open or read the entire file if you only need function names/signatures.",
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
    })
}

fn schema_inspect_symbol() -> Value {
    json!({
        "name": "inspect_symbol",
        "description": "Returns the source of a specific function or method. The output passes through the full Phase-4 sanitization pipeline. WARNING: Use ONLY to retrieve exact method/class signatures and their AST bodies in large files. DO NOT use for finding hardcoded strings or simple variable names; use standard search/grep instead.",
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
                },
                "match_mode": {
                    "type": "string",
                    "enum": ["auto", "simple", "qualified"],
                    "description": "Matching strategy for symbol_name: 'auto' (default) tries simple name first, then qualified if not found. 'simple' matches only the unqualified name, while 'qualified' requires the full path (e.g., ClassName.methodName)."
                },
                "return_all_matches": {
                    "type": "boolean",
                    "description": "If true, returns all matching symbols instead of just the first one (default: false)."
                },
                "signature_hint": {
                    "type": "string",
                    "description": "Optional: a partial signature (e.g., parameter types) to help disambiguate overloaded functions. Only used when match_mode is 'auto' or 'simple'."
                }
            },
            "required": ["file_path", "symbol_name"]
        }
    })
}

fn schema_get_dependencies_graph() -> Value {
    json!({
        "name": "get_dependencies_graph",
        "description": "Analyses import/use statements across the project and returns a JSON dependency graph (nodes = files, edges = import relationships).",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn schema_search_design_patterns() -> Value {
    json!({
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
    })
}

fn schema_audit_security_measures() -> Value {
    json!({
        "name": "audit_security_measures",
        "description": "Analyses the project for common security vulnerabilities and returns a report with recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn schema_refresh_index() -> Value {
    json!({
        "name": "refresh_index",
        "description": "Rebuilds the project file index from disk and clears the AST cache. Use this when files are added/removed or to free memory. Returns statistics on files indexed and cache cleared.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn schema_get_server_stats() -> Value {
    json!({
        "name": "get_server_stats",
        "description": "Returns server statistics: AST and tool cache utilization, file index metadata, and runtime configuration. Always available.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn schema_get_module_summary() -> Value {
    json!({
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
    })
}

fn schema_generate_project_docs() -> Value {
    json!({
        "name": "generate_project_docs",
        "description": "Analyses the indexed project and generates user-facing Markdown documentation: what the application does, how to use it, its public API surface, and inferred practical use cases. Designed for the end-user of the analysed application, not for the developer modifying its source code. Supports pagination via file_offset for large projects.",
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
                    "description": "Files per page (default: 50, max: 150).",
                    "minimum": 1
                },
                "file_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Zero-based index of the first file to analyse. Use together with max_files to paginate over large projects."
                },
                "language": {
                    "type": "string",
                    "enum": ["en", "es", "ca"],
                    "description": "Language for generated headings and inferred descriptions (default: en). Does not translate doc-comments."
                }
            },
            "required": []
        }
    })
}

fn schema_analyze_angular_component() -> Value {
    json!({
        "name": "analyze_angular_component",
        "description": "Analyses an Angular component file and returns its metadata, including inputs, outputs, lifecycle hooks, and template structure. Useful for understanding the component's API and behavior without reading the full source.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the Angular component file to analyze"
                }
            },
            "required": ["file_path"]
        }
    })
}

fn schema_lint_file() -> Value {
    json!({
        "name": "lint_file",
        "description": "Runs the hybrid lint pipeline for a file. Tree-sitter checks are always available; external linters are used when enabled and installed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to lint"
                }
            },
            "required": ["file_path"]
        }
    })
}

/// JSON Schema definitions returned by `tools/list`.
pub fn tool_definitions() -> Value {
    let is_angular = crate::state::ServerState::get_opt()
        .map(|s| s.is_angular_project())
        .unwrap_or(true);

    let mut defs = all_tool_definitions();
    if is_angular {
        defs.push(angular_tool_definitions());
    }

    Value::Array(defs.iter().map(|d| (d.schema)()).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn expensive_tools_are_correctly_identified() {
        use crate::tools::is_expensive_tool;
        assert!(is_expensive_tool("generate_project_docs"));
        assert!(is_expensive_tool("get_dependencies_graph"));
        assert!(!is_expensive_tool("get_file_outline"));
        assert!(!is_expensive_tool("inspect_symbol"));
    }

    #[tokio::test]
    async fn semaphore_blocks_excess_concurrent_tools() {
        let sem = tokio::sync::Semaphore::new(1);
        let permit1 = sem.try_acquire().unwrap();
        assert!(sem.try_acquire().is_err());
        drop(permit1);
        assert!(sem.try_acquire().is_ok());
    }
}
