use serde_json::{json, Value};

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
            "description": "Returns a structural map of a file: class names, canonical function/method identifiers, signatures, and imports. The canonical identifier can be passed directly to inspect_symbol with match_mode='qualified'. Restricted files return an access-denied notice.",
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
                        "enum": ["en", "es", "ca"],
                        "description": "Language for generated headings and inferred descriptions (default: en). Does not translate doc-comments."
                    }
                },
                "required": []
            }
        }
    ])
}
