# NexusIntelliCore — User Guide

This guide walks you through configuring and using every MCP tool exposed by NexusIntelliCore.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Project Management Tools](#2-project-management-tools)
3. [Code Analysis Tools](#3-code-analysis-tools)
4. [Security Tools](#4-security-tools)
5. [Documentation Tools](#5-documentation-tools)
6. [Server Tools](#6-server-tools)
7. [Common Patterns & Workflows](#7-common-patterns--workflows)

---

## 1. Getting Started

All tools communicate via **JSON-RPC 2.0** over **MCP stdio framing**. Tools are called using the `tools/call` method.

### Basic Request Shape

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "<tool_name>",
    "arguments": { }
  }
}
```

### Basic Response Shape

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Tool output here..."
      }
    ],
    "isError": false
  }
}
```

### List Available Tools

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

---

## 2. Project Management Tools

### `list_projects`

Lists all projects currently managed by the server.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "list_projects",
    "arguments": {}
  }
}
```

**Example output:**
```
Projects registered: 2

• NexusIntelliCore  /Users/user/Projects/NexusIntelliCore  [102 files]
• MyWebApp          /Users/user/Projects/MyWebApp           [348 files]
```

---

### `register_project`

Dynamically registers a new project root during an active session.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "register_project",
    "arguments": {
      "path": "/path/to/new/project",
      "project_id": "my-project"
    }
  }
}
```

| Parameter | Required | Description |
|---|---|---|
| `path` | ✅ | Absolute path to the project root directory |
| `project_id` | ❌ | Optional alias. Defaults to the directory name. |

---

### `unregister_project`

Removes a project and flushes all its cached data.

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "unregister_project",
    "arguments": {
      "project_id": "my-project"
    }
  }
}
```

---

### `get_project_structure`

Returns a compact directory tree with access-control markers.

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "get_project_structure",
    "arguments": {
      "project": "NexusIntelliCore"
    }
  }
}
```

| Parameter | Required | Description |
|---|---|---|
| `project` | ❌ | Project ID or path alias. Defaults to the first registered project. |

---

## 3. Code Analysis Tools

### `get_file_outline`

Returns the structural map of a source file: imports, type definitions, function signatures, and doc-comments.

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "get_file_outline",
    "arguments": {
      "file_path": "src/server.rs"
    }
  }
}
```

> **Tip:** Config files (`.env`, `.yaml`, `.toml`) are automatically redacted — secrets will never appear in the output.

---

### `get_module_summary`

Returns module-level doc-comments and a summary of the public API of a file.

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "get_module_summary",
    "arguments": {
      "file_path": "src/privacy_gateway.rs"
    }
  }
}
```

---

### `inspect_symbol`

Returns the sanitized source code of a specific function, struct, enum, or method.

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "inspect_symbol",
    "arguments": {
      "file_path": "src/security.rs",
      "symbol_name": "constant_time_compare",
      "match_mode": "exact",
      "return_all_matches": false
    }
  }
}
```

| Parameter | Required | Description |
|---|---|---|
| `file_path` | ✅ | Path to the source file |
| `symbol_name` | ✅ | Name of the symbol to inspect |
| `match_mode` | ❌ | `exact` (default), `prefix`, or `contains` |
| `return_all_matches` | ❌ | Return all matching symbols (`false` by default) |
| `signature_hint` | ❌ | Optional type signature hint for disambiguation |

---

### `get_dependencies_graph`

Returns the import graph between modules with circular dependency detection.

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "get_dependencies_graph",
    "arguments": {
      "mode": "summary",
      "scope_path": "src/tools",
      "depth": 2,
      "direction": "outbound",
      "include_external": false,
      "max_nodes": 100,
      "sort_by": "fanout"
    }
  }
}
```

| Parameter | Default | Description |
|---|---|---|
| `mode` | `summary` | `summary` (compact) or `graph` (full) |
| `scope_path` | *root* | Limit analysis to a subdirectory |
| `depth` | *all* | BFS depth limit (1–5) |
| `direction` | `outbound` | `outbound`, `inbound`, or `both` |
| `include_external` | `false` | Include external library imports |
| `max_nodes` | `100` | Maximum nodes (capped at 200) |
| `max_edges_per_node` | `50` | Maximum edges per node (capped at 100) |
| `sort_by` | `fanout` | Sort hotspots by `fanout` or `fanin` |

---

### `search_design_patterns`

Detects design patterns using heuristics across the codebase.

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "search_design_patterns",
    "arguments": {
      "scope_path": "src"
    }
  }
}
```

**Detected patterns:** Factory, Builder, Observer, Repository, Singleton, Strategy.

---

### `get_file_outline` for Angular

For Angular projects, `get_file_outline` and `analyze_angular_component` work together:

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "analyze_angular_component",
    "arguments": {
      "file_path": "src/app/hero/hero.component.ts"
    }
  }
}
```

> **Note:** This tool is only registered when an Angular project is detected (`angular.json` present or `@angular/` in dependencies). It won't appear in `tools/list` for non-Angular projects.

---

### `lint_file`

Runs hybrid linting on a source file.

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tools/call",
  "params": {
    "name": "lint_file",
    "arguments": {
      "file_path": "src/main.rs"
    }
  }
}
```

- **Level 1** (always active): Tree-sitter structural checks
- **Level 2** (opt-in via `MCP_LINT_ENABLED=true`): External linters (`cargo clippy`, `eslint`, `mypy`, etc.)

---

### `query_ast`

Runs an ad-hoc [Tree-sitter S-expression query](https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries) against a source file.

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "tools/call",
  "params": {
    "name": "query_ast",
    "arguments": {
      "file_path": "src/security.rs",
      "query": "(function_item name: (identifier) @fn_name)"
    }
  }
}
```

---

### `read_config_file`

Safely reads a configuration file with automatic secret redaction.

```json
{
  "jsonrpc": "2.0",
  "id": 13,
  "method": "tools/call",
  "params": {
    "name": "read_config_file",
    "arguments": {
      "file_path": "config/app.yaml"
    }
  }
}
```

**Supported formats:** `.properties`, `.yaml`, `.yml`, `.toml`, `.env`

Sensitive values (API keys, passwords, tokens) are replaced with `[REDACTED_BY_MCP]`.

---

## 4. Security Tools

### `audit_security_measures`

Runs a full security audit: secret scanning and AST-based insecure code detection.

```json
{
  "jsonrpc": "2.0",
  "id": 14,
  "method": "tools/call",
  "params": {
    "name": "audit_security_measures",
    "arguments": {}
  }
}
```

**What it detects:**
- Hardcoded secrets: OpenAI keys, AWS credentials, GitHub tokens, JWT tokens, PEM keys
- Database connection strings
- Private IP addresses and internal hostnames
- Unsafe Rust blocks
- SQL injection heuristics

> **Important:** Secret _values_ are never recorded. The audit report only shows the secret _type_ and _location_.

---

## 5. Documentation Tools

### `generate_project_docs`

Auto-generates structured Markdown documentation from the codebase AST.

```json
{
  "jsonrpc": "2.0",
  "id": 15,
  "method": "tools/call",
  "params": {
    "name": "generate_project_docs",
    "arguments": {
      "language": "en",
      "file_offset": 0
    }
  }
}
```

| Parameter | Default | Description |
|---|---|---|
| `language` | `en` | `en` (English), `es` (Spanish), `ca` (Catalan) |
| `file_offset` | `0` | Pagination offset (50 files per page) |

> **Tip:** If the output indicates more pages, call again with `file_offset: 50`, `file_offset: 100`, etc.

---

## 6. Server Tools

### `get_server_stats`

Returns operational server metrics: cache hit ratios, invocation counts, uptime.

```json
{
  "jsonrpc": "2.0",
  "id": 16,
  "method": "tools/call",
  "params": {
    "name": "get_server_stats",
    "arguments": {}
  }
}
```

---

### `refresh_index`

Rebuilds the file index and flushes all AST and tool caches. Use when files are added/removed or to free memory.

```json
{
  "jsonrpc": "2.0",
  "id": 17,
  "method": "tools/call",
  "params": {
    "name": "refresh_index",
    "arguments": {}
  }
}
```

---

## 7. Common Patterns & Workflows

### Workflow: Understand a new codebase

```
1. get_project_structure        → Overview of files and directories
2. get_dependencies_graph       → Module dependencies and hotspots
3. search_design_patterns       → Architectural patterns in use
4. get_file_outline <key file>  → Deep dive into a specific module
5. inspect_symbol <symbol>      → Inspect a specific function or type
```

### Workflow: Security review

```
1. audit_security_measures      → Full secret and code security scan
2. get_file_outline <file>      → Review structure of flagged files
3. inspect_symbol <fn>          → Inspect flagged functions
```

### Workflow: Generate documentation

```
1. generate_project_docs (language: "en")  → English documentation
2. generate_project_docs (language: "es")  → Spanish documentation
3. generate_project_docs (language: "ca")  → Catalan documentation
```

### Workflow: Multi-project analysis

```
1. list_projects                          → See registered projects
2. register_project (path: "/new/path")   → Add a new project
3. get_project_structure (project: "id")  → Analyse specific project
4. unregister_project (project_id: "id")  → Clean up when done
```
