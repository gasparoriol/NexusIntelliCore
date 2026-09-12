# NexusIntelliCore — Complete MCP API Reference

> **Current as of:** v0.9.0 (2026-09-12). This document is the normative source of the MCP contract. It must match `src/tools/definitions.rs`.

---

## MCP Protocol

NexusIntelliCore communicates via **JSON-RPC 2.0** over **MCP stdio framing** (`Content-Length` headers). Line-delimited JSON mode is also supported for compatibility.

### Supported Protocol Methods

| Method | Description |
|---|---|
| `initialize` | MCP handshake (authentication if `MCP_AUTH_TOKEN` is set) |
| `notifications/initialized` | Notification — no response expected |
| `tools/list` | Discover available tools |
| `tools/call` | Invoke a tool |
| `ping` | Server liveness check |

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "tool_name",
    "arguments": { "param": "value" }
  }
}
```

### Success Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{ "type": "text", "text": "Output..." }],
    "isError": false
  }
}
```

### Error Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid Params",
    "data": "Missing required argument: file_path"
  }
}
```

### Error Codes

| Code | Message | Meaning |
|---|---|---|
| `-32700` | Parse Error | Invalid JSON received |
| `-32600` | Invalid Request | Request format is invalid |
| `-32601` | Method Not Found | Unknown tool or method name |
| `-32602` | Invalid Params | Parameters don't match expected schema |
| `-32603` | Internal Error | Server error during processing |

---

## Tool Reference

### 1. `get_project_structure`

Returns a compact directory tree with access-control markers.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `project` | string | No | Project ID or path alias. Defaults to first registered project. |

**Example:**
```json
{ "name": "get_project_structure", "arguments": { "project": "NexusIntelliCore" } }
```

**Cacheable:** No

---

### 2. `get_file_outline`

Returns the structural map of a file: imports, types, function signatures, and doc-comments.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Relative or absolute path to the source file |

**Example:**
```json
{ "name": "get_file_outline", "arguments": { "file_path": "src/server.rs" } }
```

**Cacheable:** Yes

---

### 3. `get_module_summary`

Returns module-level doc-comments and a summary of the public API.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Path to the source file |

**Example:**
```json
{ "name": "get_module_summary", "arguments": { "file_path": "src/privacy_gateway.rs" } }
```

**Cacheable:** Yes

---

### 4. `inspect_symbol`

Returns the sanitized source of a specific function, struct, enum, or method.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Path to the source file |
| `symbol_name` | string | ✅ | Name of the symbol |
| `match_mode` | string | No | `exact` (default), `prefix`, or `contains` |
| `return_all_matches` | bool | No | Return all matching symbols. Default: `false` |
| `signature_hint` | string | No | Type signature hint for disambiguation |

**Example:**
```json
{
  "name": "inspect_symbol",
  "arguments": {
    "file_path": "src/security.rs",
    "symbol_name": "constant_time_compare",
    "match_mode": "exact"
  }
}
```

**Cacheable:** Yes

---

### 5. `get_dependencies_graph`

Returns the import graph between modules, including dependency-cycle alerts.

**Parameters:**

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `summary` | `summary` or `graph` |
| `scope_path` | string | No | *root* | Limit to a subdirectory |
| `depth` | integer | No | *all* | BFS depth limit (1–5) |
| `direction` | string | No | `outbound` | `outbound`, `inbound`, or `both` |
| `include_external` | bool | No | `false` | Include external library deps |
| `include_unresolved` | bool | No | `false` | Include unresolved imports |
| `max_nodes` | integer | No | `100` | Capped at 200 |
| `max_edges_per_node` | integer | No | `50` | Capped at 100 |
| `sort_by` | string | No | `fanout` | `fanout` or `fanin` |

**Response shape:**
```json
{
  "nodes": [{ "id": "src/tools/server.rs", "kind": "file", "label": "..." }],
  "edges": [{ "source": "src/tools/audit.rs", "target": "src/privacy_gateway.rs", "label": "internal" }],
  "meta": {
    "dependency_cycles": [],
    "truncated": false,
    "metrics": { "duration_ms": 123, "graph_nodes_returned": 52 }
  }
}
```

**Cacheable:** Yes

---

### 6. `search_design_patterns`

Detects design patterns using heuristics across files.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `scope_path` | string | No | Limit to a subdirectory |
| `file_path` | string | No | Limit to a specific file |
| `sort_by` | string | No | Sort results. Default: `pattern` |

**Detected patterns:** Factory, Builder, Observer, Repository, Singleton, Strategy

**Example:**
```json
{ "name": "search_design_patterns", "arguments": { "scope_path": "src" } }
```

**Cacheable:** Yes

---

### 7. `audit_security_measures`

Runs secret scanning and AST-based insecure code detection across the project.

**Parameters:** None

**What it detects:**
- `secret-detection`: Hardcoded API keys, tokens, credentials, connection strings
- `rust-unsafe`: Unsafe Rust blocks
- `sql-injection-heuristic`: String concatenation in SQL contexts

**Important:** Secret _values_ are NEVER included. Only type and location are reported.

**Cacheable:** Yes

---

### 8. `analyze_angular_component`

Analyzes an Angular component: extracts selector, template, styles, inputs, outputs, and lifecycle hooks.

> Only available when an Angular project is detected.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Path to the `.ts` component file |

**Cacheable:** Yes

---

### 9. `refresh_index`

Rebuilds the file index and flushes all AST and tool caches.

**Parameters:** None

**Cacheable:** No

---

### 10. `get_server_stats`

Returns operational server metrics.

**Parameters:** None

**Returns:** Cache hit ratios, tool invocation counts, uptime, registered projects.

**Cacheable:** No

---

### 11. `generate_project_docs`

Auto-generates structured Markdown documentation from the codebase AST.

**Parameters:**

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `language` | string | No | `en` | `en`, `es`, or `ca` |
| `file_offset` | integer | No | `0` | Pagination offset (50 files per page) |
| `sections` | array | No | *all* | Sections to include |
| `visibility` | string | No | `public` | `public` or `all` |

**Cacheable:** Yes

---

### 12. `lint_file`

Hybrid linting: Tree-sitter structural checks (Level 1) + optional external linters (Level 2).

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Path to the source file |

> Level 2 external linters require `MCP_LINT_ENABLED=true`.

**Cacheable:** Yes

---

### 13. `query_ast`

Runs an ad-hoc Tree-sitter S-expression query against a source file.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Path to the source file |
| `query` | string | ✅ | Tree-sitter S-expression pattern |

**Example:**
```json
{
  "name": "query_ast",
  "arguments": {
    "file_path": "src/security.rs",
    "query": "(function_item name: (identifier) @fn_name)"
  }
}
```

**Cacheable:** Yes

---

### 14. `read_config_file`

Safely reads a configuration file with automatic secret redaction.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | ✅ | Path to the config file |

**Supported formats:** `.properties`, `.yaml`, `.yml`, `.toml`, `.env`

Sensitive values are replaced with `[REDACTED_BY_MCP]`.

**Cacheable:** Yes

---

### 15. `list_projects`

Lists all active workspace projects managed by the server.

**Parameters:** None

**Cacheable:** No

---

### 16. `register_project`

Dynamically registers a new project root at runtime.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | string | ✅ | Absolute path to the project root |
| `project_id` | string | No | Optional alias. Defaults to directory name. |

**Cacheable:** No

---

### 17. `unregister_project`

Unregisters a project root and flushes all its associated caches.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `project_id` | string | ✅ | Project ID or alias to unregister |

**Cacheable:** No

---

## Operational Limits

| Limit | Default | Configuration |
|---|---|---|
| Tool execution timeout | 30 seconds | `MCP_TOOL_TIMEOUT_SECS` |
| External linter timeout | 10 seconds | `MCP_LINT_TIMEOUT_SECS` |
| Dependency graph max nodes | 200 (cap) | `max_nodes` parameter |
| Dependency graph max edges/node | 100 (cap) | `max_edges_per_node` parameter |
| `generate_project_docs` page size | 50 files | `file_offset` parameter |
| Summary response budget | 25 KiB | Internal |
| Graph response budget | Larger | Internal |
