# NexusIntelliCore - Complete API Reference

> **Vigente:** 2026-08-18. Esta sección es la fuente normativa del contrato MCP actual y debe coincidir con `src/tools/definitions.rs`. El material marcado como histórico se conserva para contexto y no define métodos válidos.

## Current MCP Contract

The server communicates JSON-RPC 2.0 over MCP stdio framing. The supported protocol methods are:

- `initialize`
- `notifications/initialized` (notification, no response)
- `tools/list`
- `tools/call`
- `ping`

The current tool registry contains these tools:

| Tool                        | Required input                         | Notes                                                         |
| --------------------------- | -------------------------------------- | ------------------------------------------------------------- |
| `get_project_structure`     | none                                   | Compact project tree and architectural hints                  |
| `get_file_outline`          | `file_path`                            | Structural file map; config files are redacted                |
| `inspect_symbol`            | `file_path`, `symbol_name`             | Supports `match_mode`, `return_all_matches`, `signature_hint` |
| `lint_file`                 | `file_path`                            | Built-in checks plus opt-in external linter                   |
| `get_dependencies_graph`    | none                                   | Supports filters, budgets, cycles and resolution metrics      |
| `query_ast`                 | `file_path`, `query`                   | Tree-sitter query with sanitized captures                     |
| `read_config_file`          | `file_path`                            | Safe redacted view of supported config formats                |
| `search_design_patterns`    | none                                   | Heuristic pattern search with optional filters                |
| `audit_security_measures`   | none                                   | Secret and AST security audit                                 |
| `refresh_index`             | none                                   | Rebuilds the file index and invalidates analysis state        |
| `get_server_stats`          | none                                   | Operational server, cache and invocation statistics           |
| `get_module_summary`        | `file_path`                            | Module documentation and API summary                          |
| `generate_project_docs`     | none                                   | Supports sections, visibility, pagination and language        |
| `analyze_angular_component` | `file_path` or legacy `component_path` | Registered dynamically for Angular projects                   |

`tools/list` is the authoritative discovery surface. The Angular tool is omitted when the project is not detected as Angular. Tool schemas and cache/expense policies are generated from the same registry, so this table must be checked against `src/tools/definitions.rs` when the registry changes.

### Common Request and Response Shape

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_project_structure",
    "arguments": {}
  }
}
```

Successful tool calls return a JSON-RPC result containing MCP text content. Tool-level failures use `isError: true` inside the result; malformed JSON-RPC requests and unknown methods use the JSON-RPC `error` member.

### Operational Contract

- MCP-framed messages use `Content-Length`; line-delimited JSON is also supported for compatibility.
- Dependency graph defaults are `mode=summary`, `max_nodes=100`, `max_edges_per_node=50`, and a 25 KiB summary response budget.
- Dependency graph limits are capped at 200 nodes and 100 edges per node; effective clamps or invalid values appear in `meta.applied_limits.adjustments`.
- Graph output reports `dependency_cycles`, truncation state, response metrics and resolution statistics.
- `MCP_LINT_ENABLED` is opt-in; `MCP_LINT_TIMEOUT_SECS` defaults to 10 seconds.
- All tool inputs and outputs pass through the Privacy Gateway where applicable; config reads and AST captures are explicitly redacted.

## Historical API Material

The sections below describe earlier names and shapes retained for migration context. They are not supported MCP methods and must not be used as the current API contract.

## JSON-RPC 2.0 Protocol

All communication with NexusIntelliCore follows JSON-RPC 2.0 specification over MCP framing.

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "tool_name",
  "params": {
    "param1": "value1",
    "param2": "value2"
  },
  "id": 1
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Response content"
      }
    ]
  },
  "id": 1
}
```

### Error Format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Invalid Request",
    "data": "Additional error details"
  },
  "id": 1
}
```

## Core Tools

### 1. analyze_project

Comprehensive analysis of an entire project.

**Method**: `tools/project`

**Parameters**:

```json
{
  "path": "/path/to/project"
}
```

**Response**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Project structure, statistics, and detected patterns..."
    }
  ]
}
```

**Returns**:

- Project statistics
- Language distribution
- Detected design patterns
- Dependency summary
- Security findings count
- Estimated complexity

---

### 2. analyze_file

Detailed analysis of a single source file.

**Method**: `tools/analyze_file`

**Parameters**:

```json
{
  "path": "/path/to/file.rs"
}
```

**Returns**:

```rust
FileAnalysis {
  language: Lang,
  imports: Vec<ImportInfo>,
  functions: Vec<FunctionInfo>,
  classes: Vec<ClassInfo>,
  strings: Vec<StringLiteral>,
  css_rules: Vec<CssRuleInfo>,
  html_elements: Vec<HtmlElementInfo>,
  audit_findings: Vec<AuditFinding>,
}
```

**Example Response**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "File: main.rs\nLanguage: Rust\nFunctions: 5\nImports: 12\nSecurity findings: 0"
    }
  ]
}
```

---

### 3. audit_security

Security audit of a file or project.

**Method**: `tools/audit`

**Parameters**:

```json
{
  "path": "/path/to/analyze"
}
```

**Finding Types**:

- `XSS`: Cross-Site Scripting vulnerability
- `SQLInjection`: SQL injection risk
- `PathTraversal`: Path traversal vulnerability
- `UnsafeCode`: Unsafe operations (Rust)
- `HardcodedSecret`: Hardcoded credentials
- `WeakCrypto`: Weak cryptographic implementation

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "SECURITY AUDIT REPORT\n\nFile: src/main.rs\n\n[HIGH] Hardcoded API key at line 42\nPattern: OpenAI API key format detected\nRecommendation: Use environment variables\n\nTotal findings: 1"
    }
  ]
}
```

---

### 4. dependency_graph

Analyze project dependencies and imports.

**Method**: `tools/deps_graph`

**Parameters**:

```json
{
  "path": "/path/to/project"
}
```

**Import Classifications**:

- `Internal`: Same-project imports
- `External`: Third-party dependencies
- `Standard`: Standard library imports
- `Circular`: Circular dependency detected
- `Unresolved`: Unable to resolve import

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "DEPENDENCY GRAPH\n\nFile: src/main.rs\nExternal deps: serde_json, tokio, tree-sitter\nInternal imports: ./analyzer.rs, ./protocol.rs\n\nTotal external: 28\nTotal internal: 12\nCircular dependencies: 0"
    }
  ]
}
```

### 4.1 get_dependencies_graph (Incremental Contract)

Current MCP tool name: `get_dependencies_graph`

This tool now supports incremental exploration and returns a canonical graph payload with `nodes`, `edges`, and `meta`.

**Input Parameters**:

```json
{
  "mode": "summary",
  "scope_path": "src/tools",
  "depth": 2,
  "direction": "outbound",
  "include_external": false,
  "include_unresolved": false,
  "max_nodes": 100,
  "max_edges_per_node": 50,
  "sort_by": "fanout"
}
```

**Output Shape**:

```json
{
  "nodes": [
    {
      "id": "src/tools/deps_graph.rs",
      "label": "src/tools/deps_graph.rs",
      "kind": "file"
    }
  ],
  "edges": [
    {
      "source": "src/tools/deps_graph.rs",
      "target": "src/analyzer.rs",
      "label": "internal"
    }
  ],
  "meta": {
    "format": "nodes_edges_meta",
    "applied_filters": {
      "mode": "summary",
      "scope_path": "src/tools",
      "depth": 2,
      "direction": "outbound",
      "include_external": false,
      "include_unresolved": false,
      "sort_by": "fanout"
    },
    "applied_limits": {
      "max_nodes": 100,
      "max_edges_per_node": 50,
      "response_budget_bytes": 25600
    },
    "summary": {
      "type": "summary",
      "statistics": {},
      "top_hotspots": []
    },
    "truncated": false,
    "truncation_reason": null,
    "metrics": {
      "graph_nodes_returned": 1,
      "graph_edges_returned": 1,
      "response_bytes": 512,
      "truncated": false,
      "duration_ms": 8
    }
  }
}
```

**Guardrails**:

- `summary` mode enforces a compact response budget (`MAX_RESPONSE_BYTES`).
- `graph` mode allows a larger budget (`MAX_GRAPH_RESPONSE_BYTES`).
- If budget is exceeded, the tool truncates edges first, then nodes, and reports:
  - `meta.truncated=true`
  - `meta.truncation_reason`

**Direction Modes**:

- `outbound`: what each file imports/depends on.
- `inbound`: who depends on a file (`dependents` transformed into inbound edges).
- `both`: outbound + inbound merged.

**Depth**:

- If provided, applies BFS-limited traversal up to depth `1..5` from scope roots.

---

### 5. extract_patterns

Detect design patterns in code.

**Method**: `tools/patterns`

**Parameters**:

```json
{
  "path": "/path/to/file.rs"
}
```

**Patterns Detected**:

- Factory
- Builder
- Observer
- Repository
- Singleton
- Strategy

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "DESIGN PATTERNS\n\nFactory Pattern (High Confidence: 0.92)\n  Location: src/analyzer.rs\n  Evidence: 4 constructor methods (new_*, create_*)\n\nBuilder Pattern (Medium Confidence: 0.65)\n  Location: src/state.rs\n  Evidence: Chainable method calls"
    }
  ]
}
```

---

### 6. extract_outline

Get code structure and outline.

**Method**: `tools/outline`

**Parameters**:

```json
{
  "path": "/path/to/file.ts"
}
```

**Returns**:

- Class definitions
- Function signatures
- Module structure
- Public/private members

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "CODE OUTLINE: src/analyzer.rs\n\n[struct] FileAnalysis\n  - field: path\n  - field: language\n  - method: new()\n  - method: analyze()\n\n[fn] detect_language()\n[fn] analyze_file()"
    }
  ]
}
```

---

### 7. generate_docs

Generate project documentation.

**Method**: `tools/project_docs`

**Parameters**:

```json
{
  "path": "/path/to/project",
  "language": "en",
  "include_private": false
}
```

**Supported Languages**:

- `en`: English
- `es`: Spanish

**Returns**:

- Project overview
- API reference
- Usage examples
- Use cases
- Architecture summary

---

### 8. angular_analysis

Angular component relationship analysis.

**Method**: `tools/angular`

**Parameters**:

```json
{
  "path": "/path/to/component.ts"
}
```

**Returns** (`AngularComponentInfo`):

```rust
pub struct AngularComponentInfo {
  pub selector: String,
  pub template_path: Option<PathBuf>,
  pub style_paths: Vec<PathBuf>,
  pub inputs: Vec<String>,
  pub outputs: Vec<String>,
  pub lifecycle_hooks: Vec<String>,
}
```

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "ANGULAR COMPONENT: AppHeroComponent\n\nSelector: app-hero\nTemplate: ./hero.component.html\nStyles: ./hero.component.css\nInputs: heroData\nOutputs: heroSelected\nLifecycle Hooks: OnInit, OnDestroy"
    }
  ]
}
```

---

### 9. extract_summary

Get module summary and public API.

**Method**: `tools/summary`

**Parameters**:

```json
{
  "path": "/path/to/file.rs"
}
```

**Returns**:

- Module documentation
- Public symbols (functions, types)
- Function signatures
- Import summary

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "MODULE SUMMARY: analyzer.rs\n\n//! Core AST-based code analysis engine\n\nPublic Types:\n- Lang (enum)\n- FileAnalysis (struct)\n- ImportKind (enum)\n\nPublic Functions:\n- detect_language(path: &Path) -> Lang\n- analyze_file(path: &Path) -> Result<FileAnalysis>"
    }
  ]
}
```

---

### 10. extract_definitions

Look up symbol definitions.

**Method**: `tools/definitions`

**Parameters**:

```json
{
  "symbol": "FileAnalysis",
  "kind": "struct"
}
```

**Returns**:

- Definition location
- Full signature
- Documentation
- Type information

---

### 11. server_status

Get server status and capabilities.

**Method**: `tools/server`

**Parameters**: (none)

**Response Example**:

```json
{
  "content": [
    {
      "type": "text",
      "text": "NexusIntelliCore MCP Server\nVersion: 0.1.0\nStatus: Running\n\nCapabilities:\n- Multi-language AST analysis\n- Security auditing\n- Dependency graph analysis\n- Design pattern detection\n- Documentation generation\n\nSupported Languages: Java, TypeScript, Python, C#, Go, Rust"
    }
  ]
}
```

---

## Type Reference

### FileAnalysis

```rust
pub struct FileAnalysis {
  pub path: PathBuf,
  pub language: Lang,
  pub imports: Vec<ImportInfo>,
  pub functions: Vec<FunctionInfo>,
  pub classes: Vec<ClassInfo>,
  pub strings: Vec<StringLiteral>,
  pub css_rules: Vec<CssRuleInfo>,
  pub html_elements: Vec<HtmlElementInfo>,
  pub audit_findings: Vec<AuditFinding>,
}
```

### ImportInfo

```rust
pub struct ImportInfo {
  pub path: String,
  pub kind: ImportKind,
  pub line: usize,
  pub resolved: Option<PathBuf>,
}
```

**ImportKind**:

- `Standard`: Standard library (std, sys, etc.)
- `Internal`: Project-local import
- `External`: Third-party package
- `Restricted`: Access denied/ignored
- `Unresolved`: Cannot resolve

### FunctionInfo

```rust
pub struct FunctionInfo {
  pub name: String,
  pub signature: String,
  pub doc: Option<String>,
  pub line: usize,
  pub is_async: bool,
  pub is_public: bool,
  pub parameters: Vec<String>,
  pub return_type: Option<String>,
}
```

### AuditFinding

```rust
pub struct AuditFinding {
  pub kind: AuditFindingKind,
  pub severity: AuditSeverity,
  pub line: usize,
  pub message: String,
  pub context: Option<String>,
  pub remediation: Option<String>,
}
```

**AuditSeverity**:

- `Critical`: Immediate action required
- `High`: Should be fixed soon
- `Medium`: Consider fixing
- `Low`: Minor issue, nice to fix
- `Info`: Informational only

### PatternMatch

```rust
pub struct PatternMatch {
  pub pattern_name: String,
  pub confidence: f32,  // 0.0 - 1.0
  pub location: String,
  pub evidence: Vec<String>,
  pub class_or_file: String,
}
```

---

## Error Codes

| Code   | Message              | Meaning                         |
| ------ | -------------------- | ------------------------------- |
| -32700 | Parse Error          | Server received invalid JSON    |
| -32600 | Invalid Request      | Request format is invalid       |
| -32601 | Method Not Found     | Unknown tool/method name        |
| -32602 | Invalid Params       | Parameters don't match expected |
| -32603 | Internal Error       | Server error during processing  |
| -32000 | File Not Found       | Specified file doesn't exist    |
| -32001 | Invalid Path         | Path is outside allowed scope   |
| -32002 | Analysis Failed      | Error during analysis           |
| -32003 | Unsupported Language | Language not supported          |

---

## Usage Examples

### Example 1: Analyze a TypeScript Project

```bash
cat <<EOF | nc localhost 9090
{
  "jsonrpc": "2.0",
  "method": "tools/project",
  "params": {
    "path": "/home/user/my-app"
  },
  "id": 1
}
EOF
```

### Example 2: Security Audit

```bash
cat <<EOF | nc localhost 9090
{
  "jsonrpc": "2.0",
  "method": "tools/audit",
  "params": {
    "path": "/home/user/my-app/src/auth.ts"
  },
  "id": 2
}
EOF
```

### Example 3: Analyze Angular Component

```bash
cat <<EOF | nc localhost 9090
{
  "jsonrpc": "2.0",
  "method": "tools/angular",
  "params": {
    "path": "/home/user/my-app/src/app/hero.component.ts"
  },
  "id": 3
}
EOF
```

### Example 4: Generate Documentation

```bash
cat <<EOF | nc localhost 9090
{
  "jsonrpc": "2.0",
  "method": "tools/project_docs",
  "params": {
    "path": "/home/user/my-library",
    "language": "en"
  },
  "id": 4
}
EOF
```

---

## Rate Limiting & Quotas

Current limits (configurable):

- **Concurrent requests**: Unlimited (async)
- **Request timeout**: 30 seconds
- **Max file size**: 100 MB
- **Max project files**: 10,000
- **Cache entries**: 1024 (LRU)

---

## Versioning

- **Protocol Version**: JSON-RPC 2.0
- **MCP Version**: Compatible with MCP v0.1+
- **API Version**: 0.1.0 (subject to change)

---

## Backwards Compatibility

API is in active development. Breaking changes may occur in minor versions during 0.x releases. For production use, pin to specific version.

---

For more information, see:

- [README.md](./README.md) - Project overview
- [architecture.md](./architecture.md) - System architecture
- [SECURITY.md](./SECURITY.md) - Security guidelines
