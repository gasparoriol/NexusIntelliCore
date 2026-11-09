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

Runs secret scanning, AST-based insecure code detection, taint analysis and infrastructure checks across the project.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `format` | string | No | `markdown` (default): report with an embedded JSON summary. `sarif`: pure SARIF 2.1.0 log (GitHub code scanning, IDEs). `baseline`: `audit-baseline.json` content accepting every current finding. |

**What it detects:**
Rules are declarative (`src/analyzer/rules/`): each one carries an id `<lang|any>-<cwe-slug>-<variant>`, CWE, OWASP category, tier and base severity.

- `any-hardcoded-secret` (CWE-798): Hardcoded API keys, tokens, credentials, connection strings
- `rust-unsafe-code-block` / `-fn` / `-asm` (CWE-676): `unsafe` blocks, `unsafe fn`, inline `asm!`
- `rust-uncaught-panic-unwrap` (CWE-248, pattern): `unwrap()` / `expect()` calls
- `js-code-injection-eval`, `js-code-injection-new-function`, `py-code-injection-eval`, `kotlin-code-injection-eval` (CWE-94/95)
- `js-xss-inner-html` (CWE-79): `innerHTML` assignments
- `py-command-injection-shell-true`, `java-command-injection-exec` (CWE-78)
- **Taint rules** (`<lang>-<vuln>-taint`; `lang` = `java`, `py`, `js` for JS/TS, `rust`, `go`, `cs`, `kotlin`): AST data flow from user input (Spring/JAX-RS/Servlet, Flask/Django/FastAPI, Express/Koa/NestJS, ASP.NET Core, `net/http`/gin/echo, axum/actix, CLI args) to a sink, honouring sanitizers and confinement guards. Flows are followed through calls to project functions via summaries (up to 3 nested calls, across files); a call whose name is defined more than once is not resolved:
  - `sql-injection` (CWE-89), `command-injection` (CWE-78), `ssrf` (CWE-918), `open-redirect` (CWE-601): Java, Python, JS/TS, Rust, Go, C#, Kotlin
  - `path-traversal` (CWE-22): Java, Python, JS/TS, Go, C#, Kotlin (Critical for write/delete sinks)
  - `ssti` (CWE-1336): Java, Python, JS/TS, Go, C#
  - `log-injection` (CWE-117): Java, Python, JS/TS, Go, C#, Kotlin
- `any-sql-injection-heuristic` (CWE-89): String concatenation in SQL contexts; only for languages without SQL taint rules (C)
- **Configuration and API rules** (`<lang>-<weakness>`; `lang` adds `go`, `cs`, `c`, `kotlin`):
  - `weak-crypto-hash` (CWE-328) / `weak-crypto-cipher` (CWE-327): MD5/SHA-1, DES/3DES/RC2/RC4/Blowfish, ECB — Java, Kotlin, Python, JS/TS, Go, C#, Rust, C
  - `tls-validation-disabled` (CWE-295): `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`, trust-all managers, `danger_accept_invalid_certs(true)`… — Java, Python, JS/TS, Go, C#, Rust, C
  - `insecure-random-context` (CWE-338): `Math.random`, `java.util.Random`, `random`, `math/rand`, `rand()` only when an enclosing variable/function name is security-related (`token`, `password`, `nonce`, `session`…) — Java, Python, JS/TS, Go, C#, C
  - `insecure-deserialization` (CWE-502): `ObjectInputStream`, XStream, `pickle`, unsafe `yaml.load`, `BinaryFormatter`, `TypeNameHandling.All`, `unserialize` — Java, Kotlin, Python, JS/TS, C#
  - `csrf-protection-disabled` (CWE-352), `cors-wildcard-credentials` (CWE-942), `insecure-cookie-flag` (CWE-614), `debug-mode-enabled` (CWE-489) and XXE (CWE-611: Java factories without `disallow-doctype-decl`, lxml `resolve_entities=True`, C# `DtdProcessing.Parse`)
  - C: `c-dangerous-function-gets` (CWE-242), `c-buffer-overflow-unbounded-copy` / `c-buffer-overflow-scanf` (CWE-120), `c-format-string-variable` (CWE-134)
- **Risk patterns (N4)**: precursors of vulnerabilities, low confidence, reported under "Risk Patterns (informative)" and **excluded from the production gate**: dynamic SQL construction (promoted to the taint finding when a source reaches it), swallowed errors, fail-open authorization (`catch` returning `true` in `isAuthorized`-like functions), non-constant-time secret comparison, secrets written to logs, blacklist validation (`replace("../", "")`), reflection from non-literal names, TOCTOU check-then-use, security TODO/FIXME comments, bind to `0.0.0.0`.
- **Infrastructure rules (N3)** on `Dockerfile`, YAML (compose, Kubernetes, CI), shell scripts and Spring `.properties` (configuration is matched on its redacted form): `docker-root-user`, `docker-remote-add`, `docker-secret-in-env`, `docker-unpinned-base-image`, `docker-ssh-port-exposed`, `any-download-pipe-to-shell` (CWE-494), `yaml-privileged-container`, `spring-actuator-endpoints-exposed`, `spring-ssl-disabled`.

**Suppressions:** `// nexus-ignore: <rule-id> <reason>` on the finding's line or the line above. The reason is mandatory; suppressed findings are listed in the report, never hidden.

**Baseline:** save `format=baseline` output as `audit-baseline.json` at the project root. Findings listed there are reported as accepted debt (`baselined_total`, SARIF `suppressions`) and only **new** findings count as production risk. Entries use `stable_id` (`rule:file:function:ordinal`), which does not change when lines move. An invalid baseline is reported and ignored; a baseline protected by `.mcpignore` is not read.

**JSON summary (`schema_version` 3):** each `production_risk` / `risk_patterns` entry includes `rule_id`, `legacy_rule_id` (id used by schema 1, e.g. `rust-unsafe`), `category`, `cwe`, `owasp`, `tier`, `severity` (`critical`/`high`/`medium`/`low`), `confidence`, `file`, `line`, `function`, `flow` (`source_line`/`sink_line` for taint rules), `fingerprint` (line-based, deduplication) and `stable_id` (baseline identity); plus `suppressed`, `suppressed_total`, `baselined_total`, `baseline` (`absent`/`loaded`/`invalid`), `top_risk_functions` (deterministic ranking: Σ severity × confidence weights, plus a bonus when user input reaches the function; use `inspect_symbol` on them) and `taint_coverage` (`inter-procedural-summaries`).

**SARIF (`format=sarif`):** one run with rules (CWE/OWASP tags, `security-severity`), results with `partialFingerprints` (`nexusStableId/v1`), `codeFlows` for taint flows, and `suppressions` (`inSource` for `nexus-ignore`, `external` for the baseline). Messages are fixed rule texts, never source content.

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
