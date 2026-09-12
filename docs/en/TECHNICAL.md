# NexusIntelliCore — Technical Architecture

This document describes the internal architecture of NexusIntelliCore for contributors and integrators.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    NexusIntelliCore MCP Server                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐     │
│  │  Transport Layer  (transport.rs)                       │     │
│  │  MCP stdio framing — Content-Length headers            │     │
│  │  + line-delimited JSON fallback mode                   │     │
│  └──────────────────────────┬─────────────────────────────┘     │
│                             │                                   │
│  ┌──────────────────────────▼─────────────────────────────┐     │
│  │  Protocol & Auth Layer  (server.rs + security.rs)      │     │
│  │  JSON-RPC 2.0 routing · initialize · tools/list        │     │
│  │  Token hashing (S2) · Rate limiting (S3)               │     │
│  │  Constant-time comparison (S1)                         │     │
│  └──────────────────────────┬─────────────────────────────┘     │
│                             │                                   │
│  ┌──────────────────────────▼─────────────────────────────┐     │
│  │  Tool Handlers  (src/tools/)                           │     │
│  │  17 registered tools — dynamic Angular detection       │     │
│  │  Tool Query Cache (moka::future::Cache)                │     │
│  └──────────────────────────┬─────────────────────────────┘     │
│                             │                                   │
│  ┌──────────────────────────▼─────────────────────────────┐     │
│  │  Privacy Gateway  (privacy_gateway.rs + sanitizer.rs)  │     │
│  │  Multi-layer secret redaction · @mcp-strip annotations │     │
│  │  Infrastructure masking · Sensitive comment removal     │     │
│  └──────────────────────────┬─────────────────────────────┘     │
│                             │                                   │
│  ┌──────────────────────────▼─────────────────────────────┐     │
│  │  Core Analysis Engine                                  │     │
│  │  Analyzer (AST) · Indexer · Watcher · Relations        │     │
│  │  State (moka cache + RwLock isolation per project)     │     │
│  └──────────────────────────┬─────────────────────────────┘     │
│                             │                                   │
│  ┌──────────────────────────▼─────────────────────────────┐     │
│  │  Tree-sitter Parsers (11 languages)                    │     │
│  │  Rust · Java · TS/JS · Python · C · C# · Go           │     │
│  │  Kotlin · CSS · HTML                                   │     │
│  └────────────────────────────────────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Source Structure

```
src/
├── main.rs                  # Entry point — CLI args, Tokio runtime, server bootstrap
├── server.rs                # MCP server loop — JSON-RPC routing
├── transport.rs             # MCP stdio framing (Content-Length) + line-delimited mode
├── protocol.rs              # JSON-RPC 2.0 types: JsonRpcRequest, JsonRpcResponse
├── security.rs              # Auth: token hashing, constant-time compare, rate limiting, audit log
├── privacy_gateway.rs       # Central Privacy Gateway — boundary gate for all I/O
├── sanitizer.rs             # Pattern-based secret redaction engine
├── indexer.rs               # File discovery with glob/gitignore support
├── watcher.rs               # File system watcher — cache invalidation on file change
├── relations.rs             # Angular component relationship resolver
├── audit_queries.rs         # AST-based security audit query definitions
├── analyzer/                # AST analysis engine (Tree-sitter)
│   ├── mod.rs               # analyze_file() — main entry point
│   ├── imports.rs           # Import classification
│   ├── functions.rs         # Function extraction
│   ├── types.rs             # Type/struct/enum extraction
│   └── tests.rs             # Analyzer unit tests
├── linter/
│   ├── level1.rs            # Tree-sitter structural linter
│   └── level2.rs            # External linter bridge (cargo clippy, eslint, mypy)
├── state/
│   ├── mod.rs               # ServerState — global shared cache (moka)
│   └── project.rs           # ProjectContext — per-project isolated state
└── tools/
    ├── mod.rs               # Tool dispatcher — routes tools/call to handlers
    ├── definitions.rs       # Tool schema registry (normative API contract)
    ├── angular.rs           # analyze_angular_component handler
    ├── audit.rs             # audit_security_measures handler
    ├── config_file.rs       # read_config_file handler
    ├── deps_graph/          # get_dependencies_graph handler (builder, cycles, render)
    ├── lint.rs              # lint_file handler
    ├── outline.rs           # get_file_outline handler
    ├── patterns.rs          # search_design_patterns handler
    ├── project.rs           # get_project_structure handler
    ├── project_docs/        # generate_project_docs handler (i18n, render, format)
    ├── projects_tool.rs     # list/register/unregister_project handlers
    ├── query_ast.rs         # query_ast handler
    ├── server.rs            # get_server_stats handler
    ├── summary.rs           # get_module_summary handler
    └── symbol.rs            # inspect_symbol handler
```

---

## Module Deep Dives

### Transport Layer (`transport.rs`)

Handles MCP framing and JSON-RPC serialization/deserialization.

- Reads `Content-Length` headers from stdin for proper frame parsing
- Falls back to line-delimited JSON for compatibility with older clients
- `TransportLimits` struct is the single source of truth for all framing constraints
- Uses `BufReader<R>` for efficient buffered I/O via `McpTransport`

### Protocol & Authentication (`server.rs` + `security.rs`)

The `initialize` MCP handshake performs authentication if `MCP_AUTH_TOKEN` is set:

1. Client provides `MCP_AUTH_TOKEN` in the initialize params
2. Server hashes the provided token using `compute_token_digest()` (32-byte SHA-256 digest)
3. Comparison uses `constant_time_compare_hashes()` — fixed-time, no length leakage **(S1)**
4. Raw token is discarded from memory immediately after hashing **(S2)**
5. Failed attempts trigger `AUTH_FAILURE_COUNT` with exponential backoff (250ms → 2s) **(S3)**

Tamper-evident audit logging **(S4)** writes append-only NDJSON with chained hashes (`prev_hash` + `hash`) when `MCP_AUDIT_LOG_PATH` is set.

### Privacy Gateway (`privacy_gateway.rs` + `sanitizer.rs`)

All tool outputs pass through the Privacy Gateway before returning to the client.

**Sanitization pipeline:**
```
Raw tool output
  → strip_sensitive_comments()    — remove @mcp-strip annotations
  → detect_all_secrets()          — identify secret patterns
  → sanitize_text()               — replace secrets with [REDACTED_BY_MCP]
  → infrastructure masking        — redact internal hostnames and private IPs
  → sanitize_config_text()        — for config file reads
  → Privacy Gateway output
```

**Detected secret types:** `OPENAI_KEY`, `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `JWT_TOKEN`, `DB_CONNECTION_URI`, `PEM_PRIVATE_KEY`, `PRIVATE_IP`, `INTERNAL_HOSTNAME`, `GENERIC_SECRET`

### State Management (`state/`)

**Two-level isolation model:**

| Level | Type | Scope |
|---|---|---|
| `ServerState` | Global shared | AST cache + tool query cache (`moka::future::Cache`) |
| `ProjectContext` | Per-project isolated | `FileIndex`, `TsPathAliasConfig`, `LintPool`, `FileWatcher` |

All `RwLock`/`Mutex` accesses use poison error recovery (`unwrap_or_else(PoisonError::into_inner)`) — the server never crashes if a worker thread panics.

`ServerState::try_get()` provides a non-panicking alternative to `ServerState::get()`.

### Tool Query Cache (`moka::future::Cache`)

Deterministic tools cache their final outputs to avoid re-analysing unchanged files:

- Cache key: `(tool_name, file_path, args_hash)`
- Cache invalidation: file watcher triggers invalidation on modification/create/delete
- Manual flush: `refresh_index` tool flushes all caches

### File Watcher (`watcher.rs`)

Uses `notify::RecommendedWatcher` (FSEvents on macOS, inotify on Linux):
- **Content change** → invalidates AST cache entry for that file
- **Create/Remove/Rename** → requests a debounced index refresh
- Best-effort: if the watcher fails to start (e.g., OS inotify limit), the server continues without automatic invalidation

### Analyzer Engine (`analyzer/`)

Entry point: `analyze_file(path: &Path) -> Result<FileAnalysis>`

**Analysis flow:**
```
File path
  → detect_language()     — extension + content heuristics
  → Tree-sitter parser    — language-specific grammar
  → AST traversal         — extract imports, functions, types, strings
  → audit_file_ast()      — run security checks against AST
  → FileAnalysis result
```

**Supported languages:** Rust, Java, TypeScript, JavaScript, Python, C, C#, Go, Kotlin, CSS, HTML

---

## Concurrency Model

- **Async runtime:** Tokio — all tool handlers are `async fn`
- **Shared state:** `Arc<RwLock<ServerState>>` — multiple concurrent reads, exclusive writes
- **Per-project isolation:** Each `ProjectContext` has its own `Arc<RwLock<FileIndex>>`
- **No global mutable state** — functional design, dependencies explicit via parameters
- **Blocking operations:** wrapped with `tokio::task::block_in_place` where needed

---

## Design Patterns Detected (by `search_design_patterns`)

| Pattern | Location | Evidence |
|---|---|---|
| Factory | `src/analyzer/tests.rs` | 4 `create_*/make_*/new_*()` methods |
| Factory | `src/state/mod.rs` | 2 `create_*/make_*/new_*()` methods |
| Factory | `src/watcher.rs` | 2 `create_*/make_*/new_*()` methods |

---

## Dependency Graph (Core Hotspots)

All tool handlers depend on the Privacy Gateway as the central output sanitization point:

```
src/tools/audit.rs        → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/outline.rs      → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/symbol.rs       → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/angular.rs      → src/privacy_gateway.rs
src/tools/deps_graph/     → src/privacy_gateway.rs
src/tools/lint.rs         → src/privacy_gateway.rs
src/tools/patterns.rs     → src/privacy_gateway.rs
src/tools/project.rs      → src/privacy_gateway.rs
src/tools/summary.rs      → src/privacy_gateway.rs
```

**No circular dependencies detected.**

---

## Extending NexusIntelliCore

### Adding a New Tool

1. Create `src/tools/newtool.rs` — implement the `async fn` handler
2. Register the tool schema in `src/tools/definitions.rs`
3. Add dispatch entry in `src/tools/mod.rs`
4. Update `tests/api_docs_consistency.rs` to include the new tool
5. Add integration tests

### Adding a New Language

1. Add the Tree-sitter grammar crate to `Cargo.toml`
2. Register the language parser in `src/analyzer/mod.rs`
3. Add language-specific import/function/type extraction rules
4. Add test fixtures in `tests/fixtures/`
5. Update language detection in `detect_language()`

### Adding a New Audit Check

1. Define the finding type in `src/audit_queries.rs`
2. Implement the check in `audit_file_ast()` in `src/analyzer/`
3. Add test cases in `tests/audit_corpus.rs`
4. Document the new check in `docs/*/SECURITY.md`
