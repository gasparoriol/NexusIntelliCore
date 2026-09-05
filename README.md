# NexusIntelliCore

NexusIntelliCore is a production-ready, Rust-based Model Context Protocol (MCP) server for semantic code analysis with built-in privacy controls and enterprise-grade security.

It exposes code intelligence tools over stdio JSON-RPC/MCP and sanitizes all outputs through a multi-layered Privacy Gateway before returning them to clients.

---

## Current Status 

NexusIntelliCore is a secure-by-design MCP server built for single-developer workflows, multi-project environments, and multi-user context-compression pipelines.

### Verified Quality & Security Metrics

- **Zero Unsafe Code**: Enforced at the compiler level via `#[forbid(unsafe_code)]`.
- **Zero Clippy Warnings**: Clean build under `-D warnings`.
- **362 Automated Tests**: 100% pass rate across unit, integration, privacy adversarial, and stress test suites.
- **Stress-Tested Engine**: Validated against 500+ file synthetic projects and high-concurrency requests with zero memory leaks or deadlocks.
- **CI/CD Pipeline**: 8 automated security and quality jobs (Gitleaks secret scanning, Cargo Audit, Clippy security lints, MCP handshake probes, Tarpaulin code coverage, internal doc link validation).

---

## What This Project Solves

NexusIntelliCore helps LLM-enabled tooling understand repositories safely and efficiently by providing:

- Multi-project runtime management and automatic path resolution
- Project structure discovery with access control boundaries
- File-level outlines (types, imports, function signatures)
- Symbol inspection with targeted source extraction
- Dependency graph extraction with circular dependency detection
- Design pattern heuristics and AST-based security checks
- Automated project documentation generation (Markdown, multilingual: EN, ES, CA)
- Safe configuration file reading with key/value redaction

All tool outputs pass through a centralized **Privacy Gateway** boundary gate before reaching the client.

---

## Hardening & Security Features (v1.0.0)

### 1. Token Hashing & Memory Hardening (`S2`)
Raw authentication tokens (`MCP_AUTH_TOKEN`) are **never stored in plain text memory**. Upon startup or configuration loading, the token string is immediately hashed into a 32-byte digest (`auth_token_hash`) and discarded from memory. Client authentication is evaluated strictly against the hash.

### 2. Constant-Time Comparison (`S1`)
Token verification uses a constant-time digest comparison (`constant_time_compare`) that computes fixed-size 32-byte hashes over all inputs unconditionally. **No early returns on length mismatch**, eliminating length-leakage timing attacks.

### 3. Handshake Authentication Rate Limiting (`S3`)
Failed authentication attempts on the `initialize` MCP method trigger an automatic rate-limiter (`AUTH_FAILURE_COUNT`) with exponential backoff delay (250 ms up to 2.0 s) to prevent brute-force attacks on the server.

### 4. Tamper-Evident Audit Logging (`S4`)
When audit logging is enabled (`MCP_AUDIT_LOG_PATH`), every protocol and lifecycle event is logged in append-only NDJSON format with chained hashes (`prev_hash` + `hash`). This creates an immutable cryptographic hash chain across audit records.

---

## Multi-Project Architecture & Operations

NexusIntelliCore includes native support for multi-project workflows, enabling a single server instance to serve and manage multiple independent code repositories concurrently.

### 1. Startup Multi-Root Initialization
Pass one or more project root paths directly via CLI parameters:

```bash
# Single project mode
nexusintellicore /path/to/project1

# Multi-project mode (multiple roots on startup)
nexusintellicore /path/to/project1 /path/to/project2 /path/to/project3
```

Alternatively, start the server empty and register repositories dynamically.

### 2. Dynamic Runtime Registration (`list_projects`, `register_project`, `unregister_project`)
Projects can be managed dynamically during an active MCP session:

- **`list_projects`**: Lists all active project contexts, canonical root paths, file counts, and Angular framework detection status.
- **`register_project`**: Registers a new project root directory at runtime. Accepts `path` (required) and an optional `project_id` alias.
- **`unregister_project`**: Removes a project root from the server state and automatically purges its associated AST and tool cache entries.

### 3. Automatic Project Path Resolution
File-based tools (`get_file_outline`, `inspect_symbol`, `lint_file`, `query_ast`, `get_module_summary`, etc.) automatically map the target `file_path` to the correct registered project root without requiring explicit project selection.

For structural tools like `get_project_structure`, an optional `project` parameter accepts a project ID or path alias to target a specific workspace. If omitted, the default (first registered) project is selected automatically.

### 4. Isolated State & Shared Cache Design
- **Per-Project Isolation (`ProjectContext`)**: Each project maintains its own isolated `FileIndex`, TypeScript path alias configuration (`TsPathAliasConfig`), linter pool (`LintPool`), and filesystem watcher (`FileWatcher`).
- **Global Shared Cache (`ServerState`)**: AST caches and tool query caches are managed centrally at the server level using `moka::future::Cache`, ensuring maximum memory efficiency and zero cross-project data leakage.

---

## Core Architecture & Engine Features

### MCP Runtime

- JSON-RPC 2.0 request handling (`initialize`, `tools/list`, `tools/call`, `ping`)
- Stdio transport with MCP framing (`Content-Length`)
- Compatibility support for line-delimited JSON mode
- Structured logging via `tracing`
- Configurable tool execution timeout (`MCP_TOOL_TIMEOUT_SECS`, default 30s)

### Resilience & Lock Hardening

- **Poison Error Recovery**: All `RwLock` and `Mutex` accesses in state management and watcher threads use safe poison recovery (`unwrap_or_else(PoisonError::into_inner)`), preventing server crashes if a worker thread panics.
- **Fallible State Access**: `ServerState::try_get()` provides a non-panicking alternative to `ServerState::get()`.

### Optimization & Caching

- **Tool Query Cache**: Caches final outputs of deterministic tools using `moka::future::Cache` to avoid re-analysing files when code is unchanged.
- **Dynamic Tool Discovery**: Scans project root on startup; if Angular is not detected (`angular.json` or `@angular/` dependencies), `analyze_angular_component` is dynamically hidden to reduce model context noise.
- **Reactive File Watcher**: `notify`-based file watcher automatically invalidates AST cache and schedules debounced index refreshes on file modification, creation, or deletion.

---

## MCP Tools Reference (17 Tools)

| Tool Name | Cacheable | Description |
|---|:---:|---|
| `get_project_structure` | No | Directory tree with access-control markers (`project` ID optional) |
| `get_file_outline` | Yes | Structural map of a file (signatures, types, imports, doc-comments) |
| `get_module_summary` | Yes | Module-level doc-comments and public API summary |
| `inspect_symbol` | Yes | Sanitized source code of a specific function, class, or method |
| `get_dependencies_graph` | Yes | Import graph between modules, including dependency-cycle alerts |
| `search_design_patterns` | Yes | Heuristic design-pattern detection across files |
| `audit_security_measures` | Yes | Secret scanning and AST-based insecure code detection |
| `analyze_angular_component` | Yes | Angular triad analysis (TS Component + HTML Template + CSS Styles) |
| `refresh_index` | No | Rebuild file index and flush AST/tool caches |
| `get_server_stats` | No | Server operational metrics (cache hit ratios, invocation counts, uptime) |
| `generate_project_docs` | Yes | Auto-generate structured Markdown documentation from AST (EN, ES, CA) |
| `lint_file` | Yes | Hybrid linting (Tree-sitter Level 1 + optional external Level 2 linters) |
| `query_ast` | Yes | Ad-hoc Tree-sitter S-expression query against source files |
| `read_config_file` | Yes | Safe read of `.properties`, `.yaml`, `.toml`, `.env` with automatic secret redaction |
| `list_projects` | No | List all active workspace projects managed by the server instance |
| `register_project` | No | Dynamically register a new project root directory at runtime |
| `unregister_project` | No | Unregister a project root and flush its associated caches |

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | *None* | Expected authentication token required during MCP `initialize` handshake |
| `MCP_ALLOWED_TOOLS` | *All* | Comma-separated whitelist of allowed tool names |
| `MCP_AUDIT_LOG_PATH` | *None* | File path for append-only NDJSON tamper-evident audit logging |
| `MCP_SECURITY_CONFIG_PATH` | *None* | Path to JSON security config file |
| `MCP_TOOL_TIMEOUT_SECS` | `30` | Timeout in seconds for individual tool execution calls |
| `MCP_LINT_ENABLED` | `false` | Enables Level 2 external linters (`cargo clippy`, `eslint`, `mypy`, etc.) |
| `MCP_LINT_TIMEOUT_SECS` | `10` | Timeout in seconds for external linter execution |
| `MCP_ROOT_PATH` | *None* | Fallback project root path if not provided via CLI argument |

---

## Build & Release

### Building Locally

```bash
cargo build --release
```

Binary output: `target/release/nexusintellicore`

### Cargo Make Tasks

`Makefile.toml` provides cross-platform release tasks:

```bash
# Build Linux static binary (MUSL)
cargo make linux-release

# Build Windows 64-bit binary (.exe)
cargo make windows-release

# Build macOS Universal Binary (Intel + Apple Silicon)
cargo make mac-universal-release

# Run stress & high-concurrency integration test suite
cargo make stress

# Generate code coverage report (cargo-tarpaulin)
cargo make coverage
```

### Release Assets & Verification

Release builds are published with SHA-256 checksum files for integrity verification:

- `nexusintellicore-linux-musl` & `nexusintellicore-linux-musl.sha256`
- `nexusintellicore-windows.exe` & `nexusintellicore-windows.exe.sha256`
- `nexusintellicore-macos-universal` & `nexusintellicore-macos-universal.sha256`

---

## VS Code MCP Configuration Example

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "nexusintellicore": {
      "transport": "stdio",
      "command": "${workspaceFolder}/target/release/nexusintellicore",
      "cwd": "${workspaceFolder}",
      "args": ["${workspaceFolder}"],
      "env": {
        "MCP_LINT_ENABLED": "true",
        "MCP_LINT_TIMEOUT_SECS": "10",
        "MCP_TOOL_TIMEOUT_SECS": "30",
        "RUST_LOG": "error"
      }
    }
  }
}
```

---

## License

This project is licensed under the MIT License. See `LICENSE.md` for details.
