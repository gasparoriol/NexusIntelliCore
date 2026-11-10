# NexusIntelliCore

NexusIntelliCore is a production-ready, Rust-based Model Context Protocol (MCP) server for semantic code analysis with built-in privacy controls and enterprise-grade security.

It exposes code intelligence tools over stdio JSON-RPC/MCP and sanitizes all outputs through a multi-layered Privacy Gateway before returning them to clients.

---

## Current Status (v2.0.0)

NexusIntelliCore is a secure-by-design MCP server built for single-developer workflows, multi-project environments, and multi-user context-compression pipelines.

### What's New in v2.0.0

- **Declarative SAST Engine v2**: 170+ Tree-Sitter security rules across 8 languages (Java, Kotlin, Python, JavaScript, TypeScript, Go, C#, Rust, C) categorized across 4 tiers (N1 Structural, N2 Taint, N3 Infrastructure, N4 Patterns).
- **Inter-Procedural Taint Flow Analysis**: Dynamic dataflow tracking across functions and files (depth 3) for SQL injection, command injection, path traversal, SSRF, open redirect, SSTI, and log injection.
- **Enterprise Standards Compliance**: Native SARIF 2.1.0 output format for seamless GitHub Code Scanning integration.
- **Baseline Adoption & Debt Management**: Support for `audit-baseline.json` using line-independent identities (`rule:file:function:ordinal`) to accept existing debt without masking new regressions.
- **In-Code Suppressions**: Auditable, formal code suppressions (`// nexus-ignore: <rule-id> <reason>`).
- **Session-Aware Multi-Project Engine**: Isolated active project selection (`set_active_project`), unified `project_id` parameter across all tools, and dynamic workspace resolution.

### Verified Quality & Security Metrics

- **Zero Unsafe Code**: Enforced at the compiler level via `#[forbid(unsafe_code)]`.
- **Zero Clippy Warnings**: Clean build under `-D warnings`.
- **700+ Automated Tests**: 100% pass rate across unit, integration, privacy adversarial, SAST rule corpora (per-rule precision/recall gates), and stress test suites.
- **Stress-Tested Engine**: Validated against 500+ file synthetic projects and high-concurrency requests with zero memory leaks or deadlocks. The SAST engine audits 500 files in under 350 ms (release) and is gated in CI by a latency budget.
- **CI/CD Pipeline**: 8 automated security and quality jobs (Gitleaks secret scanning, Cargo Audit, Clippy security lints, MCP handshake probes, Tarpaulin code coverage, internal doc link validation).

---

## What This Project Solves

NexusIntelliCore helps LLM-enabled tooling understand repositories safely and efficiently by providing:

- Multi-project runtime management and automatic path resolution
- Project structure discovery with access control boundaries
- File-level outlines (types, imports, function signatures)
- Symbol inspection with targeted source extraction
- Dependency graph extraction with circular dependency detection
- Design pattern heuristics
- Multi-language SAST: 170+ declarative rules, taint analysis across functions and files, SARIF 2.1.0 output and baseline adoption (see [Security Audit Engine](#security-audit-engine-sast))
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

## Security Audit Engine (SAST)

`audit_security_measures` is a deterministic, offline static-analysis engine built on tree-sitter. It runs no external binaries and never makes network calls; rules are embedded in the binary.

### How it works

| Tier | What it detects | Examples |
|---|---|---|
| **N1 Structural** | A dangerous API or insecure configuration visible in a single AST node | Weak hashes/ciphers, TLS validation disabled, unsafe deserialization, CSRF/CORS/cookie flags, XXE, `gets`/`strcpy` |
| **N2 Taint** | User input reaching a sink, following sanitizers, guards and calls | SQL/command injection, path traversal, SSRF, open redirect, SSTI, log injection |
| **N3 Text/Config** | Infrastructure and configuration files (matched on redacted text) | `USER root`, `curl \| sh`, secrets in `ENV`, privileged containers, Spring actuator exposure |
| **N4 Patterns** | Precursors of vulnerabilities, low confidence, **outside the production gate** | Dynamic SQL construction, swallowed errors, fail-open authorization, non-constant-time secret comparison, secrets in logs, TOCTOU |

- **Languages**: Java, Kotlin, Python, JavaScript/TypeScript, Go, C#, Rust and C (taint analysis for Java, Kotlin, Python, JS/TS, Go, C# and Rust).
- **Declarative rules**: each rule is a tree-sitter query (`src/analyzer/rules/**/*.scm`) plus metadata (stable id, CWE, OWASP, severity, confidence, remediation). Adding a rule means adding a `.scm` file and one registry entry; queries are compiled once per language, on first use.
- **Taint across functions and files**: flows are followed through function summaries up to 3 nested calls. A call whose name is defined more than once is not resolved (precision over recall).
- **Zero secret exposure**: findings carry only rule, location and a fixed description. Secret values are never emitted, and the final report passes through the Privacy Gateway.

### Report formats

```json
{ "name": "audit_security_measures", "arguments": { "format": "sarif" } }
```

| `format` | Output |
|---|---|
| `markdown` (default) | Human-readable report with production risk, risk patterns, a ranked list of functions to review, and an embedded JSON summary (`schema_version` 3) |
| `sarif` | Pure SARIF 2.1.0 log with rule metadata, `codeFlows` for taint flows and `suppressions`, ready for GitHub code scanning |
| `baseline` | Content of `audit-baseline.json` accepting every current finding |

### Adopting it in an existing project

1. Run the audit with `format: "baseline"` and save the output as `audit-baseline.json` at the project root.
2. From then on, findings in the baseline are reported as accepted debt and only **new** findings count as production risk.
3. Baseline entries use a line-independent identity (`rule:file:function:ordinal`), so moving code does not resurrect old findings.

### Suppressions

```java
// nexus-ignore: java-command-injection-exec reviewed in PR 12, fixed program and arguments
Runtime.getRuntime().exec(CMD);
```

A suppression on the finding's line or the line above needs a non-empty reason. Suppressed findings are listed in the report and in SARIF, never hidden.

### Quality gates

Every rule ships with positive, safe and evasion fixtures and must reach precision >= 0.95 and recall >= 0.90 per rule and language. The repository's own production code is held to zero taint findings and a fixed baseline for the remaining rules (`tests/audit_baseline.rs`).

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

### 2. Dynamic Runtime Registration (`list_projects`, `register_project`, `unregister_project`, `set_active_project`)
Projects can be managed dynamically during an active MCP session:

- **`list_projects`**: Lists all active project contexts, canonical root paths, file counts, Angular framework detection status and an `active` flag marking the session's active project.
- **`register_project`**: Registers a new project root directory at runtime. Accepts `path` (required), an optional `project_id` alias, `set_active` (default `false`) to also make it the active project of the session, and `index` (default `true`) to verify the index is ready and report the files indexed.
- **`set_active_project`**: Sets the active project of the current session (`project_id` or a registered root path) and returns `{ active_project_id, root, files_indexed }`.
- **`unregister_project`**: Removes a project root from the server state and automatically purges its associated AST and tool cache entries.

### 3. Project Selection: Active Project per Session
Every project-scoped tool accepts an optional `project_id` (alias `root_path`). Resolution order per call: explicit `project_id` → project owning the `file_path` argument → session active project → first registered project (first CLI root). Unknown ids return an error listing the valid ids, and a `root_path`/`file_path` outside the registered roots is rejected.

The active project lives in the connection's session (not in a process-wide global) and is selected automatically from `rootUri` / `workspaceFolders` of the MCP `initialize` request when they match (symlinks, trailing slashes and case on case-insensitive filesystems are normalised) a registered root. Project-scoped results include a `project: { id, root }` field with the project actually used, and `get_server_stats` reports `active_project_id`.

**Migration note:** the argument order of the CLI roots no longer decides which project tools operate on once the client sends a matching `rootUri`/`workspaceFolders` or calls `set_active_project`. Without either, behaviour is unchanged (first root is the default). The legacy `project` argument of `get_project_structure` is still accepted as an alias of `project_id`.

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

## MCP Tools Reference (18 Tools)

| Tool Name | Cacheable | Description |
|---|:---:|---|
| `get_project_structure` | No | Directory tree with access-control markers (`project_id` optional) |
| `get_file_outline` | Yes | Structural map of a file (signatures, types, imports, doc-comments) |
| `get_module_summary` | Yes | Module-level doc-comments and public API summary |
| `inspect_symbol` | Yes | Sanitized source code of a specific function, class, or method |
| `get_dependencies_graph` | Yes | Import graph between modules, including dependency-cycle alerts |
| `search_design_patterns` | Yes | Heuristic design-pattern detection across files |
| `audit_security_measures` | Yes | Multi-language SAST: secrets, structural rules, taint analysis, infrastructure checks, risk patterns; `format` = `markdown` / `sarif` / `baseline` |
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
| `set_active_project` | No | Set the session's active project (all project-scoped tools accept an optional `project_id`) |

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
