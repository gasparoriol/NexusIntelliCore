# NexusIntelliCore

**NexusIntelliCore** is a production-ready, Rust-based [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for semantic code analysis with built-in privacy controls and enterprise-grade security.

It exposes **17 code intelligence tools** over stdio JSON-RPC/MCP and sanitizes all outputs through a multi-layered Privacy Gateway before returning them to clients.

---

## Verified Quality & Security Metrics

| Metric | Value |
|---|---|
| Automated Tests | **362** (100% pass rate) |
| Unsafe Code | **Zero** — enforced at compiler level via `#[forbid(unsafe_code)]` |
| Clippy Warnings | **Zero** — clean build under `-D warnings` |
| Stress-Tested | 500+ file synthetic projects, high-concurrency, zero memory leaks |
| CI/CD Jobs | **8** automated security & quality jobs |

---

## What NexusIntelliCore Solves

NexusIntelliCore helps LLM-enabled tooling understand repositories safely and efficiently by providing:

- **Multi-project runtime management** and automatic path resolution
- **Project structure discovery** with access control boundaries
- **File-level outlines** — types, imports, function signatures
- **Symbol inspection** with targeted source extraction
- **Dependency graph extraction** with circular dependency detection
- **Design pattern heuristics** and AST-based security checks
- **Automated project documentation generation** (Markdown, multilingual: EN, ES, CA)
- **Safe configuration file reading** with key/value redaction

All tool outputs pass through a centralized **Privacy Gateway** boundary gate before reaching the client.

---

## Features

### 🔬 Multi-Language AST Analysis
Parses source code using [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) for: **Rust, Java, TypeScript, JavaScript, Python, C, C#, Go, Kotlin, CSS, HTML**.

### 🔒 Privacy-First Security
A multi-layered Privacy Gateway automatically redacts secrets, credentials, internal hostnames, and sensitive data from all tool outputs.

### 🏗️ Multi-Project Support
A single server instance manages multiple independent code repositories concurrently, with isolated state per project and a shared global cache.

### ⚡ High Performance
- Async runtime (Tokio) with configurable timeouts
- Tool query cache (`moka`) — avoids re-analysing unchanged files
- Reactive file watcher — automatic AST cache invalidation on file changes
- Poison error recovery — server never crashes on worker thread panic

### 🔐 Enterprise Hardening (v1.0.0)
- **S1** — Constant-time token comparison (no timing attacks)
- **S2** — Token hashing in memory (no plain-text secrets)
- **S3** — Authentication rate limiting with exponential backoff
- **S4** — Tamper-evident audit logging with cryptographic hash chain

---

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- `cargo` package manager

### Build

```bash
git clone https://github.com/your-org/NexusIntelliCore.git
cd NexusIntelliCore
cargo build --release
```

Binary output: `target/release/nexusintellicore`

### Run (Single Project)

```bash
./target/release/nexusintellicore /path/to/your/project
```

### Run (Multi-Project)

```bash
./target/release/nexusintellicore /path/to/project1 /path/to/project2
```

### VS Code Integration

Add to your `.vscode/mcp.json`:

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

## Available Tools (17)

| Tool | Description |
|---|---|
| `get_project_structure` | Directory tree with access-control markers |
| `get_file_outline` | Structural map: signatures, types, imports, doc-comments |
| `get_module_summary` | Module-level doc-comments and public API summary |
| `inspect_symbol` | Sanitized source code of a specific function, class, or method |
| `get_dependencies_graph` | Import graph between modules, including dependency-cycle alerts |
| `search_design_patterns` | Heuristic design-pattern detection across files |
| `audit_security_measures` | Secret scanning and AST-based insecure code detection |
| `analyze_angular_component` | Angular triad analysis (TS Component + HTML Template + CSS Styles) |
| `refresh_index` | Rebuild file index and flush AST/tool caches |
| `get_server_stats` | Server operational metrics (cache hit ratios, invocation counts) |
| `generate_project_docs` | Auto-generate structured Markdown documentation (EN, ES, CA) |
| `lint_file` | Hybrid linting: Tree-sitter Level 1 + optional external Level 2 |
| `query_ast` | Ad-hoc Tree-sitter S-expression query against source files |
| `read_config_file` | Safe read of config files with automatic secret redaction |
| `list_projects` | List all active workspace projects |
| `register_project` | Dynamically register a new project root at runtime |
| `unregister_project` | Unregister a project root and flush its associated caches |

---

## Build & Release Targets

```bash
# Build Linux static binary (MUSL)
cargo make linux-release

# Build Windows 64-bit binary
cargo make windows-release

# Build macOS Universal Binary (Intel + Apple Silicon)
cargo make mac-universal-release

# Run stress & high-concurrency test suite
cargo make stress

# Generate code coverage report
cargo make coverage
```

---

## Testing

```bash
# All tests
cargo test

# Integration tests
cargo test --test integration
cargo test --test multiproject_integration
cargo test --test privacy_adversarial
```

---

## Documentation

| Document | Description |
|---|---|
| [USER_GUIDE.md](./USER_GUIDE.md) | Step-by-step usage guide for each MCP tool |
| [CONFIGURATION.md](./CONFIGURATION.md) | All environment variables and build options |
| [API.md](./API.md) | Complete MCP API reference (17 tools) |
| [TECHNICAL.md](./TECHNICAL.md) | Internal architecture and module deep-dive |
| [SECURITY.md](./SECURITY.md) | Security architecture and Privacy Gateway |

---

## License

This project is licensed under the MIT License. See [`LICENSE.md`](../../LICENSE.md) for details.
