# NexusIntelliCore MCP Server

NexusIntelliCore is a Rust-based Model Context Protocol (MCP) server for semantic code analysis with built-in privacy controls.

It exposes code intelligence tools over stdio JSON-RPC/MCP and sanitizes outputs before returning them to clients.

## What This Project Solves

NexusIntelliCore helps LLM-enabled tooling understand repositories safely and efficiently by providing:

- Project structure discovery
- File-level outlines (types, imports, function signatures)
- Symbol inspection
- Dependency graph extraction
- Design pattern heuristics
- Security-oriented static checks

All tool outputs pass through a centralized Privacy Gateway.

## Core Features

### MCP Runtime

- JSON-RPC 2.0 request handling (`initialize`, `tools/list`, `tools/call`, `ping`)
- Stdio transport with MCP framing (`Content-Length`)
- Compatibility support for line-delimited JSON mode
- Structured logging through `tracing`

### Analysis Tools

The server currently exposes six MCP tools:

1. `get_project_structure`
2. `get_file_outline`
3. `inspect_symbol`
4. `get_dependencies_graph`
5. `search_design_patterns`
6. `audit_security_measures`

### Privacy and Security Controls

- Centralized output sanitization via Privacy Gateway
- Secret redaction in returned content
- Support for `@mcp-strip` behavior in symbol outputs
- Path validation and project-root boundary enforcement
- Restricted file handling through `.mcpignore` policies

## Architecture Overview

High-level module responsibilities:

- `src/main.rs`: server bootstrap, MCP lifecycle handling, request dispatch
- `src/transport.rs`: stdio framing/parsing and transport I/O
- `src/protocol.rs`: JSON-RPC protocol types and response helpers
- `src/tools.rs`: tool registry and tool dispatch implementation
- `src/state.rs`: global state, lazy index initialization, analysis cache
- `src/indexer.rs`: file discovery, tree rendering, restriction matching
- `src/analyzer.rs`: language detection and syntax/AST extraction with Tree-sitter
- `src/privacy_gateway.rs`: policy-driven sanitization layer
- `src/sanitizer.rs`: secret detection/redaction utilities

## Requirements

- Rust toolchain (stable)
- Cargo
- Bash (for probe script)
- Python 3 (used by the probe script parser)

## Build

```bash
cargo build --release
```

Binary output:

- `target/release/nexusintellicore-mcp`

## Run Locally

Use a project root as argument:

```bash
target/release/nexusintellicore-mcp /absolute/path/to/project
```

Alternative (environment variable):

```bash
MCP_ROOT_PATH=/absolute/path/to/project target/release/nexusintellicore-mcp
```

## VS Code MCP Configuration Example

Example `.vscode/mcp.json`:

```json
{
  "servers": {
    "nexusintellicore": {
      "transport": "stdio",
      "command": "${workspaceFolder}/target/release/nexusintellicore-mcp",
      "cwd": "${workspaceFolder}",
      "args": ["${workspaceFolder}"],
      "env": {
        "RUST_LOG": "error",
        "RUST_BACKTRACE": "0",
        "NEXUS_MCP_STDIN_TRACE": "1"
      }
    }
  }
}
```

## Test and Diagnostics

Run tests:

```bash
cargo test
```

Probe MCP handshake and tool response:

```bash
scripts/mcp_handshake_probe.sh --server ./target/release/nexusintellicore-mcp --root "$(pwd)"
```

Helpful probe options:

- `--tool tools/list`
- `--timeout 10`

## Tooling Notes

- The file index is initialized lazily on first index-dependent call.
- Analysis results are cached by file modification time.
- Security audit output reports issue type and location, never secret values.

## Known Constraints

- Design-pattern detection is heuristic.
- Dependency resolution is best-effort across languages.
- Security checks intentionally favor broad detection and may require manual validation.

## Contributing

1. Add or update tool logic in `src/tools.rs`.
2. Keep output sanitization centralized in `src/privacy_gateway.rs`.
3. Add tests for behavior and regressions.
4. Validate MCP framing behavior after transport changes.

## License

No license file is currently present in this repository.
