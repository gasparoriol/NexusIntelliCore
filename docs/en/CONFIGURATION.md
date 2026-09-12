# NexusIntelliCore — Configuration Reference

This document covers all environment variables, startup arguments, and build targets available in NexusIntelliCore.

---

## Startup Arguments

The server accepts one or more project root paths as positional CLI arguments:

```bash
# Single project mode
nexusintellicore /path/to/project

# Multi-project mode
nexusintellicore /path/to/project1 /path/to/project2 /path/to/project3
```

If no path is provided, the server falls back to `MCP_ROOT_PATH` (see below) or starts empty and waits for dynamic registration via `register_project`.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | *None* | Expected authentication token for the MCP `initialize` handshake. If set, all clients must provide this token. |
| `MCP_ALLOWED_TOOLS` | *All* | Comma-separated allowlist of tool names. Omitted tools are hidden from `tools/list`. |
| `MCP_AUDIT_LOG_PATH` | *None* | File path for append-only NDJSON tamper-evident audit logging with cryptographic hash chaining. |
| `MCP_SECURITY_CONFIG_PATH` | *None* | Path to a JSON security configuration file. |
| `MCP_TOOL_TIMEOUT_SECS` | `30` | Timeout in seconds for individual tool execution calls. |
| `MCP_LINT_ENABLED` | `false` | Enables Level 2 external linters (`cargo clippy`, `eslint`, `mypy`, etc.). Opt-in only. |
| `MCP_LINT_TIMEOUT_SECS` | `10` | Timeout in seconds for external linter execution. |
| `MCP_ROOT_PATH` | *None* | Fallback project root path if not provided via CLI argument. |
| `RUST_LOG` | `error` | Log level for structured logging via `tracing`. Values: `error`, `warn`, `info`, `debug`, `trace`. |

### Usage Examples

```bash
# Run with authentication token
MCP_AUTH_TOKEN="your-secret-token" nexusintellicore /path/to/project

# Enable external linting with longer timeout
MCP_LINT_ENABLED=true MCP_LINT_TIMEOUT_SECS=30 nexusintellicore /path/to/project

# Enable tamper-evident audit logging
MCP_AUDIT_LOG_PATH=/var/log/nexusintellicore-audit.ndjson nexusintellicore /path/to/project

# Restrict available tools
MCP_ALLOWED_TOOLS="get_file_outline,inspect_symbol,audit_security_measures" nexusintellicore /path/to/project

# Debug logging
RUST_LOG=nexusintellicore=debug nexusintellicore /path/to/project
```

---

## VS Code MCP Configuration

Add to `.vscode/mcp.json` in your workspace:

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

## Build Targets (Makefile.toml)

All targets use `cargo-make`. Install with: `cargo install cargo-make`

| Target | Command | Description |
|---|---|---|
| `linux-release` | `cargo make linux-release` | Build Linux static binary (MUSL, x86_64) |
| `windows-release` | `cargo make windows-release` | Build Windows 64-bit binary (`.exe`) |
| `mac-universal-release` | `cargo make mac-universal-release` | Build macOS Universal Binary (Intel + Apple Silicon) |
| `stress` | `cargo make stress` | Run stress & high-concurrency integration test suite |
| `coverage` | `cargo make coverage` | Generate code coverage report (requires `cargo-tarpaulin`) |

### Release Asset Verification

Each release binary ships with a SHA-256 checksum file:

```bash
# Verify Linux binary
sha256sum -c nexusintellicore-linux-musl.sha256

# Verify macOS binary
shasum -a 256 -c nexusintellicore-macos-universal.sha256
```

---

## Security Configuration File (`MCP_SECURITY_CONFIG_PATH`)

The optional JSON security configuration file supports the following fields:

```json
{
  "allowed_paths": ["/path/to/allowed/project"],
  "denied_extensions": [".env", ".pem"],
  "max_file_size_bytes": 104857600,
  "redact_patterns": ["custom-secret-pattern-.*"]
}
```

---

## Tool-Level Caching

The following tools have their outputs cached in the shared `moka` cache:

| Tool | Cacheable |
|---|:---:|
| `get_project_structure` | No |
| `get_file_outline` | ✅ Yes |
| `get_module_summary` | ✅ Yes |
| `inspect_symbol` | ✅ Yes |
| `get_dependencies_graph` | ✅ Yes |
| `search_design_patterns` | ✅ Yes |
| `audit_security_measures` | ✅ Yes |
| `analyze_angular_component` | ✅ Yes |
| `refresh_index` | No |
| `get_server_stats` | No |
| `generate_project_docs` | ✅ Yes |
| `lint_file` | ✅ Yes |
| `query_ast` | ✅ Yes |
| `read_config_file` | ✅ Yes |
| `list_projects` | No |
| `register_project` | No |
| `unregister_project` | No |

Cache is automatically invalidated when files change (via the file watcher). You can also force a full cache flush with `refresh_index`.
