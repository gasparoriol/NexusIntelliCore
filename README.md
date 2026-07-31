# NexusIntelliCore

NexusIntelliCore is a Rust-based Model Context Protocol (MCP) server for semantic code analysis with built-in privacy controls.

It exposes code intelligence tools over stdio JSON-RPC/MCP and sanitizes outputs before returning them to clients.

## Current Status

NexusIntelliCore is a secure-by-design Model Context Protocol (MCP) server for local experimentation, workflow design, and context-compression research.

It includes:

- Built-in token authentication (`MCP_AUTH_TOKEN`) for client verification.
- Tool access control (`MCP_ALLOWED_TOOLS`) to limit available capabilities.
- Detailed audit logging (`MCP_AUDIT_LOG_PATH`) for all protocol and tool interactions.
- End-to-end privacy validation through the Privacy Gateway.

That makes NexusIntelliCore a highly customizable, secure foundation for local and multi-user environments.

## What This Project Solves

NexusIntelliCore helps LLM-enabled tooling understand repositories safely and efficiently by providing:

- Project structure discovery
- File-level outlines (types, imports, function signatures)
- Symbol inspection
- Dependency graph extraction
- Design pattern heuristics
- Security-oriented static checks
- Automated project documentation generation (Markdown, multilingual)

All tool outputs pass through a centralized Privacy Gateway.

## Core Features

### MCP Runtime

- JSON-RPC 2.0 request handling (`initialize`, `tools/list`, `tools/call`, `ping`)
- Stdio transport with MCP framing (`Content-Length`)
- Compatibility support for line-delimited JSON mode
- Structured logging through `tracing`

### Optimization & Caching

- **Tool Query Cache**: Caches final outputs of deterministic tools using `moka::future::Cache` to avoid re-analysing files when project code is unchanged. Purgings are immediate on file watcher events and concurrent misses are deduplicated.
- **Dynamic Tool Discovery**: Scans project root on startup; if Angular is not detected (`angular.json` or `@angular/` package dependencies), the `analyze_angular_component` tool is dynamically hidden from the client to reduce context noise and model hallucinations.

#### `.mcpignore` Reactive Refresh

- The file watcher treats `.mcpignore` changes as topology-impacting events and schedules a full index refresh.
- A watcher-triggered refresh rebuilds both `allowed_files` and `restricted_files` from disk and invalidates the tool cache for the project root.
- Regular file content changes still evict AST entries and invalidate matching tool-cache keys.
- Manual fallback remains available through `refresh_index` when watcher events are unavailable in the runtime environment.

### Analysis Tools

The server exposes fourteen MCP tools:

1. `get_project_structure` — directory tree with access-control markers
2. `get_file_outline` — structural map of a file (signatures, types, imports, doc-comments)
3. `get_module_summary` — module-level doc-comments and public API
4. `inspect_symbol` — sanitized source of a specific function or method
5. `get_dependencies_graph` — import graph between modules, including dependency-cycle alerts
6. `search_design_patterns` — heuristic design-pattern detection
7. `audit_security_measures` — secret scanning and insecure-code detection
8. `analyze_angular_component` — full Angular component analysis (TS + HTML + CSS)
9. `refresh_index` — rebuild the file index and flush the AST cache
10. `get_server_stats` — operational stats (cache entries, indexed files, uptime)
11. `generate_project_docs` — auto-generate structured Markdown documentation from AST analysis
12. `lint_file` — hybrid linting for a file (tree-sitter checks always available; external linters are opt-in)
13. `query_ast` — ad-hoc tree-sitter query against any supported source file, captures sanitized through the Privacy Gateway
14. `read_config_file` — safe read of configuration files (`.properties`, `.yaml`, `.yml`, `.toml`, `.env`) with automatic secret and IP redaction

#### Dependency Graph Cycle Detection

`get_dependencies_graph` now reports circular dependencies using strongly connected components (SCC) over the directed file dependency graph.

- Cycle detection is computed from project-file edges (`internal` and `restricted` dependencies).
- Results are included in a top-level `dependency_cycles` array.
- Each cycle entry includes:
  - `files`: list of files in the cycle
  - `size`: number of files in that cycle
- Aggregate cycle metadata is exposed at `meta.alerts`:
  - `dependency_cycles_detected`
  - `cycle_sizes`

The detected cycles reflect the same active filters as the graph itself (`scope_path`, `depth`, `direction`, and dependency-type flags).

#### Security Audit Coverage (AST)

`audit_security_measures` combines regex-based secret detection with AST-based unsafe pattern detection.

AST checks currently include:

- Rust: `unsafe` blocks and unsafe declarations.
- JavaScript / TypeScript / TSX:
  - `eval(...)`
  - `new Function(...)`
  - assignments to `.innerHTML`
- Python:
  - `eval(...)` / `exec(...)`
  - `subprocess.*(..., shell=True)`

Findings are classified by kind and location (`line`), including:

- `UnsafeCode`
- `DynamicExecution`
- `InsecureAssignment`

#### Ad-hoc AST Queries (`query_ast`)

`query_ast` lets clients run an arbitrary tree-sitter S-expression query against any source file and receive the matching node captures.

| Parameter   | Type     | Required | Description                                                                      |
| ----------- | -------- | -------- | -------------------------------------------------------------------------------- |
| `file_path` | `string` | yes      | Absolute path to the source file to query                                        |
| `query`     | `string` | yes      | A tree-sitter S-expression query (e.g. `(function_item name: (identifier) @fn)`) |

Each capture in the response includes:

- `capture`: the capture name from the query pattern (e.g. `@fn`)
- `start` / `end`: `{ row, column }` positions in the source file
- `text`: the capture text, sanitized through the Privacy Gateway
- `redactions`: list of pattern labels that fired on that capture

The tool validates the path against the project root and `.mcpignore` before reading, and returns a structured error when the file language has no tree-sitter grammar or the query is malformed.

**Practical use**: pinpoint every call to a specific function, find all type definitions of a given name, or extract string literals from a file — without sending the whole file to the model.

#### Configuration File Safety (`read_config_file`)

`read_config_file` provides a safe, redacted view of plain-text configuration files that have no tree-sitter grammar and would otherwise be read verbatim by the agent.

| Parameter   | Type     | Required | Description                              |
| ----------- | -------- | -------- | ---------------------------------------- |
| `file_path` | `string` | yes      | Absolute path to the config file to read |

Accepted extensions: `.properties`, `.yaml`, `.yml`, `.toml`, `.env`, `.env.*`.

Redaction rules applied line-by-line:

- **Sensitive-key redaction**: when the key name matches `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `apikey`, `auth`, `credential`, `private`, `cert`, `keystore`, `dsn`, or `connection_string`, the value is replaced with `[REDACTED_BY_MCP]` regardless of its content.
- **Secret-pattern redaction**: values that match any of the generic secret patterns (API keys, JWT, DB connection URIs, PEM keys, GitHub tokens, …) are redacted even when the key name is neutral.
- **IPv4 redaction (Option A)**: any IPv4 address in a config value is redacted, except `127.0.0.1` and `0.0.0.0`.
- **Key and structure preserved**: the key name, indentation, and separator (`=` / `: `) are never altered, so the model can reason about which settings are present without seeing the secret values.
- **Comments and blank lines**: `#`, `!` comment lines and blank lines pass through unmodified.

The response JSON contains:

- `content`: the sanitized file text
- `redactions`: list of pattern labels that fired (e.g. `CONFIG_SENSITIVE_KEY`, `DB_CONNECTION_URI`, `CONFIG_IPV4`)

`get_file_outline` applies the same sanitization defensively when called on a config file, returning the key structure without exposing values.

### Documentation Generation

`generate_project_docs` produces structured Markdown documentation by statically analysing the project's AST. It accepts four optional parameters:

| Parameter     | Type            | Default                                  | Description                                                  |
| ------------- | --------------- | ---------------------------------------- | ------------------------------------------------------------ |
| `sections`    | `array[string]` | `["overview","usage","api","use_cases"]` | Sections to include: `overview`, `usage`, `api`, `use_cases` |
| `public_only` | `boolean`       | `true`                                   | When `true`, only documents public symbols                   |
| `max_files`   | `integer`       | `50`                                     | Maximum number of files to analyse                           |
| `language`    | `string`        | `"en"`                                   | Output language: `"en"`, `"es"`, `"ca"`                      |

The tool infers project entry-points and use-cases from the AST (via `detect_entrypoints` / `infer_use_cases` in `src/analyzer.rs`) and all output is sanitized through the Privacy Gateway before reaching the client.

### Linting

`lint_file` adds a new file-level linting entry point that combines always-on tree-sitter-based checks with an optional external-linter layer.

- Tree-sitter linting is always available and is used to surface lightweight diagnostics immediately.
- External linters are enabled only when `MCP_LINT_ENABLED` is set to a truthy value.
- `MCP_LINT_TIMEOUT_SECS` controls the timeout budget for the external pass.
- `inspect_symbol` now appends lint summaries for the inspected symbol range when linting is enabled, capped to avoid inflating responses.
- The lint tool is sanitized through the Privacy Gateway before returning results.

#### Level 1 vs Level 2

- **Level 1**: fast built-in checks with real line/column reporting and basic filtering to avoid false positives inside inline comments and string literals.
- **Level 2**: optional external linters, selected per language, with graceful degradation when the tool is not installed.

#### Supported External Linters

When `MCP_LINT_ENABLED=true`, NexusIntelliCore attempts to run one external linter depending on the file language:

| Language                      | External tool  | Notes                                                                           |
| ----------------------------- | -------------- | ------------------------------------------------------------------------------- |
| Rust                          | `cargo clippy` | Parses JSON diagnostics and filters them to the requested file                  |
| JavaScript / TypeScript / TSX | `eslint`       | Uses local `node_modules/.bin/eslint` when available, otherwise global `eslint` |
| Python                        | `mypy`         | Uses text diagnostics with columns and error codes                              |
| Java                          | `javac`        | Runs with `-Xlint` and parses compiler warnings/errors                          |
| Kotlin                        | `ktlint`       | Preferred Kotlin linter                                                         |
| Kotlin fallback               | `kotlinc`      | Used automatically when `ktlint` is not available                               |
| C                             | `cppcheck`     | Parses machine-friendly templated diagnostics                                   |
| C#                            | `dotnet build` | Searches for the nearest `.csproj` or `.sln` and parses compiler diagnostics    |

If the selected tool is missing from the environment, the server does not fail the request; it returns an informational diagnostic describing the missing dependency.

#### Environment Variables

- `MCP_LINT_ENABLED`: enables the Level 2 external-linter pass when set to a truthy value (`1`, `true`, `TRUE`, `yes`, `on`).
- `MCP_LINT_TIMEOUT_SECS`: timeout budget for each external linter process. Default: `10` seconds.

#### Practical Notes

- Kotlin files (`.kt`, `.kts`) are recognized for external linting even though there is no built-in Tree-sitter AST extraction for Kotlin yet.
- For C#, external linting requires a nearby `.csproj` or `.sln`; otherwise the server returns an informational diagnostic instead of failing.
- For Kotlin, `ktlint` is tried first; if it is not installed, NexusIntelliCore falls back automatically to `kotlinc`.
- External linting remains opt-in so the server can still be used in minimal environments without language-specific tooling installed.

#### Practical Prompting Guide (Lint)

Use linting as a context filter, not as extra output for every request. The main savings come from reducing code you send to the model, not from adding more diagnostics.

Recommended flow:

1. Locate first: `get_file_outline` or `get_module_summary`.
2. Narrow to one unit: `inspect_symbol` for a specific function/class.
3. Ask for lint summary only on that unit, then request a targeted fix.

Prompt patterns that usually save tokens:

- "Inspect `<symbol>` and return lint diagnostics only (no source dump)."
- "Return only `warning` and `error` diagnostics. Ignore informational tool-availability notices."
- "Cap output to the top N diagnostics and propose a minimal patch."
- "Use `inspect_symbol` on the target method instead of reading the full file."

Prompt patterns that usually waste tokens:

- "Analyze the whole module" when you only need one function.
- Requesting full source and full lint output in the same step.
- Repeating external lint requests after a clear "tool not found" diagnostic.

Important limitations (honest expectations):

- Level 1 is intentionally lightweight; it is useful for fast signals, not deep semantic correctness.
- Level 2 value depends on installed tooling (`eslint`, `mypy`, `javac`, `ktlint`, etc.).
- Kotlin currently relies on external linting for deeper checks.
- HTML/SCSS lint depth may be lower than TypeScript/Rust depending on installed tools.

Rule of thumb: if lint output does not change your next action, do not request it for that step.

---

### CSS, HTML, and Angular Support

`get_file_outline` understands CSS and HTML files:

- **CSS** — extracts all rule-set selectors, their property counts, line ranges, and enclosing `@media` queries.
- **HTML** — extracts element tags, referenced CSS class names, Angular input (`[…]`) and output (`(…)`) bindings, and flags Angular component tags (tags containing a hyphen).
- **SCSS / Sass** — files are detected and their language reported, but selectors are not parsed (returned as an empty outline).

`analyze_angular_component` resolves the full triad of an Angular component:

- Reads the `@Component` decorator from a `.component.ts` file.
- Resolves `templateUrl` → HTML file, `styleUrls` → CSS files.
- Normalises relative paths (including `..` segments) without touching the filesystem.
- Returns a combined JSON object with `component`, `template`, and `styles` sections, sanitised through the Privacy Gateway.

### Privacy and Security Controls

- Centralized output sanitization via Privacy Gateway.
- Secret redaction in returned content.
- Support for `@mcp-strip` behavior in symbol outputs.
- Path validation and project-root boundary enforcement.
- Restricted file handling through `.mcpignore` policies.
- **Client Authentication**: Restricts connections using a shared secret token.
- **Tool Access Control**: Limits the tools a client can invoke.
- **Detailed Audit Trail**: Structured event logging for security monitoring.

### Runtime Security Configuration

The server's security behaviors are defined through environment variables or a configuration JSON file.

#### Environment Variables

- `MCP_AUTH_TOKEN`: The expected token required from the client on the `initialize` handshake.
- `MCP_ALLOWED_TOOLS`: Comma-separated list of tool names allowed to be executed (e.g., `get_project_structure,get_file_outline`). If empty/unset, all tools are permitted.
- `MCP_AUDIT_LOG_PATH`: Path to a file where all protocol/lifecycle requests and tool call attempts will be recorded in JSON lines (NDJSON) format.
- `MCP_SECURITY_CONFIG_PATH`: Path to a JSON configuration file (details below).

#### JSON Configuration Example

Create a file (e.g. `security-config.json`):

```json
{
  "auth_token": "my-secret-handshake-token-123",
  "allowed_tools": [
    "get_project_structure",
    "get_file_outline",
    "inspect_symbol"
  ],
  "audit_log_path": "/var/log/nexusintellicore-audit.log"
}
```

Point the server to it:

```bash
export MCP_SECURITY_CONFIG_PATH=/path/to/security-config.json
target/release/nexusintellicore /absolute/path/to/project
```

#### Authentication Handshake

When `auth_token` is enabled, the client must pass the matching token inside the `initialize` parameters. The server checks the following paths in the parameters hierarchy:

- `params.auth_token`
- `params.token`
- `params._meta.auth_token`
- `params._meta.token`

Requests received prior to successful initialization will be rejected with an authentication error code `-32001`. Unauthorized tool calls return `-32003`.

## Architecture Overview

High-level module responsibilities:

- `src/main.rs`: server bootstrap, MCP lifecycle handling, request dispatch
- `src/transport.rs`: stdio framing/parsing and transport I/O
- `src/protocol.rs`: JSON-RPC protocol types and response helpers
- `src/tools/mod.rs`: tool registry and tool dispatch implementation
- `src/tools/deps_graph/`: modular implementation of `get_dependencies_graph` split into import resolution, graph building, cycle detection, and rendering helpers
- `src/state/mod.rs`: `ServerState` facade that composes cache, index, metrics, path-alias resolution, and watcher-refresh coordination
- `src/state/cache.rs`: AST cache and tool-response cache management using `moka::future::Cache`, including selective invalidation of cached tool results when a file changes
- `src/state/index.rs`: `FileIndex` lifecycle management and refresh orchestration
- `src/state/metrics.rs`: server counters and operational metrics (cache hits/misses, invocation counts, concurrency rejections)
- `src/state/resolver.rs`: path validation, JSON canonicalization for cache keys, and TS/JS path-alias discovery/resolution
- `src/indexer.rs`: file discovery, tree rendering, restriction matching
- `src/analyzer.rs`: language detection and syntax/AST extraction with Tree-sitter (Rust, Python, JS, TS, Java, C, C#, CSS, HTML); entry-point detection and use-case inference for `generate_project_docs`
- `src/relations.rs`: Angular `@Component` decorator parser — resolves `templateUrl` and `styleUrls` to filesystem paths
- `src/watcher.rs`: file-system watcher (FSEvents/inotify via `notify`); classifies events into cache invalidation or index refresh, with 500 ms debounce for topological changes, operating against the shared `ServerState`
- `src/privacy_gateway.rs`: policy-driven sanitization layer
- `src/sanitizer.rs`: secret detection/redaction utilities; `sanitize_config_text` for key-value config files; `is_config_file` for format detection

## Requirements

- Rust toolchain (stable)
- Cargo
- Bash (for probe script)
- Python 3 (used by the probe script parser)

Optional external linting tools, depending on the languages you want to support:

- Rust: `cargo clippy`
- JavaScript / TypeScript / TSX: `eslint`
- Python: `mypy`
- Java: `javac`
- Kotlin: `ktlint` or `kotlinc`
- C: `cppcheck`
- C#: `.NET SDK` (`dotnet`)

## Build

```bash
cargo build --release
```

Binary output:

- `target/release/nexusintellicore`

## Run Locally

Use a project root as argument:

```bash
target/release/nexusintellicore /absolute/path/to/project
```

Alternative (environment variable):

```bash
MCP_ROOT_PATH=/absolute/path/to/project target/release/nexusintellicore
```

## VS Code MCP Configuration Example

Example `.vscode/mcp.json`:

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
scripts/mcp_handshake_probe.sh --server ./target/release/nexusintellicore --root "$(pwd)"
```

Helpful probe options:

- `--tool tools/list`
- `--timeout 10`

## Tooling Notes

- The file index is initialized lazily on first index-dependent call.
- Analysis results are cached by file modification time.
- The file-system watcher (`notify`) automatically invalidates cache entries on content changes and schedules an index rebuild (debounced 500 ms) on create/remove/rename events; this requires no manual `refresh_index` call during normal operation.
- Security audit output reports issue type and location, never secret values.

## Using NexusIntelliCore Effectively

NexusIntelliCore is most useful when it helps reduce irrelevant context before sending anything to an LLM. The main savings do not come from adding more context; they come from narrowing the context to the smallest slice that still explains the behavior you care about.

This matters especially in Angular and Java projects, where it is easy to waste tokens on:

- entire components or services
- full controller-service-repository chains
- large feature modules or multiple layers "just in case"

In practice, the most effective workflow is:

1. `get_project_structure` to locate the relevant slice.
2. `get_file_outline` to inspect imports, types, and signatures without sending implementation details.
3. `inspect_symbol` only for the method, service, or class that directly controls the behavior.
4. `get_dependencies_graph` only when the change spans multiple modules or layers.

For Angular, this usually means inspecting the outline of a component and its backing service before opening any full implementation. For Java, it usually means starting from a controller or service outline, then inspecting one public method and following one call hop at a time.

The practical rule is simple: do not send whole files unless you already know they are the minimal necessary unit.

### Honest Guidance

NexusIntelliCore will not compensate for poor context discipline. If you use it to ask an LLM to "analyze the whole module" or "understand the full backend flow," token usage will still be high and answer quality will still degrade.

The tool is a context filter, not a substitute for engineering judgment.

What it does well:

- expose project structure quickly
- surface signatures, types, and imports without dumping full source
- let you inspect one symbol at a time
- reduce unnecessary code sent to the model

What it does not do:

- understand business intent on its own
- replace debugging hypotheses or architectural judgment
- make broad prompts efficient if the prompt itself is unfocused

If used well, NexusIntelliCore can materially reduce token usage and improve answer precision. If used loosely, it mostly becomes another layer of noise.

### Practical Example: Creating a Component with Project Context

The most effective use of NexusIntelliCore is not to generate code directly, but to extract your project's exact patterns before asking an LLM to create code. This results in a precise, context-aware prompt that produces correct code on the first try instead of multiple iterations.

**Scenario**: You need to create a success/error dialog component in Angular.

**Without NexusIntelliCore (weak prompt)**:

```
Create an Angular dialog component that shows success or error messages.
```

Result: Generic Material dialog. Doesn't match your project's styling, patterns, or service architecture. Requires iterations to fix.

**With NexusIntelliCore (strong prompt)**:

1. **Investigate structure**:
   - `get_project_structure` → find `src/app/shared/dialogs` and `src/app/core/services`

2. **Extract existing pattern**:
   - `get_file_outline` on `src/app/shared/dialogs/notification-dialog.component.ts` → see current inputs, outputs, imports
   - `inspect_symbol` on the component's `constructor` → copy exact dependency injection pattern
   - `inspect_symbol` on the RxJS subscription pattern → see how ngOnDestroy cleanup works

3. **Find styling and theming**:
   - `get_file_outline` on `src/app/shared/styles/theme.scss` → see available CSS variables
   - `search_design_patterns` on `src/app/shared/dialogs` → confirm the modal/dialog pattern used

4. **Extract service integration**:
   - `get_file_outline` on `src/app/core/services/notification.service.ts` → see how errors are broadcast
   - `get_dependencies_graph` → understand which services depend on which

5. **Generate precise prompt** to the LLM:

```
Create a SuccessErrorDialogComponent for Angular based on these project-specific requirements:

**Existing Pattern (from NotificationDialogComponent)**:
- MatDialog.DialogRef<NotificationDialogComponent> injected in constructor
- @Input() message: string
- @Input() type: 'success' | 'error' | 'info'
- @Output() onClose = new EventEmitter<void>()
- RxJS: destroy$ = new Subject<void>()
- ngOnDestroy: destroy$.next(); destroy$.complete()

**Styling** (from theme.scss):
- Success: var(--color-success-light), var(--color-success-dark)
- Error: var(--color-error-light), var(--color-error-dark)
- Use Tailwind utilities where possible, custom vars for colors

**Service Integration** (from notification.service.ts):
- Inject NotificationService
- Subscribe to errorOccurred$ event in ngOnInit
- Use takeUntil(destroy$) to unsubscribe

**Requirements**:
1. Auto-close after 5 seconds for success, manual close for error
2. Display icon (checkmark for success, X for error)
3. Dismiss button that emits onClose
4. Follow existing NotificationDialogComponent structure exactly
5. Use the same imports and dependencies

Here is the exact constructor signature from NotificationDialogComponent:
[copied from inspect_symbol]

Here are the exact styles from theme.scss:
[copied from get_file_outline]
```

Result: The LLM creates a component that fits perfectly into your project on the first try. No iteration needed. Tokens saved because the first response is correct.

**The difference in practice**:

- Without NexusIntelliCore: 4-6 exchanges with the LLM, lots of "adjust the styling", "use this pattern", "add this service"
- With NexusIntelliCore: 1-2 exchanges, minimal adjustments

The time investment in NexusIntelliCore queries (2-3 minutes) pays back immediately in fewer LLM iterations and higher-quality code.

## Known Constraints

- Design-pattern detection is heuristic.
- Dependency resolution is best-effort across languages.
- Security checks intentionally favor broad detection and may require manual validation.
- SCSS and Sass files are detected and reported as `scss` but their selectors are not parsed.
- `analyze_angular_component` does not resolve dynamically constructed `templateUrl`/`styleUrls` expressions or spread operators in the decorator.
- Inline `template` and `styles` properties inside `@Component` are not parsed by `analyze_angular_component`.

## License

This project is licensed under the MIT License. See `LICENSE.md` for the full text.
