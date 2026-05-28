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

The server currently exposes nine MCP tools:

1. `list_directory`
2. `read_file`
3. `search_code`
4. `get_file_outline`
5. `analyze_code`
6. `get_server_stats`
7. `refresh_index`
8. `get_lru_stats`
9. `analyze_angular_component`

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
- `src/analyzer.rs`: language detection and syntax/AST extraction with Tree-sitter (Rust, Python, JS, TS, Java, C, C#, CSS, HTML)
- `src/relations.rs`: Angular `@Component` decorator parser — resolves `templateUrl` and `styleUrls` to filesystem paths
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
