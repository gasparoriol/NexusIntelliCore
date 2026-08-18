# NexusIntelliCore - Architecture & System Design

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│         MCP Server (JSON-RPC 2.0)                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  Transport Layer (MCP Framing)               │  │
│  │  - Stdin/Stdout communication                │  │
│  │  - Frame serialization/deserialization       │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │                                   │
│  ┌──────────────▼───────────────────────────────┐  │
│  │  Protocol Handler (JSON-RPC Router)          │  │
│  │  - Request routing                           │  │
│  │  - Response formatting                       │  │
│  │  - Error handling                            │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │                                   │
│  ┌──────────────▼───────────────────────────────┐  │
│  │  Tool Handlers                               │  │
│  │  ├── Angular Component Analysis              │  │
│  │  ├── Security Auditing                       │  │
│  │  ├── Dependency Graph Analysis               │  │
│  │  ├── Design Pattern Detection                │  │
│  │  ├── Code Outline Extraction                 │  │
│  │  ├── Documentation Generation                │  │
│  │  └── More...                                 │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │                                   │
│  ┌──────────────▼───────────────────────────────┐  │
│  │  Privacy Gateway                             │  │
│  │  - Input sanitization                        │  │
│  │  - Output redaction                          │  │
│  │  - Sensitive data masking                    │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │                                   │
│  ┌──────────────▼───────────────────────────────┐  │
│  │  Core Analysis Engine                        │  │
│  │  ├── Analyzer (AST parsing)                  │  │
│  │  ├── Indexer (File discovery)                │  │
│  │  ├── Relations (Component linking)           │  │
│  │  ├── Watcher (File monitoring)               │  │
│  │  └── State Manager (LRU cache)               │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │                                   │
│  ┌──────────────▼───────────────────────────────┐  │
│  │  File System & Tree-Sitter Parsers           │  │
│  │  - Language detection                        │  │
│  │  - AST generation                            │  │
│  │  - Symbol extraction                         │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Component Deep Dive

### 1. Transport Layer (`transport.rs`)

**Responsibility**: Handle MCP frame protocol and JSON-RPC serialization

**Key Operations**:

- Read JSON-RPC requests from stdin with proper framing
- Serialize responses with MCP headers
- Handle async I/O with Tokio
- Parse multiline JSON payloads

**Data Flow**:

```
Raw stdin bytes → Parse MCP frame → Extract JSON-RPC → Route to handler
```

### 2. Protocol Layer (`protocol.rs`)

**Responsibility**: Define and validate JSON-RPC 2.0 structures

**Core Types**:

```rust
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<Value>,
    pub error: Option<RpcError>,
    pub id: Value,
}
```

### 3. Privacy Gateway (`privacy_gateway.rs`)

**Responsibility**: Sanitize all data flowing through the system

**Sanitization Rules**:

- **Secrets**: API keys, tokens, credentials
- **Infrastructure**: Hostnames, internal IPs, database URLs
- **Personally Identifiable**: Emails, phone numbers
- **Credentials**: Passwords, encryption keys

**Processing Pipeline**:

```
User input → Sanitizer rules → Pattern matching → Redaction → Output
```

### 4. Analyzer Engine (`analyzer.rs`)

**Responsibility**: AST-based code analysis

**Supported Languages**:

- Java, TypeScript, Python, C#, Go, Rust, C/C++
- HTML/CSS (via template extraction)
- JSON, XML (basic)

**Analysis Output** (`FileAnalysis`):

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

**Analysis Flow**:

```
File path → Language detection → Tree-sitter parser → AST traversal
→ Symbol extraction → Relationship mapping → Security audit → Result
```

### 5. Indexer (`indexer.rs`)

**Responsibility**: Discover and catalog project files

**Features**:

- Glob pattern support for include/exclude
- Efficient file walking with `ignore` crate
- Respect .gitignore patterns
- Build file-to-language index

**Output**: `FileIndex` (BTreeMap of path → language)

### 6. State Management (`state.rs`)

**Responsibility**: Cache analysis results and manage lifecycle

**Features**:

- LRU cache (default 1024 entries) for analysis results
- Atomic flags for server state
- File modification tracking
- Thread-safe with `Arc<RwLock>`

**Cache Strategy**:

```
Request for file → Check cache (hit/miss)
→ If miss, analyze → Store in LRU → Return result
```

### 7. File Watcher (`watcher.rs`)

**Responsibility**: Monitor file system for changes

**Capabilities**:

- Recursive directory watching
- Event filtering (create, modify, delete, rename)
- Debouncing of rapid changes
- Update server state on changes

**Event Types**:

- `Create`: New file/directory
- `Modify`: File content/metadata changes
- `Remove`: File/directory deletion
- `Rename`: File/directory renaming

### 8. Relations Engine (`relations.rs`)

**Responsibility**: Resolve component relationships (Angular-specific)

**Processing**:

```typescript
// Input: Angular component decorator
@Component({
  selector: 'app-hero',
  templateUrl: './hero.component.html',
  styleUrls: ['./hero.component.css']
})

// Output: AngularComponentInfo
AngularComponentInfo {
  selector: 'app-hero',
  template_path: './hero.component.html',
  style_paths: ['./hero.component.css'],
  ...
}
```

## Tool Implementations (MCP Handlers)

### Angular Component Analysis (`tools/angular.rs`)

**Input**: TypeScript file path and source

**Process**:

1. Extract `@Component` decorator
2. Resolve `templateUrl` and `styleUrls`
3. Extract selector and component metadata
4. Return resolved file paths

**Output**: JSON with component structure

### Security Auditing (`tools/audit.rs`)

**Input**: File path or source code

**Process**:

1. Detect language
2. Parse AST
3. Run security checks
4. Classify findings (Severity, Type, Location)

**Finding Classifications**:

- XSS (Cross-Site Scripting)
- SQL Injection
- Command Injection
- Path Traversal
- Unsafe Operations

### Dependency Graph (`tools/deps_graph.rs`)

**Input**: Project root

**Process**:

1. Index all files
2. Analyze imports in each file
3. Classify import types (internal/external/circular)
4. Build dependency matrix

**Output**: Graph representation (JSON/DOT format)

### Design Pattern Detection (`tools/patterns.rs`)

**Patterns Detected**:

- **Factory**: Multiple constructors (`create_*`, `make_*`, `new_*`)
- **Builder**: Chainable method calls with fluent API
- **Observer**: Event listeners and subscribers
- **Repository**: Data access abstraction
- **Singleton**: Private constructor with static instance
- **Strategy**: Pluggable algorithm implementations

### Documentation Generation (`tools/project_docs.rs`)

**Process**:

1. Analyze all files
2. Extract public API symbols
3. Parse documentation comments
4. Infer use cases from symbol names
5. Generate markdown documentation

**Output Structure**:

```
# Project Overview
## Architecture
## API Reference
## Use Cases
## Code Examples
```

## Data Flow Example: Complete Analysis

```
1. Client sends:
   {
     "jsonrpc": "2.0",
     "method": "analyze_project",
     "params": { "path": "/project" },
     "id": 1
   }

2. Transport layer reads MCP frame

3. Router identifies method → routes to project.rs tool

4. Tool handler:
   - Calls indexer to find files
   - For each file:
     a. Sanitizes path through privacy gateway
     b. Loads analyzer for language
     c. Parses with Tree-sitter
     d. Extracts symbols and relationships
     e. Runs security audit
     f. Caches result in LRU
   - Aggregates results

5. Privacy gateway sanitizes output (redacts secrets)

6. Formats as JSON-RPC response

7. Transport layer wraps with MCP framing

8. Sends via stdout to client
```

## Concurrency Model

**Thread Safety**:

- `Arc<RwLock<ServerState>>`: Shared mutable state
- `tokio::sync` primitives for async operations
- No global mutable state (functional paradigm)

**Async Runtime**:

- Tokio for async I/O
- Blocking operations wrapped with `tokio::task::block_in_place`
- Timeout support for long-running analyses

## Memory Management

**LRU Cache**:

- Default size: 1024 entries
- Eviction policy: Least Recently Used
- Per-entry: FileAnalysis structure (~1-5 KB each)

**Profiling Considerations**:

- Large codebases: Monitor cache hit ratio
- Adjust cache size based on available memory
- Periodic cache refresh via `refresh_index` tool

## Security Architecture

### Privacy-First Design

```
Untrusted Input
      ↓
Privacy Gateway (aggressive sanitization)
      ↓
Internal Processing (clean data only)
      ↓
Privacy Gateway (output redaction)
      ↓
Trusted Output
```

### Secret Pattern Matching

Patterns recognized:

- OpenAI API keys (`sk-*`)
- AWS credentials
- GitHub tokens
- JWT tokens
- Database connection strings
- Private PEM keys
- Internal hostnames
- Private IP addresses

### Audit Trail

Security findings include:

- Finding type and severity
- Source file and line number
- Code context
- Remediation hints

## Extension Points

### Adding New Language Support

1. **Tree-sitter Grammar**: Add parser binary
2. **Language Detection**: Update `detect_language()` in analyzer.rs
3. **Analysis Rules**: Add language-specific checks
4. **Test Coverage**: Add test files

### Adding New Tools

1. Create `src/tools/newtool.rs`
2. Implement MCP handler function
3. Register in `src/tools/mod.rs`
4. Add to `tool_definitions` list
5. Document via `tools/definitions.rs`

### Adding New Audit Checks

1. Define finding type in analyzer.rs
2. Implement check logic in `audit_file_ast()`
3. Add test cases
4. Document in security guidelines

## Performance Optimization Strategies

1. **Lazy Parsing**: Only parse when tool is called
2. **Caching**: LRU cache prevents re-analysis
3. **Selective Imports**: Only analyze relevant sections
4. **Parallel Analysis**: Process multiple files concurrently
5. **Early Exit**: Stop parsing when condition met

## Deployment Considerations

### Recommended Configuration

```
Environment Variable | Default | Purpose
RUST_LOG           | info    | Logging level
MCP_CACHE_SIZE     | 1024    | LRU cache entries
MAX_FILE_SIZE      | 100MB   | Maximum file to analyze
TIMEOUT_SECS       | 30      | Operation timeout
```

### Resource Requirements

- **CPU**: Single-threaded async, scales with # of concurrent requests
- **RAM**: ~100MB baseline + 5-10MB per cached analysis
- **Disk**: <500MB for binary + dependencies
- **I/O**: Efficient for file scanning

---

For more information, see:

- [README.md](./README.md) - Project overview
- [SECURITY.md](./SECURITY.md) - Security details
- [API.md](./API.md) - API reference
