# NexusIntelliCore - Complete Project Documentation

## Overview

**NexusIntelliCore** is a Model Context Protocol (MCP) server implementation in Rust that provides comprehensive code analysis, auditing, and documentation capabilities for multi-language codebases.

### Project Statistics

- **Primary Language**: Rust (25 files)
- **Public API Symbols**: 66 functions, 27 types (49 documented)
- **Architecture**: Modular MCP-compliant server with privacy-first security gateway
- **Build System**: Cargo (Rust package manager)

## Key Features

### 1. **Code Analysis Engine**

- Multi-language AST parsing (Java, TypeScript, Python, C#, Go, Rust)
- Semantic import classification
- Function/class/method extraction
- CSS rule extraction from stylesheets
- HTML element analysis with Angular binding detection

### 2. **Security Auditing**

- AST-based vulnerability detection
- Hardcoded secret pattern recognition
- Security finding classification (XSS, SQL injection, etc.)
- Privacy-preserving data sanitization

### 3. **Design Pattern Detection**

- Factory pattern recognition
- Builder pattern detection
- Observer, Repository, Singleton, and Strategy pattern identification
- Confidence scoring for pattern matches

### 4. **Dependency Graph Analysis**

- Module-level dependency mapping
- Import kind classification (internal/external/restricted)
- Circular dependency detection
- Dependency visualization support

### 5. **Documentation Generation**

- Automatic project structure documentation
- API surface analysis
- Use case inference from docstrings
- Entrypoint detection and classification

## Getting Started

### Building the Project

```bash
cargo build --release
```

### Running the MCP Server

```bash
cargo run --release
```

The server listens on stdin/stdout and communicates via JSON-RPC 2.0 protocol with MCP framing.

### Running Tests

```bash
# All tests
cargo test

# Integration tests (note: some tests are currently disabled)
cargo test --test integration
cargo test --test privacy_gateway_integration
```

## Architecture Overview

### Core Modules

| Module               | Purpose                                           |
| -------------------- | ------------------------------------------------- |
| `main.rs`            | MCP server entry point, JSON-RPC request handling |
| `analyzer.rs`        | AST parsing and code analysis engine              |
| `protocol.rs`        | JSON-RPC 2.0 request/response structures          |
| `privacy_gateway.rs` | Data sanitization and privacy preservation        |
| `sanitizer.rs`       | Pattern-based secret/sensitive data redaction     |
| `indexer.rs`         | File discovery and indexing with glob patterns    |
| `state.rs`           | Server state management with LRU cache            |
| `transport.rs`       | MCP framing and stdio communication               |
| `watcher.rs`         | File system monitoring for real-time updates      |

### Tools (MCP Handler Implementations)

| Tool              | Functionality                                          |
| ----------------- | ------------------------------------------------------ |
| `angular.rs`      | Angular component analysis and relationship extraction |
| `audit.rs`        | Security auditing and finding reporting                |
| `definitions.rs`  | Symbol definition lookup                               |
| `deps_graph.rs`   | Dependency graph analysis and visualization            |
| `outline.rs`      | Code outline and structure extraction                  |
| `patterns.rs`     | Design pattern detection                               |
| `project.rs`      | Project-level analysis                                 |
| `project_docs.rs` | Documentation generation                               |
| `server.rs`       | Server lifecycle and status                            |
| `summary.rs`      | Module summaries and public API extraction             |
| `symbol.rs`       | Symbol inspection and analysis                         |

## Security Considerations

### Privacy Gateway

All user data flows through the `privacy_gateway` before processing:

- Automatic detection and redaction of sensitive information
- Pattern-based secret recognition (API keys, credentials, tokens, etc.)
- Internal hostname and private IP masking
- Database connection string sanitization

### Security Findings

The audit engine detects:

- XSS vulnerabilities in web templates
- SQL injection patterns
- Unsafe code blocks (Rust-specific)
- Hardcoded credentials
- Weak cryptographic implementations

### Audit Report

**Total Security Issues Found**: 32

- Most issues are intentionally hardcoded patterns used for sanitization rule validation
- Real application should implement environment-based secret management

## API Surface

### Main Entry Points

#### `analyze_file(path: &Path) -> Result<FileAnalysis>`

Comprehensive AST-based analysis of a source file. Returns structure information, imports, functions, classes, and security findings.

#### `audit_file_ast(source: &str, lang: &Lang) -> Vec<AuditFinding>`

Run AST-based security checks on source code. Returns findings with severity and source location.

#### `detect_patterns(analysis: &FileAnalysis, file_path: &str) -> Vec<PatternMatch>`

Scan code structure for common design patterns. Returns confidence-scored matches.

#### `extract_component_info(ts_file: &Path, source: &str) -> Option<AngularComponentInfo>`

Extract Angular component metadata and resolve related template/style files.

#### `infer_use_cases(analyses: &[(PathBuf, FileAnalysis)]) -> Vec<InferredUseCase>`

Analyze public API and documentation to infer practical use cases.

### Response Structures

All tools return JSON via MCP protocol:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Analysis results..."
    }
  ]
}
```

## Design Patterns Detected

### Factory Pattern

- **Location**: `src/analyzer.rs`, `src/watcher.rs`
- **Detection**: Multiple `create_*()`, `make_*()`, `new_*()` constructors
- **Confidence**: 4 methods in analyzer, 2 methods in watcher

## Dependency Overview

### Core Dependencies

| Dependency    | Purpose             | Version |
| ------------- | ------------------- | ------- |
| `anyhow`      | Error handling      | ^1.0    |
| `serde`       | Serialization       | ^1.0    |
| `serde_json`  | JSON support        | ^1.0    |
| `tokio`       | Async runtime       | ^1.0    |
| `tree-sitter` | AST parsing         | ^0.20   |
| `tracing`     | Structured logging  | ^0.1    |
| `regex`       | Pattern matching    | ^1.0    |
| `notify`      | File watching       | ^6.0    |
| `lru`         | LRU cache           | ^0.12   |
| `lazy_static` | Lazy initialization | ^1.4    |
| `globset`     | Glob matching       | ^0.4    |

## Use Cases

### 1. **Code Analysis & Intelligence**

Analyze large codebases to extract structure, relationships, and metrics.

### 2. **Security Auditing**

Detect security vulnerabilities and hardcoded secrets in source code.

### 3. **Architecture Documentation**

Automatically generate project documentation from code analysis.

### 4. **Pattern Recognition**

Identify design patterns and architectural styles in existing codebases.

### 5. **AI Integration**

Provide comprehensive code context for AI-assisted development tools.

### 6. **Legacy System Modernization**

Analyze legacy applications for modernization opportunities.

## File Structure

```
NexusIntelliCore/
├── src/
│   ├── main.rs                 # MCP server entry point
│   ├── analyzer.rs             # Code analysis engine
│   ├── protocol.rs             # JSON-RPC structures
│   ├── privacy_gateway.rs      # Data sanitization
│   ├── sanitizer.rs            # Pattern-based redaction
│   ├── indexer.rs              # File discovery
│   ├── state.rs                # Server state
│   ├── transport.rs            # MCP framing
│   ├── watcher.rs              # File monitoring
│   ├── audit_queries.rs        # Audit queries
│   ├── relations.rs            # Component relationships
│   └── tools/                  # MCP tool handlers
│       ├── mod.rs
│       ├── angular.rs
│       ├── audit.rs
│       ├── definitions.rs
│       ├── deps_graph.rs
│       ├── outline.rs
│       ├── patterns.rs
│       ├── project.rs
│       ├── project_docs.rs
│       ├── server.rs
│       ├── summary.rs
│       └── symbol.rs
├── tests/
│   ├── integration.rs
│   └── privacy_gateway_integration.rs
├── Cargo.toml                  # Project manifest
├── Makefile.toml               # Build automation
└── docs/                       # Documentation
```

## Contributing

When contributing to NexusIntelliCore:

1. Ensure all new features include appropriate error handling with `anyhow::Result`
2. Add security audit coverage for new file type support
3. Include documentation comments for public APIs
4. Run tests: `cargo test`
5. Check code with: `cargo clippy`

## Performance Characteristics

- **LRU Cache**: Configurable up to 1024 entries for analysis results
- **File Watching**: Recursive directory watching with debouncing
- **Memory**: ~50-100MB typical footprint
- **Analysis**: Sub-second for individual files, scales linearly with codebase size

## Known Limitations

1. **Integration Tests**: Some tests disabled due to MCP framing bug with multiple sequential messages
2. **Language Support**: Tree-sitter parsers included for major languages, extensible for others
3. **Circular Dependencies**: Partial cycle detection, not fully bidirectional

## Future Roadmap

- [ ] Extended language support (Kotlin, Groovy, etc.)
- [ ] Machine learning-based pattern classification
- [ ] Real-time dependency updates
- [ ] Integration with popular IDEs
- [ ] Custom rule engine for audit queries

## License

See LICENSE.md for details.

## Support

For issues, questions, or contributions, please refer to the project's issue tracker and contribution guidelines.

---

For detailed information on specific topics, see:

- [architecture.md](./architecture.md) - Deep dive into system design
- [SECURITY.md](./SECURITY.md) - Security best practices and audit findings
- [API.md](./API.md) - Complete API reference
