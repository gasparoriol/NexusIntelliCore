# NexusIntelliCore — Security Guide

This document covers the security architecture, hardening features, Privacy Gateway, and security best practices for NexusIntelliCore.

---

## Security Hardening Features (v1.0.0)

NexusIntelliCore implements four enterprise-grade hardening features:

### S1 — Constant-Time Token Comparison

Token verification uses **constant-time digest comparison** that computes fixed-size 32-byte SHA-256 hashes over all inputs unconditionally.

- **No early returns on length mismatch** — eliminates length-leakage timing attacks
- Implemented in `security.rs`: `constant_time_compare_hashes()` and `constant_time_compare()`

### S2 — Token Hashing & Memory Hardening

Raw authentication tokens (`MCP_AUTH_TOKEN`) are **never stored in plain-text memory**:

1. On startup, the token string is immediately hashed into a 32-byte digest (`auth_token_hash`)
2. The original string is discarded from memory
3. All authentication checks compare hashes only

Implemented in `security.rs`: `compute_token_digest()`

### S3 — Authentication Rate Limiting

Failed authentication attempts on the `initialize` MCP method trigger:

- Automatic exponential backoff delay: **250ms → 500ms → 1s → 2s** (max)
- Counter: `AUTH_FAILURE_COUNT` atomic integer
- Prevents brute-force attacks on the MCP server

### S4 — Tamper-Evident Audit Logging

When `MCP_AUDIT_LOG_PATH` is set, every protocol and lifecycle event is logged in **append-only NDJSON format** with:

- Chained hashes: each record includes `prev_hash` and its own `hash`
- Creates an **immutable cryptographic hash chain** across all audit records
- Any tampering with historical records breaks the chain

```bash
# Enable audit logging
MCP_AUDIT_LOG_PATH=/var/log/nexusintellicore-audit.ndjson nexusintellicore /path/to/project
```

---

## Privacy Gateway

All tool inputs and outputs pass through the centralized **Privacy Gateway** before reaching the client. This is the primary data protection layer.

### What Gets Redacted

| Category | Examples | Replacement |
|---|---|---|
| OpenAI API keys | `sk-abc123...` | `[REDACTED_OPENAI_KEY]` |
| AWS credentials | `AKIA...` | `[REDACTED_AWS_KEY]` |
| GitHub tokens | `ghp_...` | `[REDACTED_GITHUB_TOKEN]` |
| JWT tokens | `eyJhbGc...` | `[REDACTED_JWT]` |
| Database URIs | `postgresql://user:pass@host/db` | `[REDACTED_DB_URI]` |
| PEM private keys | `-----BEGIN RSA PRIVATE KEY-----` | `[REDACTED_PEM_KEY]` |
| Private IP addresses | `192.168.x.x`, `10.x.x.x` | `[PRIVATE_IP]` |
| Internal hostnames | `prod-db.internal`, `*.local` | `[INTERNAL_HOSTNAME]` |
| Generic secrets | `password=...`, `secret=...` | `[REDACTED_SECRET]` |

### `@mcp-strip` Annotation

You can mark any comment block to be entirely stripped from tool outputs:

```rust
// @mcp-strip
// This comment will never appear in MCP tool output
// It may contain deployment details, internal IPs, etc.
```

### Config File Sanitization

`read_config_file` uses `sanitize_config_text()` — a specialized sanitizer for key-value configuration formats. Any key containing `password`, `secret`, `token`, `key`, or `credential` has its value replaced with `[REDACTED_BY_MCP]`.

---

## Audit Security Report

Results from `audit_security_measures` run on the NexusIntelliCore codebase itself:

| Context | Critical | High |
|---|---|---|
| Production code | 16 | 83 |
| Test code | 16 | 90 |
| Fixtures | 2 | 3 |
| Detector definitions | 30 | 12 |

> **Important context:** The vast majority of findings are **intentional test patterns** embedded in:
> - `src/sanitizer.rs` — test cases for the secret detection rules themselves
> - `src/privacy_gateway.rs` — example sanitization patterns used in tests
> - `tests/privacy_adversarial.rs`, `tests/audit_corpus.rs` — adversarial test data

These are not vulnerabilities. They are the sanitization rules and their test fixtures.

---

## Defense-in-Depth Architecture

```
Layer 1: Transport Security
  ├── MCP stdio framing (no network exposure by default)
  └── Authentication via MCP_AUTH_TOKEN (S1 + S2 + S3)

Layer 2: Input Validation
  ├── File path validation — restricted to registered project roots
  ├── Parameter schema validation via tool definitions
  └── Request size limits via TransportLimits

Layer 3: Privacy Gateway (S4-adjacent)
  ├── Input sanitization before processing
  ├── Output redaction before returning to client
  └── @mcp-strip annotation support

Layer 4: Safe Parsing
  ├── Tree-sitter: memory-safe, no arbitrary code execution
  ├── No `eval()` or equivalent ever used
  └── Bounded memory allocation

Layer 5: Audit Trail
  ├── Tamper-evident hash-chained NDJSON log (S4)
  └── All tool invocations recorded with timestamps
```

---

## Threat Model

| Attack Vector | Mitigation | Status |
|---|---|---|
| Arbitrary code execution | Parse-only analysis, no `exec()` | ✅ Protected |
| Secret data leakage | Privacy Gateway pattern redaction | ✅ Protected |
| Path traversal | Bounded path validation, project root anchoring | ✅ Protected |
| Timing attack on auth | Constant-time comparison (S1) | ✅ Protected |
| Brute-force auth | Rate limiting with exponential backoff (S3) | ✅ Protected |
| Memory token leakage | Token hashed on startup, raw string discarded (S2) | ✅ Protected |
| Audit log tampering | Cryptographic hash chain (S4) | ✅ Protected |
| DoS via huge files | Configurable timeouts (`MCP_TOOL_TIMEOUT_SECS`) | ⚠️ Configurable |
| In-transit interception | No built-in TLS (use TLS proxy/ingress) | ⚠️ External |

---

## Security Configuration

```bash
# Require authentication for all MCP connections
MCP_AUTH_TOKEN="your-long-random-secret"

# Enable audit logging
MCP_AUDIT_LOG_PATH="/var/log/nexusintellicore-audit.ndjson"

# Restrict available tools to a safe subset
MCP_ALLOWED_TOOLS="get_file_outline,inspect_symbol,get_module_summary"

# Set conservative timeouts
MCP_TOOL_TIMEOUT_SECS=30
MCP_LINT_TIMEOUT_SECS=10

# Enable structured debug logging for security events
RUST_LOG=nexusintellicore=debug
```

---

## Security Best Practices for Operators

1. **Run with `MCP_AUTH_TOKEN`** in any shared or networked environment
2. **Enable audit logging** (`MCP_AUDIT_LOG_PATH`) for compliance and forensics
3. **Use `MCP_ALLOWED_TOOLS`** to enforce least-privilege tool access
4. **Restrict with `MCP_ROOT_PATH`** — only analyze directories you intend to expose
5. **Monitor the audit log** — any tampering breaks the hash chain
6. **Keep dependencies updated**: `cargo update && cargo audit`
7. **Use a TLS proxy/ingress** if exposing the server over a network

---

## Security Best Practices for Developers

1. **Never hardcode secrets** in source code — use environment variables
2. **Use `@mcp-strip`** to annotate comments with internal deployment details
3. **Run `cargo audit`** before each release to check for known CVEs
4. **Run `cargo clippy -- -D warnings`** — clippy lints include security patterns
5. **Add audit test coverage** for new file types and patterns in `tests/audit_corpus.rs`

---

## Vulnerability Reporting

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. **Email** the security details directly to the maintainers
3. Provide: description, impact assessment, proof of concept (if applicable), suggested remediation
4. Expected response: acknowledgment within 24h, patch within 30 days

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security Guidelines (ANSSI)](https://anssi-fr.github.io/rust-guide/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
