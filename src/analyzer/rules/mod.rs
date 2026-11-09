//! Declarative SAST rule registry (SAST v2, Fase 0).
//!
//! A rule is data: metadata plus, for structural rules, a tree-sitter query
//! stored as a `.scm` file next to this module. Adding a structural rule means
//! adding a `.scm` file and one entry in [`STRUCTURAL_RULES`]; the audit engine
//! does not change. Queries are compiled once per language on first use and
//! shared by every audited file.
//!
//! Rule ids follow `<lang|any>-<cwe-slug>-<variant>`. `legacy_id` keeps the id
//! emitted by `schema_version` 1 of the audit JSON so existing consumers can
//! migrate.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use tree_sitter::Query;

use super::lang::LANGUAGE_REGISTRY;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
}

impl Severity {
    /// Raise one level when `cond` holds (e.g. the sink writes or executes).
    #[must_use]
    pub fn escalate_if(self, cond: bool) -> Self {
        match (cond, self) {
            (false, s) => s,
            (true, Self::Medium) => Self::High,
            (true, Self::High | Self::Critical) => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
}

/// Analysis tier that produces the finding (see SAST v2 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// N1 — dangerous API or configuration visible in a single AST node.
    Structural,
    /// N2 — source → sink data flow.
    Taint,
    /// N3 — secrets, configuration and text heuristics.
    Text,
    /// N4 — constructs that enable vulnerabilities without a proven flow.
    Pattern,
}

#[derive(Debug)]
pub struct RuleMeta {
    pub id: &'static str,
    /// Id used by audit JSON `schema_version` 1, when it differs from `id`.
    pub legacy_id: Option<&'static str>,
    pub cwe: &'static str,
    pub owasp: Option<&'static str>,
    pub category: &'static str,
    pub tier: Tier,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Finding text; must never contain user source content.
    pub description: &'static str,
    /// One-line remediation; must never contain user source content.
    pub remediation: &'static str,
}

impl RuleMeta {
    /// True when `id` names this rule by its current or legacy id.
    #[must_use]
    pub fn matches_id(&self, id: &str) -> bool {
        self.id == id || self.legacy_id == Some(id)
    }
}

/// A structural (N1/N4) rule: metadata + query applied to the listed grammars.
///
/// The reported line is the earliest capture whose name does not start with
/// `_` (helper captures only feed predicates).
pub struct Rule {
    pub meta: RuleMeta,
    /// Grammar names as returned by `LanguageGrammar::name`.
    pub languages: &'static [&'static str],
    pub query: &'static str,
    /// Report only when the name of an enclosing declaration (variable, key,
    /// assignment target or function) contains one of these lowercase words.
    /// Empty: always report.
    pub context: &'static [&'static str],
    /// Skip when the enclosing function (or the file, at top level) contains
    /// one of these markers, e.g. a hardening call next to a parser factory.
    pub unless_scope: &'static [&'static str],
}

impl Rule {
    const fn with_context(mut self, words: &'static [&'static str]) -> Self {
        self.context = words;
        self
    }

    const fn unless_scope(mut self, markers: &'static [&'static str]) -> Self {
        self.unless_scope = markers;
        self
    }
}

pub struct CompiledRule {
    pub meta: &'static RuleMeta,
    pub query: Query,
    pub context: &'static [&'static str],
    pub unless_scope: &'static [&'static str],
}

const JS_LANGS: &[&str] = &["javascript", "typescript", "tsx"];

pub static STRUCTURAL_RULES: &[Rule] = &[
    // ── Rust ────────────────────────────────────────────────────────────────
    Rule {
        meta: RuleMeta {
            id: "rust-unsafe-code-block",
            legacy_id: Some("rust-unsafe"),
            cwe: "CWE-676",
            owasp: None,
            category: "unsafe_code",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "unsafe block",
            remediation:
                "Remove the unsafe block or document and test its safety invariants (// SAFETY:).",
        },
        languages: &["rust"],
        query: include_str!("rust/unsafe_block.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "rust-unsafe-code-fn",
            legacy_id: Some("rust-unsafe"),
            cwe: "CWE-676",
            owasp: None,
            category: "unsafe_code",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "unsafe fn declaration",
            remediation:
                "Expose a safe API or document the caller obligations in a # Safety section.",
        },
        languages: &["rust"],
        query: include_str!("rust/unsafe_fn.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "rust-unsafe-code-asm",
            legacy_id: Some("rust-unsafe"),
            cwe: "CWE-676",
            owasp: None,
            category: "unsafe_code",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "inline asm! invocation",
            remediation: "Prefer intrinsics or a vetted crate over inline assembly.",
        },
        languages: &["rust"],
        query: include_str!("rust/inline_asm.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "rust-uncaught-panic-unwrap",
            legacy_id: Some("rust-unsafe"),
            cwe: "CWE-248",
            owasp: None,
            category: "panic_risk",
            tier: Tier::Pattern,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            description: "unwrap()/expect() call may panic",
            remediation: "Propagate the error with `?` or handle the None/Err case explicitly.",
        },
        languages: &["rust"],
        query: include_str!("rust/panic_unwrap.scm"),
        context: &[],
        unless_scope: &[],
    },
    // ── JavaScript / TypeScript ─────────────────────────────────────────────
    Rule {
        meta: RuleMeta {
            id: "js-code-injection-eval",
            legacy_id: Some("dynamic-execution"),
            cwe: "CWE-95",
            owasp: Some("A03:2021"),
            category: "code_injection",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "eval() call",
            remediation: "Replace eval() with JSON.parse or an explicit dispatch table.",
        },
        languages: JS_LANGS,
        query: include_str!("js/eval.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "js-code-injection-new-function",
            legacy_id: Some("dynamic-execution"),
            cwe: "CWE-94",
            owasp: Some("A03:2021"),
            category: "code_injection",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "new Function() call",
            remediation: "Avoid building functions from strings; use static functions or closures.",
        },
        languages: JS_LANGS,
        query: include_str!("js/new_function.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "js-xss-inner-html",
            legacy_id: Some("insecure-assignment"),
            cwe: "CWE-79",
            owasp: Some("A03:2021"),
            category: "xss",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "innerHTML assignment",
            remediation: "Use textContent or sanitize the HTML (e.g. DOMPurify) before assigning.",
        },
        languages: JS_LANGS,
        query: include_str!("js/inner_html.scm"),
        context: &[],
        unless_scope: &[],
    },
    // ── Python ──────────────────────────────────────────────────────────────
    Rule {
        meta: RuleMeta {
            id: "py-code-injection-eval",
            legacy_id: Some("dynamic-execution"),
            cwe: "CWE-95",
            owasp: Some("A03:2021"),
            category: "code_injection",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "eval/exec call",
            remediation: "Use ast.literal_eval for literals or an explicit dispatch table.",
        },
        languages: &["python"],
        query: include_str!("python/eval_exec.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "py-command-injection-shell-true",
            legacy_id: Some("dynamic-execution"),
            cwe: "CWE-78",
            owasp: Some("A03:2021"),
            category: "command_injection",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "subprocess shell=True call",
            remediation: "Pass an argument list with shell=False.",
        },
        languages: &["python"],
        query: include_str!("python/subprocess_shell_true.scm"),
        context: &[],
        unless_scope: &[],
    },
    // ── Java / Kotlin ───────────────────────────────────────────────────────
    Rule {
        meta: RuleMeta {
            id: "java-command-injection-exec",
            legacy_id: Some("dynamic-execution"),
            cwe: "CWE-78",
            owasp: Some("A03:2021"),
            category: "command_injection",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "Runtime.exec() or ProcessBuilder call",
            remediation: "Use ProcessBuilder with a fixed command and validated argument list.",
        },
        languages: &["java"],
        query: include_str!("java/exec.scm"),
        context: &[],
        unless_scope: &[],
    },
    Rule {
        meta: RuleMeta {
            id: "kotlin-code-injection-eval",
            legacy_id: Some("dynamic-execution"),
            cwe: "CWE-95",
            owasp: Some("A03:2021"),
            category: "code_injection",
            tier: Tier::Structural,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "dynamic execution call",
            remediation: "Avoid evaluating dynamic code; use a fixed set of operations.",
        },
        languages: &["kotlin"],
        query: include_str!("kotlin/eval.scm"),
        context: &[],
        unless_scope: &[],
    },
    // ── Fase 1: cryptography, TLS, PRNG, deserialization, configuration, C ──
    structural(
        "java-weak-crypto-hash",
        WEAK_HASH,
        &["java"],
        include_str!("java/weak_hash.scm"),
    ),
    structural(
        "java-weak-crypto-cipher",
        WEAK_CIPHER,
        &["java"],
        include_str!("java/weak_cipher.scm"),
    ),
    structural(
        "java-tls-validation-disabled",
        TLS_OFF,
        &["java"],
        include_str!("java/tls_disabled.scm"),
    ),
    structural(
        "java-insecure-random-context",
        WEAK_RANDOM,
        &["java"],
        include_str!("java/insecure_random.scm"),
    )
    .with_context(SECURITY_NAMES),
    structural(
        "java-insecure-deserialization",
        DESERIALIZATION,
        &["java"],
        include_str!("java/deserialization.scm"),
    ),
    structural(
        "java-csrf-protection-disabled",
        CSRF_OFF,
        &["java"],
        include_str!("java/csrf_disabled.scm"),
    ),
    structural(
        "java-cors-wildcard-credentials",
        CORS_CREDENTIALS,
        &["java"],
        include_str!("java/cors_credentials.scm"),
    ),
    structural(
        "java-insecure-cookie-flag",
        COOKIE_FLAGS,
        &["java"],
        include_str!("java/cookie_flags.scm"),
    ),
    structural(
        "java-xxe-unhardened-parser",
        XXE_DEFAULT,
        &["java"],
        include_str!("java/xxe.scm"),
    )
    .unless_scope(XXE_HARDENING),
    structural(
        "kotlin-weak-crypto-hash",
        WEAK_HASH,
        &["kotlin"],
        include_str!("kotlin/weak_hash.scm"),
    ),
    structural(
        "kotlin-weak-crypto-cipher",
        WEAK_CIPHER,
        &["kotlin"],
        include_str!("kotlin/weak_cipher.scm"),
    ),
    structural(
        "kotlin-insecure-deserialization",
        DESERIALIZATION,
        &["kotlin"],
        include_str!("kotlin/deserialization.scm"),
    ),
    structural(
        "py-weak-crypto-hash",
        WEAK_HASH,
        &["python"],
        include_str!("python/weak_hash.scm"),
    ),
    structural(
        "py-weak-crypto-cipher",
        WEAK_CIPHER,
        &["python"],
        include_str!("python/weak_cipher.scm"),
    ),
    structural(
        "py-tls-validation-disabled",
        TLS_OFF,
        &["python"],
        include_str!("python/tls_disabled.scm"),
    ),
    structural(
        "py-insecure-random-context",
        WEAK_RANDOM,
        &["python"],
        include_str!("python/insecure_random.scm"),
    )
    .with_context(SECURITY_NAMES),
    structural(
        "py-insecure-deserialization",
        DESERIALIZATION,
        &["python"],
        include_str!("python/deserialization.scm"),
    ),
    structural(
        "py-csrf-protection-disabled",
        CSRF_OFF,
        &["python"],
        include_str!("python/csrf_disabled.scm"),
    ),
    structural(
        "py-cors-wildcard-credentials",
        CORS_CREDENTIALS,
        &["python"],
        include_str!("python/cors_credentials.scm"),
    ),
    structural(
        "py-debug-mode-enabled",
        DEBUG_ON,
        &["python"],
        include_str!("python/debug_mode.scm"),
    ),
    structural(
        "py-insecure-cookie-flag",
        COOKIE_FLAGS,
        &["python"],
        include_str!("python/cookie_flags.scm"),
    ),
    structural(
        "py-xxe-entity-resolution",
        XXE_EXPLICIT,
        &["python"],
        include_str!("python/xxe.scm"),
    ),
    structural(
        "js-weak-crypto-hash",
        WEAK_HASH,
        JS_LANGS,
        include_str!("js/weak_hash.scm"),
    ),
    structural(
        "js-weak-crypto-cipher",
        WEAK_CIPHER,
        JS_LANGS,
        include_str!("js/weak_cipher.scm"),
    ),
    structural(
        "js-tls-validation-disabled",
        TLS_OFF,
        JS_LANGS,
        include_str!("js/tls_disabled.scm"),
    ),
    structural(
        "js-insecure-random-context",
        WEAK_RANDOM,
        JS_LANGS,
        include_str!("js/insecure_random.scm"),
    )
    .with_context(SECURITY_NAMES),
    structural(
        "js-insecure-deserialization",
        DESERIALIZATION,
        JS_LANGS,
        include_str!("js/deserialization.scm"),
    ),
    structural(
        "js-cors-wildcard-credentials",
        CORS_CREDENTIALS,
        JS_LANGS,
        include_str!("js/cors_credentials.scm"),
    ),
    structural(
        "js-insecure-cookie-flag",
        COOKIE_FLAGS,
        JS_LANGS,
        include_str!("js/cookie_flags.scm"),
    ),
    structural(
        "go-weak-crypto-hash",
        WEAK_HASH,
        &["go"],
        include_str!("go/weak_hash.scm"),
    ),
    structural(
        "go-weak-crypto-cipher",
        WEAK_CIPHER,
        &["go"],
        include_str!("go/weak_cipher.scm"),
    ),
    structural(
        "go-tls-validation-disabled",
        TLS_OFF,
        &["go"],
        include_str!("go/tls_disabled.scm"),
    ),
    structural(
        "go-insecure-random-context",
        WEAK_RANDOM,
        &["go"],
        include_str!("go/insecure_random.scm"),
    )
    .with_context(SECURITY_NAMES),
    structural(
        "go-cors-wildcard-credentials",
        CORS_CREDENTIALS,
        &["go"],
        include_str!("go/cors_credentials.scm"),
    ),
    structural(
        "go-insecure-cookie-flag",
        COOKIE_FLAGS,
        &["go"],
        include_str!("go/cookie_flags.scm"),
    ),
    structural(
        "cs-weak-crypto-hash",
        WEAK_HASH,
        &["csharp"],
        include_str!("csharp/weak_hash.scm"),
    ),
    structural(
        "cs-weak-crypto-cipher",
        WEAK_CIPHER,
        &["csharp"],
        include_str!("csharp/weak_cipher.scm"),
    ),
    structural(
        "cs-tls-validation-disabled",
        TLS_OFF,
        &["csharp"],
        include_str!("csharp/tls_disabled.scm"),
    ),
    structural(
        "cs-insecure-random-context",
        WEAK_RANDOM,
        &["csharp"],
        include_str!("csharp/insecure_random.scm"),
    )
    .with_context(SECURITY_NAMES),
    structural(
        "cs-insecure-deserialization",
        DESERIALIZATION,
        &["csharp"],
        include_str!("csharp/deserialization.scm"),
    ),
    structural(
        "cs-csrf-protection-disabled",
        CSRF_OFF,
        &["csharp"],
        include_str!("csharp/csrf_disabled.scm"),
    ),
    structural(
        "cs-cors-wildcard-credentials",
        CORS_CREDENTIALS,
        &["csharp"],
        include_str!("csharp/cors_credentials.scm"),
    ),
    structural(
        "cs-debug-mode-enabled",
        DEBUG_ON,
        &["csharp"],
        include_str!("csharp/debug_mode.scm"),
    )
    .unless_scope(&["IsDevelopment"]),
    structural(
        "cs-insecure-cookie-flag",
        COOKIE_FLAGS,
        &["csharp"],
        include_str!("csharp/cookie_flags.scm"),
    ),
    structural(
        "cs-xxe-dtd-processing",
        XXE_EXPLICIT,
        &["csharp"],
        include_str!("csharp/xxe.scm"),
    ),
    structural(
        "rust-weak-crypto-hash",
        WEAK_HASH,
        &["rust"],
        include_str!("rust/weak_hash.scm"),
    ),
    structural(
        "rust-weak-crypto-cipher",
        WEAK_CIPHER,
        &["rust"],
        include_str!("rust/weak_cipher.scm"),
    ),
    structural(
        "rust-tls-validation-disabled",
        TLS_OFF,
        &["rust"],
        include_str!("rust/tls_disabled.scm"),
    ),
    structural(
        "rust-insecure-cookie-flag",
        COOKIE_FLAGS,
        &["rust"],
        include_str!("rust/cookie_flags.scm"),
    ),
    structural(
        "c-weak-crypto-hash",
        WEAK_HASH,
        &["c"],
        include_str!("c/weak_hash.scm"),
    ),
    structural(
        "c-weak-crypto-cipher",
        WEAK_CIPHER,
        &["c"],
        include_str!("c/weak_cipher.scm"),
    ),
    structural(
        "c-tls-validation-disabled",
        TLS_OFF,
        &["c"],
        include_str!("c/tls_disabled.scm"),
    ),
    structural(
        "c-insecure-random-context",
        WEAK_RANDOM,
        &["c"],
        include_str!("c/insecure_random.scm"),
    )
    .with_context(SECURITY_NAMES),
    structural(
        "c-dangerous-function-gets",
        C_GETS,
        &["c"],
        include_str!("c/gets.scm"),
    ),
    structural(
        "c-buffer-overflow-unbounded-copy",
        C_UNBOUNDED_COPY,
        &["c"],
        include_str!("c/unbounded_copy.scm"),
    ),
    structural(
        "c-buffer-overflow-scanf",
        C_SCANF,
        &["c"],
        include_str!("c/scanf_string.scm"),
    ),
    structural(
        "c-format-string-variable",
        FORMAT_STRING,
        &["c"],
        include_str!("c/format_string.scm"),
    ),
];

// ── Structural categories (Fase 1) ──────────────────────────────────────────

const WEAK_HASH: Category = Category {
    key: "",
    cwe: "CWE-328",
    owasp: Some("A02:2021"),
    category: "weak_crypto",
    severity: Severity::Medium,
    confidence: Confidence::High,
    description: "Weak hash algorithm (MD5/SHA-1)",
    remediation: "Use SHA-256 or stronger; for passwords use bcrypt, scrypt or Argon2.",
};
const WEAK_CIPHER: Category = Category {
    key: "",
    cwe: "CWE-327",
    owasp: Some("A02:2021"),
    category: "weak_crypto",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Broken cipher (DES/3DES/RC2/RC4/Blowfish) or ECB mode",
    remediation: "Use AES-GCM or ChaCha20-Poly1305 with a random nonce.",
};
const TLS_OFF: Category = Category {
    key: "",
    cwe: "CWE-295",
    owasp: Some("A07:2021"),
    category: "tls_validation",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "TLS certificate or hostname validation disabled",
    remediation: "Keep certificate validation on; trust a private CA explicitly if needed.",
};
const WEAK_RANDOM: Category = Category {
    key: "",
    cwe: "CWE-338",
    owasp: Some("A02:2021"),
    category: "weak_random",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Non-cryptographic PRNG used for a security-sensitive value",
    remediation: "Use a CSPRNG (SecureRandom, secrets, crypto.randomBytes, crypto/rand…).",
};
const DESERIALIZATION: Category = Category {
    key: "",
    cwe: "CWE-502",
    owasp: Some("A08:2021"),
    category: "insecure_deserialization",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "Deserialization that can instantiate arbitrary types",
    remediation: "Use a data-only format (JSON) with an explicit schema or a safe loader.",
};
const CSRF_OFF: Category = Category {
    key: "",
    cwe: "CWE-352",
    owasp: Some("A01:2021"),
    category: "csrf",
    severity: Severity::Medium,
    confidence: Confidence::High,
    description: "CSRF protection disabled",
    remediation: "Keep CSRF protection on for cookie-authenticated, state-changing endpoints.",
};
const CORS_CREDENTIALS: Category = Category {
    key: "",
    cwe: "CWE-942",
    owasp: Some("A05:2021"),
    category: "cors",
    severity: Severity::Medium,
    confidence: Confidence::High,
    description: "CORS allows any origin together with credentials",
    remediation: "Allowlist trusted origins when credentials are allowed.",
};
const DEBUG_ON: Category = Category {
    key: "",
    cwe: "CWE-489",
    owasp: Some("A05:2021"),
    category: "debug_mode",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Debug mode or developer error pages enabled",
    remediation: "Enable debug features only in development configuration.",
};
const COOKIE_FLAGS: Category = Category {
    key: "",
    cwe: "CWE-614",
    owasp: Some("A05:2021"),
    category: "cookie_security",
    severity: Severity::Medium,
    confidence: Confidence::High,
    description: "Cookie explicitly set without Secure or HttpOnly",
    remediation: "Set Secure, HttpOnly and SameSite on session and auth cookies.",
};
const XXE_EXPLICIT: Category = Category {
    key: "",
    cwe: "CWE-611",
    owasp: Some("A05:2021"),
    category: "xxe",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "XML parser configured to process DTDs or external entities",
    remediation: "Disable DTD processing and external entity resolution.",
};
const XXE_DEFAULT: Category = Category {
    confidence: Confidence::Medium,
    description: "XML parser factory used without disabling DTDs / external entities",
    remediation:
        "Set disallow-doctype-decl (or ACCESS_EXTERNAL_DTD/SCHEMA to \"\") on the factory.",
    ..XXE_EXPLICIT
};
const C_GETS: Category = Category {
    key: "",
    cwe: "CWE-242",
    owasp: None,
    category: "buffer_overflow",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "gets() always risks a buffer overflow",
    remediation: "Use fgets() with the buffer size.",
};
const C_UNBOUNDED_COPY: Category = Category {
    key: "",
    cwe: "CWE-120",
    owasp: None,
    category: "buffer_overflow",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "String copy/format without a destination bound",
    remediation: "Use bounded variants (snprintf, strlcpy/strncpy with explicit termination).",
};
const C_SCANF: Category = Category {
    key: "",
    cwe: "CWE-120",
    owasp: None,
    category: "buffer_overflow",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "scanf-family \"%s\" without a field width",
    remediation: "Give every %s a maximum width (e.g. %63s) or use fgets().",
};
const FORMAT_STRING: Category = Category {
    key: "",
    cwe: "CWE-134",
    owasp: None,
    category: "format_string",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "Format string is not a literal",
    remediation: "Use a literal format: printf(\"%s\", value).",
};

/// Names that make a PRNG call security-relevant (lowercase substrings).
const SECURITY_NAMES: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "salt",
    "nonce",
    "otp",
    "session",
    "csrf",
    "apikey",
    "api_key",
    "uuid",
    "guid",
    "reset",
    "verification",
    "captcha",
    "credential",
];
/// Java XML factory hardening that prevents XXE.
const XXE_HARDENING: &[&str] = &[
    "disallow-doctype-decl",
    "external-general-entities",
    "ACCESS_EXTERNAL_DTD",
    "ACCESS_EXTERNAL_SCHEMA",
    "SUPPORT_DTD",
    "IS_SUPPORTING_EXTERNAL_ENTITIES",
];

const fn structural(
    id: &'static str,
    c: Category,
    languages: &'static [&'static str],
    query: &'static str,
) -> Rule {
    Rule {
        meta: RuleMeta {
            id,
            legacy_id: None,
            cwe: c.cwe,
            owasp: c.owasp,
            category: c.category,
            tier: Tier::Structural,
            severity: c.severity,
            confidence: c.confidence,
            description: c.description,
            remediation: c.remediation,
        },
        languages,
        query,
        context: &[],
        unless_scope: &[],
    }
}

// ── Taint rules (N2) ────────────────────────────────────────────────────────

/// A taint rule: metadata plus the `key` it consumes from the language's taint
/// queries (`@sink.<key>`, `@sanitizer.<key>`, `@guard.<key>`, `@source.<key>`).
pub struct TaintRule {
    pub key: &'static str,
    pub meta: RuleMeta,
}

/// Taint queries for a family of grammars that share node names.
///
/// The queries are concatenated and compiled once per language. Capture
/// names drive the engine (see `analyzer::taint`); helper captures used only
/// by predicates must start with `_`.
pub struct TaintPack {
    pub languages: &'static [&'static str],
    pub queries: &'static [&'static str],
    pub rules: &'static [TaintRule],
}

/// Per-vulnerability metadata shared by every language implementing it.
#[derive(Clone, Copy)]
struct Category {
    /// Taint key (`@sink.<key>`…); empty for structural categories.
    key: &'static str,
    cwe: &'static str,
    owasp: Option<&'static str>,
    category: &'static str,
    severity: Severity,
    confidence: Confidence,
    description: &'static str,
    remediation: &'static str,
}

const SQL: Category = Category {
    key: "sql",
    cwe: "CWE-89",
    owasp: Some("A03:2021"),
    category: "sql_injection",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "SQL injection: user input reaches a SQL query",
    remediation: "Use parameterized queries / prepared statements; never build SQL from input.",
};
const CMD: Category = Category {
    key: "cmd",
    cwe: "CWE-78",
    owasp: Some("A03:2021"),
    category: "command_injection",
    severity: Severity::Critical,
    confidence: Confidence::High,
    description: "OS command injection: user input reaches a command execution",
    remediation: "Run a fixed program with an argument list (no shell) and validate arguments.",
};
const PATH: Category = Category {
    key: "path",
    cwe: "CWE-22",
    owasp: Some("A01:2021"),
    category: "path_traversal",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Path traversal: user input reaches a file system path",
    remediation: "Canonicalize the path and verify it stays under the allowed base directory.",
};
const SSRF: Category = Category {
    key: "ssrf",
    cwe: "CWE-918",
    owasp: Some("A10:2021"),
    category: "ssrf",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "SSRF: user input controls the URL of a server-side request",
    remediation: "Allowlist destination hosts and reject private, loopback and link-local IPs.",
};
const REDIRECT: Category = Category {
    key: "redirect",
    cwe: "CWE-601",
    owasp: Some("A01:2021"),
    category: "open_redirect",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Open redirect: user input controls a redirect target",
    remediation: "Redirect only to relative paths or an allowlist of destinations.",
};
const SSTI: Category = Category {
    key: "ssti",
    cwe: "CWE-1336",
    owasp: Some("A03:2021"),
    category: "ssti",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Template injection: user input is compiled as a template",
    remediation: "Load templates from trusted files and pass input only as template data.",
};
const LOG: Category = Category {
    key: "log",
    cwe: "CWE-117",
    owasp: Some("A09:2021"),
    category: "log_injection",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Log injection: user input is written to a log without neutralizing CR/LF",
    remediation: "Strip or encode CR/LF before logging, or use a structured logger.",
};

const fn taint(id: &'static str, c: Category) -> TaintRule {
    TaintRule {
        key: c.key,
        meta: RuleMeta {
            id,
            legacy_id: None,
            cwe: c.cwe,
            owasp: c.owasp,
            category: c.category,
            tier: Tier::Taint,
            severity: c.severity,
            confidence: c.confidence,
            description: c.description,
            remediation: c.remediation,
        },
    }
}

static JAVA_TAINT: &[TaintRule] = &[
    taint("java-sql-injection-taint", SQL),
    taint("java-command-injection-taint", CMD),
    taint("java-path-traversal-taint", PATH),
    taint("java-ssrf-taint", SSRF),
    taint("java-open-redirect-taint", REDIRECT),
    taint("java-ssti-taint", SSTI),
    taint("java-log-injection-taint", LOG),
];

static PY_TAINT: &[TaintRule] = &[
    taint("py-sql-injection-taint", SQL),
    taint("py-command-injection-taint", CMD),
    taint("py-path-traversal-taint", PATH),
    taint("py-ssrf-taint", SSRF),
    taint("py-open-redirect-taint", REDIRECT),
    taint("py-ssti-taint", SSTI),
    taint("py-log-injection-taint", LOG),
];

static JS_TAINT: &[TaintRule] = &[
    taint("js-sql-injection-taint", SQL),
    taint("js-command-injection-taint", CMD),
    taint("js-path-traversal-taint", PATH),
    taint("js-ssrf-taint", SSRF),
    taint("js-open-redirect-taint", REDIRECT),
    taint("js-ssti-taint", SSTI),
    taint("js-log-injection-taint", LOG),
];

static RUST_TAINT: &[TaintRule] = &[
    taint("rust-sql-injection-taint", SQL),
    taint("rust-command-injection-taint", CMD),
    taint("rust-ssrf-taint", SSRF),
    taint("rust-open-redirect-taint", REDIRECT),
];

const JS_TAINT_QUERIES: [&str; 4] = [
    include_str!("js/taint_syntax.scm"),
    include_str!("js/taint_sources.scm"),
    include_str!("js/taint_sinks.scm"),
    include_str!("js/taint_sanitizers.scm"),
];

pub static TAINT_PACKS: &[TaintPack] = &[
    TaintPack {
        languages: &["java"],
        queries: &[
            include_str!("java/taint_syntax.scm"),
            include_str!("java/taint_sources.scm"),
            include_str!("java/taint_sinks.scm"),
            include_str!("java/taint_sanitizers.scm"),
        ],
        rules: JAVA_TAINT,
    },
    TaintPack {
        languages: &["python"],
        queries: &[
            include_str!("python/taint_syntax.scm"),
            include_str!("python/taint_sources.scm"),
            include_str!("python/taint_sinks.scm"),
            include_str!("python/taint_sanitizers.scm"),
        ],
        rules: PY_TAINT,
    },
    TaintPack {
        languages: &["javascript"],
        queries: &JS_TAINT_QUERIES,
        rules: JS_TAINT,
    },
    TaintPack {
        // TypeScript adds NestJS parameter decorators on top of the JS pack.
        languages: &["typescript", "tsx"],
        queries: &[
            JS_TAINT_QUERIES[0],
            JS_TAINT_QUERIES[1],
            JS_TAINT_QUERIES[2],
            JS_TAINT_QUERIES[3],
            include_str!("ts/taint_sources.scm"),
        ],
        rules: JS_TAINT,
    },
    TaintPack {
        languages: &["rust"],
        queries: &[
            include_str!("rust/taint_syntax.scm"),
            include_str!("rust/taint_sources.scm"),
            include_str!("rust/taint_sinks.scm"),
            include_str!("rust/taint_sanitizers.scm"),
        ],
        rules: RUST_TAINT,
    },
];

/// Taint pack for a grammar, if any.
#[must_use]
pub fn taint_pack(lang: &str) -> Option<&'static TaintPack> {
    TAINT_PACKS.iter().find(|p| p.languages.contains(&lang))
}

/// True when the grammar has a taint rule for `category` (e.g. `sql_injection`).
#[must_use]
pub fn taint_covers(lang: &str, category: &str) -> bool {
    taint_pack(lang).is_some_and(|p| p.rules.iter().any(|r| r.meta.category == category))
}

// ── Text-tier rules (N3) ────────────────────────────────────────────────────

pub static HARDCODED_SECRET: RuleMeta = RuleMeta {
    id: "any-hardcoded-secret",
    legacy_id: Some("secret-detection"),
    cwe: "CWE-798",
    owasp: Some("A07:2021"),
    category: "hardcoded_secret",
    tier: Tier::Text,
    severity: Severity::Critical,
    confidence: Confidence::Medium,
    description: "Hardcoded secret",
    remediation: "Move the secret to a secret manager or environment variable and rotate it.",
};

pub static SQL_INJECTION_HEURISTIC: RuleMeta = RuleMeta {
    id: "any-sql-injection-heuristic",
    legacy_id: Some("sql-injection-heuristic"),
    cwe: "CWE-89",
    owasp: Some("A03:2021"),
    category: "sql_injection",
    tier: Tier::Text,
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "Potential SQL injection via string concatenation",
    remediation: "Use parameterized queries / prepared statements.",
};

/// One slot per grammar; its rules are compiled on first use so a project
/// only pays for the languages it contains.
static COMPILED: LazyLock<HashMap<&'static str, OnceLock<Vec<CompiledRule>>>> =
    LazyLock::new(|| {
        LANGUAGE_REGISTRY
            .iter()
            .map(|g| (g.name(), OnceLock::new()))
            .collect()
    });

fn compile_rules(lang: &str) -> Vec<CompiledRule> {
    let Some(ts_lang) = LANGUAGE_REGISTRY
        .iter()
        .find(|g| g.name() == lang)
        .and_then(|g| g.tree_sitter_language())
    else {
        return Vec::new();
    };
    STRUCTURAL_RULES
        .iter()
        .filter(|r| r.languages.contains(&lang))
        .filter_map(|r| match Query::new(&ts_lang, r.query) {
            Ok(query) => Some(CompiledRule {
                meta: &r.meta,
                query,
                context: r.context,
                unless_scope: r.unless_scope,
            }),
            Err(e) => {
                tracing::warn!(rule = r.meta.id, error = %e, "invalid audit rule query; skipped");
                None
            }
        })
        .collect()
}

/// Structural rules for a grammar, compiled once and shared across files.
#[must_use]
pub fn rules_for(lang: &str) -> &'static [CompiledRule] {
    COMPILED.get(lang).map_or(&[], |slot| {
        slot.get_or_init(|| compile_rules(lang)).as_slice()
    })
}

#[cfg(test)]
mod corpus;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_rule_query_compiles_for_each_declared_language() {
        for rule in STRUCTURAL_RULES {
            assert!(
                !rule.languages.is_empty(),
                "{} has no languages",
                rule.meta.id
            );
            for lang_name in rule.languages {
                let ts_lang = LANGUAGE_REGISTRY
                    .iter()
                    .find(|g| g.name() == *lang_name)
                    .and_then(|g| g.tree_sitter_language());
                assert!(
                    ts_lang.is_some(),
                    "{}: unknown language or no tree-sitter grammar: {lang_name}",
                    rule.meta.id
                );
                if let Some(ts_lang) = ts_lang {
                    let result = Query::new(&ts_lang, rule.query);
                    assert!(
                        result.is_ok(),
                        "{} ({lang_name}): invalid query: {:?}",
                        rule.meta.id,
                        result.err()
                    );
                }
            }
        }
    }

    #[test]
    fn compiled_registry_contains_every_rule() {
        for rule in STRUCTURAL_RULES {
            for lang_name in rule.languages {
                assert!(
                    rules_for(lang_name)
                        .iter()
                        .any(|c| c.meta.id == rule.meta.id),
                    "{} missing from compiled set of {lang_name}",
                    rule.meta.id
                );
            }
        }
    }

    #[test]
    fn rule_ids_are_unique_and_well_formed() {
        let taint = [JAVA_TAINT, PY_TAINT, JS_TAINT, RUST_TAINT]
            .into_iter()
            .flatten()
            .map(|r| &r.meta);
        let all = STRUCTURAL_RULES
            .iter()
            .map(|r| &r.meta)
            .chain(taint)
            .chain([&HARDCODED_SECRET, &SQL_INJECTION_HEURISTIC]);
        let mut seen = HashSet::new();
        for meta in all {
            assert!(seen.insert(meta.id), "duplicate rule id {}", meta.id);
            assert!(
                meta.id.split('-').count() >= 3
                    && meta
                        .id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "rule id {} must follow <lang|any>-<cwe-slug>-<variant>",
                meta.id
            );
            assert!(
                meta.cwe.starts_with("CWE-"),
                "{}: bad CWE {}",
                meta.id,
                meta.cwe
            );
            assert!(
                !meta.remediation.is_empty(),
                "{}: empty remediation",
                meta.id
            );
        }
    }

    #[test]
    fn severity_escalation() {
        assert_eq!(Severity::High.escalate_if(true), Severity::Critical);
        assert_eq!(Severity::Medium.escalate_if(true), Severity::High);
        assert_eq!(Severity::Critical.escalate_if(true), Severity::Critical);
        assert_eq!(Severity::High.escalate_if(false), Severity::High);
    }
}
