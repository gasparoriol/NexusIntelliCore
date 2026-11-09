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
pub struct Rule {
    pub meta: RuleMeta,
    /// Grammar names as returned by `LanguageGrammar::name`.
    pub languages: &'static [&'static str],
    pub query: &'static str,
}

pub struct CompiledRule {
    pub meta: &'static RuleMeta,
    pub query: Query,
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
    },
];

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
struct TaintCategory {
    key: &'static str,
    cwe: &'static str,
    owasp: &'static str,
    category: &'static str,
    severity: Severity,
    confidence: Confidence,
    description: &'static str,
    remediation: &'static str,
}

const SQL: TaintCategory = TaintCategory {
    key: "sql",
    cwe: "CWE-89",
    owasp: "A03:2021",
    category: "sql_injection",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "SQL injection: user input reaches a SQL query",
    remediation: "Use parameterized queries / prepared statements; never build SQL from input.",
};
const CMD: TaintCategory = TaintCategory {
    key: "cmd",
    cwe: "CWE-78",
    owasp: "A03:2021",
    category: "command_injection",
    severity: Severity::Critical,
    confidence: Confidence::High,
    description: "OS command injection: user input reaches a command execution",
    remediation: "Run a fixed program with an argument list (no shell) and validate arguments.",
};
const PATH: TaintCategory = TaintCategory {
    key: "path",
    cwe: "CWE-22",
    owasp: "A01:2021",
    category: "path_traversal",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Path traversal: user input reaches a file system path",
    remediation: "Canonicalize the path and verify it stays under the allowed base directory.",
};
const SSRF: TaintCategory = TaintCategory {
    key: "ssrf",
    cwe: "CWE-918",
    owasp: "A10:2021",
    category: "ssrf",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "SSRF: user input controls the URL of a server-side request",
    remediation: "Allowlist destination hosts and reject private, loopback and link-local IPs.",
};
const REDIRECT: TaintCategory = TaintCategory {
    key: "redirect",
    cwe: "CWE-601",
    owasp: "A01:2021",
    category: "open_redirect",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Open redirect: user input controls a redirect target",
    remediation: "Redirect only to relative paths or an allowlist of destinations.",
};
const SSTI: TaintCategory = TaintCategory {
    key: "ssti",
    cwe: "CWE-1336",
    owasp: "A03:2021",
    category: "ssti",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Template injection: user input is compiled as a template",
    remediation: "Load templates from trusted files and pass input only as template data.",
};
const LOG: TaintCategory = TaintCategory {
    key: "log",
    cwe: "CWE-117",
    owasp: "A09:2021",
    category: "log_injection",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Log injection: user input is written to a log without neutralizing CR/LF",
    remediation: "Strip or encode CR/LF before logging, or use a structured logger.",
};

const fn taint(id: &'static str, c: TaintCategory) -> TaintRule {
    TaintRule {
        key: c.key,
        meta: RuleMeta {
            id,
            legacy_id: None,
            cwe: c.cwe,
            owasp: Some(c.owasp),
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
