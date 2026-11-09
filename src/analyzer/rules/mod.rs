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
use std::sync::LazyLock;
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

// ── Non-query rules (taint and text tiers) ──────────────────────────────────

pub static JAVA_PATH_TRAVERSAL: RuleMeta = RuleMeta {
    id: "java-path-traversal-taint",
    legacy_id: None,
    cwe: "CWE-22",
    owasp: Some("A01:2021"),
    category: "path_traversal",
    tier: Tier::Taint,
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Path traversal: tainted user input reaches a file sink",
    remediation: "Canonicalize the path and verify it stays under the allowed base directory.",
};

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

static COMPILED: LazyLock<HashMap<&'static str, Vec<CompiledRule>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    for grammar in LANGUAGE_REGISTRY.iter() {
        let Some(ts_lang) = grammar.tree_sitter_language() else {
            continue;
        };
        let compiled: Vec<CompiledRule> = STRUCTURAL_RULES
            .iter()
            .filter(|r| r.languages.contains(&grammar.name()))
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
            .collect();
        map.insert(grammar.name(), compiled);
    }
    map
});

/// Structural rules for a grammar, compiled once and shared across files.
#[must_use]
pub fn rules_for(lang: &str) -> &'static [CompiledRule] {
    COMPILED.get(lang).map_or(&[], Vec::as_slice)
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
        let all = STRUCTURAL_RULES.iter().map(|r| &r.meta).chain([
            &JAVA_PATH_TRAVERSAL,
            &HARDCODED_SECRET,
            &SQL_INJECTION_HEURISTIC,
        ]);
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
