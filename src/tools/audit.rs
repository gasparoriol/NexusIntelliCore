use anyhow::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt::Write as _;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};
use crate::sanitizer;

// ── Structured finding model ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Severity {
    Critical,
    High,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Confidence {
    High,
    Medium,
}

/// Distinguishes where a finding originates so production risk is never mixed
/// with test evidence or the detector definitions themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditContext {
    Production,
    Test,
    Fixture,
    DetectorDefinition,
}

/// Enriched finding produced by the tool layer from a raw AST/heuristic hit.
/// Fingerprint is derived from metadata only — secret values are never stored.
#[derive(Debug, Clone, Serialize)]
struct RichFinding {
    rule_id: &'static str,
    category: &'static str,
    severity: Severity,
    confidence: Confidence,
    context: AuditContext,
    file: String,
    line: usize,
    description: String,
    /// Stable, secret-free identity: `rule_id:rel_path:line`.
    fingerprint: String,
}

impl RichFinding {
    fn new(
        rule_id: &'static str,
        category: &'static str,
        severity: Severity,
        confidence: Confidence,
        file: &str,
        line: usize,
        description: String,
    ) -> Self {
        let context = classify_context(file);
        let fingerprint = format!("{rule_id}:{file}:{line}");
        Self {
            rule_id,
            category,
            severity,
            confidence,
            context,
            file: file.to_owned(),
            line,
            description,
            fingerprint,
        }
    }
}

// ── Classification helpers ───────────────────────────────────────────────────

fn classify_context(rel_path: &str) -> AuditContext {
    let p = rel_path.replace('\\', "/");
    let p = p.as_str();
    if p.contains("tests/fixtures/") {
        return AuditContext::Fixture;
    }
    // Files that define or test the detectors themselves are not production risk.
    if p.ends_with("audit_queries.rs")
        || p.ends_with("src/analyzer/audit.rs")
        || p.ends_with("sanitizer.rs")
        || p.ends_with("privacy_gateway.rs")
        || p.ends_with(".md")
    {
        return AuditContext::DetectorDefinition;
    }
    if p.starts_with("tests/")
        || p.contains("/tests/")
        || p.contains("_test.")
        || p.contains("/test_")
        // Inline test modules inside src/ (e.g. src/analyzer/tests.rs, src/transport.rs' inline #[cfg(test)])
        || p.ends_with("/tests.rs")
    {
        return AuditContext::Test;
    }
    AuditContext::Production
}

/// Remove exact duplicates; two findings are the same when their fingerprint matches.
fn dedup(mut findings: Vec<RichFinding>) -> (Vec<RichFinding>, usize) {
    let before = findings.len();
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint.clone()));
    let removed = before - findings.len();
    (findings, removed)
}

// ── Rendering ────────────────────────────────────────────────────────────────

fn severity_icon(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴 Critical",
        Severity::High => "🟠 High",
        Severity::Medium => "🟡 Medium",
    }
}

fn render_context_group(out: &mut String, title: &str, findings: &[&RichFinding]) {
    let _ = write!(out, "## {title}\n\n");
    if findings.is_empty() {
        out.push_str("  ✓ No findings in this context.\n\n");
        return;
    }
    for sev in &[Severity::Critical, Severity::High, Severity::Medium] {
        let group: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == *sev)
            .copied()
            .collect();
        if group.is_empty() {
            continue;
        }
        let _ = write!(out, "### {}\n\n", severity_icon(*sev));
        for f in &group {
            let conf_tag = match f.confidence {
                Confidence::High => "",
                Confidence::Medium => " *(heuristic)*",
            };
            let _ = writeln!(
                out,
                "  ⚠ `{}` — {} in `{}` at line {}{}",
                f.rule_id, f.description, f.file, f.line, conf_tag
            );
        }
        out.push('\n');
    }
}

fn render_summary_table(out: &mut String, findings: &[RichFinding]) {
    let count = |ctx: AuditContext, sev: Severity| {
        findings
            .iter()
            .filter(|f| f.context == ctx && f.severity == sev)
            .count()
    };
    out.push_str("| Context              | Critical | High | Medium |\n");
    out.push_str("|----------------------|----------|------|--------|\n");
    for (label, ctx) in &[
        ("production", AuditContext::Production),
        ("test", AuditContext::Test),
        ("fixture", AuditContext::Fixture),
        ("detector_definition", AuditContext::DetectorDefinition),
    ] {
        let _ = writeln!(
            out,
            "| {label:<20} | {:>8} | {:>4} | {:>6} |",
            count(*ctx, Severity::Critical),
            count(*ctx, Severity::High),
            count(*ctx, Severity::Medium),
        );
    }
    out.push('\n');
}

fn render_json_summary(
    findings: &[RichFinding],
    files_scanned: usize,
    restricted: usize,
    dupes_removed: usize,
) -> String {
    let counts = |ctx: AuditContext| {
        json!({
            "critical": findings.iter().filter(|f| f.context == ctx && f.severity == Severity::Critical).count(),
            "high":     findings.iter().filter(|f| f.context == ctx && f.severity == Severity::High).count(),
            "medium":   findings.iter().filter(|f| f.context == ctx && f.severity == Severity::Medium).count(),
        })
    };
    // Production-risk slice for CI consumption — no secret values.
    let prod_risk: Vec<Value> = findings
        .iter()
        .filter(|f| f.context == AuditContext::Production)
        .map(|f| {
            json!({
                "rule_id":     f.rule_id,
                "category":    f.category,
                "severity":    f.severity,
                "confidence":  f.confidence,
                "file":        f.file,
                "line":        f.line,
                "description": f.description,
                "fingerprint": f.fingerprint,
            })
        })
        .collect();
    let summary = json!({
        "schema_version": "1",
        "files_scanned": files_scanned,
        "restricted_files": restricted,
        "findings_before_dedup": findings.len() + dupes_removed,
        "duplicates_removed": dupes_removed,
        "findings_total": findings.len(),
        "by_context": {
            "production":          counts(AuditContext::Production),
            "test":                counts(AuditContext::Test),
            "fixture":             counts(AuditContext::Fixture),
            "detector_definition": counts(AuditContext::DetectorDefinition),
        },
        "production_risk": prod_risk,
    });
    serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_owned())
}

// ── Tool entry point ─────────────────────────────────────────────────────────

pub(super) async fn audit_security_measures(state: &crate::state::ServerState) -> Result<Value> {
    let index = state.index().await?;
    let allowed_files = index.allowed_files.clone();
    let restricted_len = index.restricted_files.len();
    drop(index);

    let mut findings: Vec<RichFinding> = Vec::new();

    for file in &allowed_files {
        let Ok(path) = state.validate_path(file) else {
            continue;
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        let path_clone = path.clone();
        let Ok(source) =
            tokio::task::spawn_blocking(move || std::fs::read_to_string(&path_clone)).await?
        else {
            continue;
        };

        // Secret detection — location and type only, never the value.
        for (secret_type, line) in sanitizer::detect_all_secrets(&source) {
            findings.push(RichFinding::new(
                "secret-detection",
                "hardcoded_secret",
                Severity::Critical,
                Confidence::Medium,
                &rel,
                line,
                format!("[{secret_type}] detected — value NOT recorded"),
            ));
        }

        // AST-based detection (tree-sitter; precise, no string-literal FPs).
        let Some(grammar) = analyzer::detect_grammar(&path) else {
            continue;
        };
        for f in analyzer::audit_file_ast(&source, grammar) {
            let (rule_id, category, severity) = match f.kind {
                analyzer::AuditFindingKind::UnsafeCode => {
                    ("rust-unsafe", "unsafe_code", Severity::High)
                }
                analyzer::AuditFindingKind::DynamicExecution => {
                    ("dynamic-execution", "dynamic_execution", Severity::High)
                }
                analyzer::AuditFindingKind::InsecureAssignment => {
                    ("insecure-assignment", "insecure_assignment", Severity::High)
                }
            };
            findings.push(RichFinding::new(
                rule_id,
                category,
                severity,
                Confidence::High,
                &rel,
                f.line,
                f.description,
            ));
        }

        // SQL-injection heuristic (text-based; AST queries not yet supported for interpolation).
        for (lineno, line) in source.lines().enumerate() {
            let lineno = lineno + 1;
            let lower = line.to_lowercase();
            if (lower.contains("select ") || lower.contains("insert ") || lower.contains("delete "))
                && (line.contains('+') || line.contains("format!") || line.contains("concat"))
            {
                findings.push(RichFinding::new(
                    "sql-injection-heuristic",
                    "sql_injection",
                    Severity::High,
                    Confidence::Medium,
                    &rel,
                    lineno,
                    "Potential SQL injection via string concatenation".to_owned(),
                ));
            }
        }
    }

    let (findings, dupes_removed) = dedup(findings);

    // ── Render Markdown ─────────────────────────────────────────────────────
    let mut out = String::from("# Security Audit Report\n\n");
    let _ = write!(
        out,
        "Files scanned: {}  Restricted: {}  \
         Findings: {} ({} after deduplication, {} duplicates removed)\n\n",
        allowed_files.len(),
        restricted_len,
        findings.len() + dupes_removed,
        findings.len(),
        dupes_removed,
    );
    out.push_str("  NOTE: Secret values are NEVER included. Only type and location are shown.\n\n");

    out.push_str("## Summary\n\n");
    render_summary_table(&mut out, &findings);

    let prod: Vec<&RichFinding> = findings
        .iter()
        .filter(|f| f.context == AuditContext::Production)
        .collect();
    render_context_group(&mut out, "Production Risk", &prod);

    let tests: Vec<&RichFinding> = findings
        .iter()
        .filter(|f| f.context == AuditContext::Test)
        .collect();
    render_context_group(&mut out, "Test Evidence (informative)", &tests);

    let annexes: Vec<&RichFinding> = findings
        .iter()
        .filter(|f| {
            f.context == AuditContext::Fixture || f.context == AuditContext::DetectorDefinition
        })
        .collect();
    render_context_group(
        &mut out,
        "Fixtures & Detector Definitions (informative)",
        &annexes,
    );

    // Inline JSON summary for CI — deterministic, versioned, secret-free.
    out.push_str("## JSON Summary\n\n```json\n");
    out.push_str(&render_json_summary(
        &findings,
        allowed_files.len(),
        restricted_len,
        dupes_removed,
    ));
    out.push_str("\n```\n");

    // Final privacy-gateway pass as an extra safety net.
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized, _) = privacy_gateway::sanitize_security_report(&out, &policy);
    let output = format!(
        "[Think like a security auditor: reason about risk, trust boundaries, and attack surface.]\n{sanitized}"
    );

    Ok(tool_response(vec![text_content(output)]))
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_context_production() {
        assert_eq!(
            classify_context("src/tools/mod.rs"),
            AuditContext::Production
        );
        assert_eq!(classify_context("src/main.rs"), AuditContext::Production);
    }

    #[test]
    fn classify_context_test_paths() {
        assert_eq!(classify_context("tests/integration.rs"), AuditContext::Test);
        assert_eq!(
            classify_context("tests/security_integration.rs"),
            AuditContext::Test
        );
    }

    #[test]
    fn classify_context_fixture() {
        assert_eq!(
            classify_context("tests/fixtures/audit_sample.rs"),
            AuditContext::Fixture
        );
        assert_eq!(
            classify_context("tests/fixtures/privacy_sample.py"),
            AuditContext::Fixture
        );
    }

    #[test]
    fn classify_context_detector_definition() {
        assert_eq!(
            classify_context("src/audit_queries.rs"),
            AuditContext::DetectorDefinition
        );
        assert_eq!(
            classify_context("src/sanitizer.rs"),
            AuditContext::DetectorDefinition
        );
        assert_eq!(
            classify_context("docs/SECURITY.md"),
            AuditContext::DetectorDefinition
        );
    }

    #[test]
    fn dedup_removes_exact_fingerprint_duplicates() {
        let f = |line: usize| {
            RichFinding::new(
                "rust-unsafe",
                "unsafe_code",
                Severity::High,
                Confidence::High,
                "src/foo.rs",
                line,
                "unsafe block".to_owned(),
            )
        };
        let findings = vec![f(10), f(10), f(20)];
        let (deduped, removed) = dedup(findings);
        assert_eq!(deduped.len(), 2, "duplicate at line 10 should be removed");
        assert_eq!(removed, 1);
    }

    #[test]
    fn dedup_keeps_different_lines() {
        let f = |line: usize| {
            RichFinding::new(
                "rust-unsafe",
                "unsafe_code",
                Severity::High,
                Confidence::High,
                "src/foo.rs",
                line,
                "unsafe block".to_owned(),
            )
        };
        let findings = vec![f(10), f(20), f(30)];
        let (deduped, removed) = dedup(findings);
        assert_eq!(deduped.len(), 3);
        assert_eq!(removed, 0);
    }

    #[test]
    fn fingerprint_never_contains_description_content() {
        let f = RichFinding::new(
            "secret-detection",
            "hardcoded_secret",
            Severity::Critical,
            Confidence::Medium,
            "src/config.rs",
            42,
            "[OPENAI_KEY] detected — value NOT recorded".to_owned(),
        );
        // Fingerprint must not contain the word "OPENAI" or any hint of a value.
        assert!(
            !f.fingerprint.contains("OPENAI"),
            "fingerprint must not echo description: {}",
            f.fingerprint
        );
        assert_eq!(f.fingerprint, "secret-detection:src/config.rs:42");
    }

    #[test]
    fn render_json_summary_is_valid_json_and_has_schema_version() {
        let findings = vec![RichFinding::new(
            "rust-unsafe",
            "unsafe_code",
            Severity::High,
            Confidence::High,
            "src/lib.rs",
            5,
            "unsafe block".to_owned(),
        )];
        let json_str = render_json_summary(&findings, 10, 0, 0);
        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("JSON summary must be valid JSON");
        assert_eq!(v["schema_version"], "1");
        assert!(v["by_context"]["production"]["high"].as_u64().unwrap_or(0) >= 1);
    }

    #[test]
    fn render_context_group_shows_check_mark_when_empty() {
        let mut out = String::new();
        render_context_group(&mut out, "Production Risk", &[]);
        assert!(out.contains('✓'), "empty group must show a check mark");
    }
}
