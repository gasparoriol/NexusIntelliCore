use anyhow::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use tokio::task::JoinSet;

use crate::analyzer;
use crate::analyzer::rules::{self, Confidence, RuleMeta, Severity};
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};
use crate::sanitizer;

// ── Structured finding model ────────────────────────────────────────────────

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
/// Rule id, CWE, category and confidence come from the rule registry.
/// Fingerprint is derived from metadata only — secret values are never stored.
#[derive(Debug, Clone)]
struct RichFinding {
    rule: &'static RuleMeta,
    /// Rule base severity, possibly escalated for this occurrence.
    severity: Severity,
    context: AuditContext,
    file: String,
    line: usize,
    description: String,
    /// Stable, secret-free identity: `rule_id:rel_path:line`.
    fingerprint: String,
}

impl RichFinding {
    fn new(
        rule: &'static RuleMeta,
        severity: Severity,
        file: &str,
        line: usize,
        description: String,
    ) -> Self {
        let context = classify_context(file);
        let fingerprint = format!("{}:{file}:{line}", rule.id);
        Self {
            rule,
            severity,
            context,
            file: file.to_owned(),
            line,
            description,
            fingerprint,
        }
    }
}

/// Finding silenced by a `nexus-ignore` directive; still listed in the report.
#[derive(Debug, Clone)]
struct SuppressedFinding {
    finding: RichFinding,
    reason: String,
}

// ── Suppressions ─────────────────────────────────────────────────────────────

const SUPPRESS_MARKER: &str = "nexus-ignore:";
const MAX_SUPPRESS_REASON_CHARS: usize = 120;

/// Reason of a `nexus-ignore: <rule-id> <reason>` directive on the finding's
/// line or the line above. The rule id may be the current or the legacy one;
/// a directive without a reason does not suppress anything.
fn suppression_reason(lines: &[&str], line: usize, rule: &RuleMeta) -> Option<String> {
    [line, line.saturating_sub(1)]
        .into_iter()
        .filter(|&l| l >= 1)
        .find_map(|l| {
            let text = lines.get(l - 1)?;
            let rest = &text[text.find(SUPPRESS_MARKER)? + SUPPRESS_MARKER.len()..];
            let (id, reason) = rest.trim_start().split_once(char::is_whitespace)?;
            let reason = reason.trim().trim_end_matches("*/").trim_end();
            (rule.matches_id(id) && !reason.is_empty())
                .then(|| reason.chars().take(MAX_SUPPRESS_REASON_CHARS).collect())
        })
}

fn split_suppressed(
    source: &str,
    findings: Vec<RichFinding>,
) -> (Vec<RichFinding>, Vec<SuppressedFinding>) {
    if !source.contains(SUPPRESS_MARKER) {
        return (findings, Vec::new());
    }
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings {
        match suppression_reason(&lines, finding.line, finding.rule) {
            Some(reason) => suppressed.push(SuppressedFinding { finding, reason }),
            None => kept.push(finding),
        }
    }
    (kept, suppressed)
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
        || p.contains("src/analyzer/rules/")
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
            let conf_tag = match f.rule.confidence {
                Confidence::High => "",
                Confidence::Medium => " *(heuristic)*",
            };
            let _ = writeln!(
                out,
                "  ⚠ `{}` ({}) — {} in `{}` at line {}{}",
                f.rule.id, f.rule.cwe, f.description, f.file, f.line, conf_tag
            );
        }
        out.push('\n');
    }
}

fn render_suppressed(out: &mut String, suppressed: &[SuppressedFinding]) {
    if suppressed.is_empty() {
        return;
    }
    out.push_str("## Suppressed (nexus-ignore)\n\n");
    for s in suppressed {
        let _ = writeln!(
            out,
            "  ⊘ `{}` in `{}` at line {} — reason: {}",
            s.finding.rule.id, s.finding.file, s.finding.line, s.reason
        );
    }
    out.push('\n');
}

/// One entry per rule that fired, with its CWE/OWASP mapping and remediation.
fn render_rule_reference(out: &mut String, findings: &[RichFinding]) {
    let mut seen = HashSet::new();
    let mut fired: Vec<&RuleMeta> = findings
        .iter()
        .map(|f| f.rule)
        .filter(|r| seen.insert(r.id))
        .collect();
    if fired.is_empty() {
        return;
    }
    fired.sort_by_key(|r| r.id);
    out.push_str("## Rule Reference\n\n");
    for r in fired {
        let _ = writeln!(
            out,
            "  - `{}` — {}{} — {}",
            r.id,
            r.cwe,
            r.owasp.map(|o| format!(" / OWASP {o}")).unwrap_or_default(),
            r.remediation
        );
    }
    out.push('\n');
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
    suppressed: &[SuppressedFinding],
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
                "rule_id":        f.rule.id,
                "legacy_rule_id": f.rule.legacy_id.unwrap_or(f.rule.id),
                "category":       f.rule.category,
                "cwe":            f.rule.cwe,
                "owasp":          f.rule.owasp,
                "tier":           f.rule.tier,
                "severity":       f.severity,
                "confidence":     f.rule.confidence,
                "file":           f.file,
                "line":           f.line,
                "description":    f.description,
                "fingerprint":    f.fingerprint,
            })
        })
        .collect();
    let suppressed_json: Vec<Value> = suppressed
        .iter()
        .map(|s| {
            json!({
                "rule_id":     s.finding.rule.id,
                "file":        s.finding.file,
                "line":        s.finding.line,
                "reason":      s.reason,
                "fingerprint": s.finding.fingerprint,
            })
        })
        .collect();
    let summary = json!({
        "schema_version": "2",
        "files_scanned": files_scanned,
        "restricted_files": restricted,
        "findings_before_dedup": findings.len() + dupes_removed,
        "duplicates_removed": dupes_removed,
        "findings_total": findings.len(),
        "suppressed_total": suppressed.len(),
        "by_context": {
            "production":          counts(AuditContext::Production),
            "test":                counts(AuditContext::Test),
            "fixture":             counts(AuditContext::Fixture),
            "detector_definition": counts(AuditContext::DetectorDefinition),
        },
        "production_risk": prod_risk,
        "suppressed": suppressed_json,
    });
    serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_owned())
}

// ── Per-file analysis ────────────────────────────────────────────────────────

/// Runs every detector on one file. Blocking (file I/O + parsing).
fn audit_file(path: &Path, rel: &str) -> (Vec<RichFinding>, Vec<SuppressedFinding>) {
    let Ok(source) = std::fs::read_to_string(path) else {
        return (Vec::new(), Vec::new());
    };
    let mut findings: Vec<RichFinding> = Vec::new();

    // Secret detection — location and type only, never the value.
    for (secret_type, line) in sanitizer::detect_all_secrets(&source) {
        findings.push(RichFinding::new(
            &rules::HARDCODED_SECRET,
            rules::HARDCODED_SECRET.severity,
            rel,
            line,
            format!("[{secret_type}] detected — value NOT recorded"),
        ));
    }

    if let Some(grammar) = analyzer::detect_grammar(path) {
        // AST-based detection (tree-sitter; precise, no string-literal FPs).
        for f in analyzer::audit_file_ast(&source, grammar) {
            findings.push(RichFinding::new(
                f.rule,
                f.rule.severity.escalate_if(f.is_write_sink),
                rel,
                f.line,
                f.description,
            ));
        }

        // SQL-injection heuristic (text-based; replaced by AST taint in Fase 2).
        let sql = &rules::SQL_INJECTION_HEURISTIC;
        for (lineno, line) in source.lines().enumerate() {
            let lower = line.to_lowercase();
            if (lower.contains("select ") || lower.contains("insert ") || lower.contains("delete "))
                && (line.contains('+') || line.contains("format!") || line.contains("concat"))
            {
                findings.push(RichFinding::new(
                    sql,
                    sql.severity,
                    rel,
                    lineno + 1,
                    sql.description.to_owned(),
                ));
            }
        }
    }

    split_suppressed(&source, findings)
}

fn report_order(a: &RichFinding, b: &RichFinding) -> std::cmp::Ordering {
    (a.file.as_str(), a.line, a.rule.id).cmp(&(b.file.as_str(), b.line, b.rule.id))
}

// ── Tool entry point ─────────────────────────────────────────────────────────

pub(super) async fn audit_security_measures(proj: &crate::state::ProjectContext) -> Result<Value> {
    let index = proj.index().await?;
    let files_scanned = index.allowed_files.len();
    let restricted_len = index.restricted_files.len();
    let files: Vec<(PathBuf, String)> = index
        .allowed_files
        .iter()
        .filter_map(|file| {
            let path = proj.validate_path(file).ok()?;
            let rel = index.relative(&path).to_string_lossy().into_owned();
            Some((path, rel))
        })
        .collect();
    drop(index);

    // One blocking task per CPU, each auditing a contiguous chunk of files.
    let workers = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let chunk_size = files.len().div_ceil(workers).max(1);
    let mut tasks = JoinSet::new();
    for chunk in files.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        tasks.spawn_blocking(move || {
            let mut findings = Vec::new();
            let mut suppressed = Vec::new();
            for (path, rel) in &chunk {
                let (f, s) = audit_file(path, rel);
                findings.extend(f);
                suppressed.extend(s);
            }
            (findings, suppressed)
        });
    }

    let mut findings: Vec<RichFinding> = Vec::new();
    let mut suppressed: Vec<SuppressedFinding> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (f, s) = joined?;
        findings.extend(f);
        suppressed.extend(s);
    }
    // Deterministic output regardless of task completion order.
    findings.sort_by(report_order);
    suppressed.sort_by(|a, b| report_order(&a.finding, &b.finding));

    let (findings, dupes_removed) = dedup(findings);
    let mut seen = HashSet::new();
    suppressed.retain(|s| seen.insert(s.finding.fingerprint.clone()));

    // ── Render Markdown ─────────────────────────────────────────────────────
    let mut out = String::from("# Security Audit Report\n\n");
    let _ = write!(
        out,
        "Files scanned: {}  Restricted: {}  \
         Findings: {} ({} after deduplication, {} duplicates removed, {} suppressed)\n\n",
        files_scanned,
        restricted_len,
        findings.len() + dupes_removed,
        findings.len(),
        dupes_removed,
        suppressed.len(),
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
    render_suppressed(&mut out, &suppressed);
    render_rule_reference(&mut out, &findings);

    // Inline JSON summary for CI — deterministic, versioned, secret-free.
    out.push_str("## JSON Summary\n\n```json\n");
    out.push_str(&render_json_summary(
        &findings,
        &suppressed,
        files_scanned,
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

    fn unsafe_block_rule() -> &'static RuleMeta {
        rules::STRUCTURAL_RULES
            .iter()
            .map(|r| &r.meta)
            .find(|m| m.id == "rust-unsafe-code-block")
            .expect("rust-unsafe-code-block is registered")
    }

    fn finding_at(line: usize) -> RichFinding {
        RichFinding::new(
            unsafe_block_rule(),
            Severity::High,
            "src/foo.rs",
            line,
            "unsafe block".to_owned(),
        )
    }

    #[test]
    fn suppression_on_same_or_previous_line_with_reason() {
        let source = "a\n// nexus-ignore: rust-unsafe-code-block FFI boundary audited\nunsafe {}\nunsafe {} // nexus-ignore: rust-unsafe reviewed in PR 12\n";
        let (kept, suppressed) = split_suppressed(source, vec![finding_at(3), finding_at(4)]);
        assert!(
            kept.is_empty(),
            "both findings must be suppressed: {kept:?}"
        );
        assert_eq!(suppressed.len(), 2);
        assert_eq!(suppressed[0].reason, "FFI boundary audited");
        assert_eq!(
            suppressed[1].reason, "reviewed in PR 12",
            "legacy id must be accepted"
        );
    }

    #[test]
    fn suppression_requires_reason_and_matching_rule() {
        let source = "// nexus-ignore: rust-unsafe-code-block\nunsafe {}\n// nexus-ignore: js-xss-inner-html not this rule\nunsafe {}\n";
        let (kept, suppressed) = split_suppressed(source, vec![finding_at(2), finding_at(4)]);
        assert_eq!(
            kept.len(),
            2,
            "missing reason or other rule must not suppress"
        );
        assert!(suppressed.is_empty());
    }

    #[test]
    fn suppression_does_not_reach_two_lines_down() {
        let source = "// nexus-ignore: rust-unsafe-code-block reason\n\nunsafe {}\n";
        let (kept, _) = split_suppressed(source, vec![finding_at(3)]);
        assert_eq!(kept.len(), 1);
    }

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
                unsafe_block_rule(),
                Severity::High,
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
                unsafe_block_rule(),
                Severity::High,
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
            &rules::HARDCODED_SECRET,
            Severity::Critical,
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
        assert_eq!(
            f.fingerprint,
            format!("{}:src/config.rs:42", rules::HARDCODED_SECRET.id)
        );
    }

    #[test]
    fn render_json_summary_is_valid_json_and_has_schema_version() {
        let findings = vec![RichFinding::new(
            unsafe_block_rule(),
            Severity::High,
            "src/lib.rs",
            5,
            "unsafe block".to_owned(),
        )];
        let json_str = render_json_summary(&findings, &[], 10, 0, 0);
        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("JSON summary must be valid JSON");
        assert_eq!(v["schema_version"], "2");
        assert!(v["by_context"]["production"]["high"].as_u64().unwrap_or(0) >= 1);
        let entry = &v["production_risk"][0];
        assert_eq!(entry["rule_id"], "rust-unsafe-code-block");
        assert_eq!(entry["legacy_rule_id"], "rust-unsafe");
        assert_eq!(entry["cwe"], "CWE-676");
        assert_eq!(entry["tier"], "structural");
    }

    #[test]
    fn render_context_group_shows_check_mark_when_empty() {
        let mut out = String::new();
        render_context_group(&mut out, "Production Risk", &[]);
        assert!(out.contains('✓'), "empty group must show a check mark");
    }
}
