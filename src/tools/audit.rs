use anyhow::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::task::JoinSet;

use crate::analyzer;
use crate::analyzer::rules::{self, Confidence, RuleMeta, Severity, Tier};
use crate::analyzer::taint::Summaries;
use crate::privacy_gateway;
use crate::protocol::{error_response, text_content, tool_response};
use crate::sanitizer;

mod sarif;

/// Baseline of accepted findings, read from the project root.
const BASELINE_FILE: &str = "audit-baseline.json";
/// JSON summary contract version (bumped when field semantics change).
const SCHEMA_VERSION: &str = "3";
const TOP_RISK_FUNCTIONS: usize = 10;

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
/// Identities are derived from metadata only — secret values are never stored.
#[derive(Debug, Clone)]
struct RichFinding {
    rule: &'static RuleMeta,
    /// Rule base severity, possibly escalated for this occurrence.
    severity: Severity,
    context: AuditContext,
    file: String,
    line: usize,
    description: String,
    /// Taint flow as (source line, sink line).
    flow: Option<(usize, usize)>,
    /// Enclosing function, when known.
    function: Option<String>,
    /// Exact identity used for deduplication: `rule_id:rel_path:line`.
    fingerprint: String,
    /// Line-independent identity used by the baseline and SARIF:
    /// `rule_id:rel_path:function:ordinal` (ordinal within that triple).
    stable_id: String,
    /// Present in `audit-baseline.json` (accepted existing debt).
    baselined: bool,
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
            flow: None,
            function: None,
            fingerprint,
            stable_id: String::new(),
            baselined: false,
        }
    }

    fn from_analyzer(f: analyzer::AuditFinding, file: &str) -> Self {
        let mut finding = Self::new(
            f.rule,
            f.rule.severity.escalate_if(f.is_write_sink),
            file,
            f.line,
            f.description,
        );
        finding.flow = f.flow;
        finding.function = f.function;
        finding
    }

    /// Counts toward the production gate: production code, not an N4
    /// pattern, not accepted in the baseline.
    fn is_production_risk(&self) -> bool {
        self.context == AuditContext::Production
            && self.rule.tier != Tier::Pattern
            && !self.baselined
    }

    fn is_risk_pattern(&self) -> bool {
        self.context == AuditContext::Production
            && self.rule.tier == Tier::Pattern
            && !self.baselined
    }
}

/// Finding silenced by a `nexus-ignore` directive; still listed in the report.
#[derive(Debug, Clone)]
struct SuppressedFinding {
    finding: RichFinding,
    reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineStatus {
    Absent,
    Loaded { entries: usize },
    Invalid,
}

/// Everything an output format needs; computed once per tool call.
struct AuditReport {
    findings: Vec<RichFinding>,
    suppressed: Vec<SuppressedFinding>,
    files_scanned: usize,
    restricted: usize,
    dupes_removed: usize,
    baseline: BaselineStatus,
}

impl AuditReport {
    fn production_risk(&self) -> impl Iterator<Item = &RichFinding> {
        self.findings.iter().filter(|f| f.is_production_risk())
    }

    fn risk_patterns(&self) -> impl Iterator<Item = &RichFinding> {
        self.findings.iter().filter(|f| f.is_risk_pattern())
    }

    fn baselined(&self) -> impl Iterator<Item = &RichFinding> {
        self.findings.iter().filter(|f| f.baselined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Markdown,
    Sarif,
    Baseline,
}

impl OutputFormat {
    fn parse(args: &Value) -> Result<Self, String> {
        match args
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("markdown")
        {
            "markdown" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            "baseline" => Ok(Self::Baseline),
            other => Err(format!(
                "Invalid format '{other}'. Allowed values: markdown, sarif, baseline"
            )),
        }
    }
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
    if p.ends_with("src/analyzer/audit.rs")
        || p.ends_with("src/analyzer/infra.rs")
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

// ── Identities and baseline ──────────────────────────────────────────────────

/// Assign `stable_id`s. Findings must already be in report order so the
/// ordinal within (rule, file, function) is deterministic.
fn assign_stable_ids<'a>(findings: impl Iterator<Item = &'a mut RichFinding>) {
    let mut ordinals: HashMap<(&'static str, String, String), usize> = HashMap::new();
    for f in findings {
        let function = f.function.clone().unwrap_or_else(|| "-".to_owned());
        let n = ordinals
            .entry((f.rule.id, f.file.clone(), function.clone()))
            .or_insert(0);
        *n += 1;
        f.stable_id = format!("{}:{}:{function}:{n}", f.rule.id, f.file);
    }
}

/// Stable ids accepted in `audit-baseline.json`
/// (`{"version": 1, "findings": ["<stable_id>", …]}`).
fn load_baseline(root: &Path, restricted: bool) -> (BaselineStatus, HashSet<String>) {
    if restricted {
        return (BaselineStatus::Absent, HashSet::new());
    }
    let Ok(text) = std::fs::read_to_string(root.join(BASELINE_FILE)) else {
        return (BaselineStatus::Absent, HashSet::new());
    };
    let ids: Option<HashSet<String>> = serde_json::from_str::<Value>(&text).ok().and_then(|v| {
        v.get("findings")?
            .as_array()?
            .iter()
            .map(|id| id.as_str().map(str::to_owned))
            .collect()
    });
    match ids {
        Some(ids) => (BaselineStatus::Loaded { entries: ids.len() }, ids),
        None => (BaselineStatus::Invalid, HashSet::new()),
    }
}

// ── Risk ranking ─────────────────────────────────────────────────────────────

struct FunctionRisk<'a> {
    file: &'a str,
    function: &'a str,
    /// Score × 10 (integer arithmetic keeps the ranking deterministic).
    score: u32,
    findings: usize,
    exposed: bool,
}

/// Deterministic per-function ranking (SAST v2 §4.2):
/// Σ severity weight × confidence weight over production findings, plus an
/// exposure bonus when user input demonstrably reaches the function (a taint
/// flow ends there).
fn rank_functions(findings: &[RichFinding]) -> Vec<FunctionRisk<'_>> {
    // Demonstrated user input weighs as much as a confirmed Critical finding.
    const EXPOSURE_BONUS: u32 = 100;
    let severity_weight = |s: Severity| match s {
        Severity::Critical => 10,
        Severity::High => 6,
        Severity::Medium => 3,
        Severity::Low => 1,
    };
    let confidence_weight = |c: Confidence| match c {
        Confidence::High => 10,
        Confidence::Medium => 6,
        Confidence::Low => 3,
    };
    let mut by_fn: BTreeMap<(&str, &str), FunctionRisk<'_>> = BTreeMap::new();
    for f in findings
        .iter()
        .filter(|f| f.context == AuditContext::Production && !f.baselined)
    {
        let Some(function) = f.function.as_deref() else {
            continue;
        };
        let entry = by_fn
            .entry((f.file.as_str(), function))
            .or_insert(FunctionRisk {
                file: &f.file,
                function,
                score: 0,
                findings: 0,
                exposed: false,
            });
        entry.score += severity_weight(f.severity) * confidence_weight(f.rule.confidence);
        entry.findings += 1;
        if f.flow.is_some() && !entry.exposed {
            entry.exposed = true;
            entry.score += EXPOSURE_BONUS;
        }
    }
    let mut ranked: Vec<FunctionRisk<'_>> = by_fn.into_values().collect();
    ranked.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| (a.file, a.function).cmp(&(b.file, b.function)))
    });
    ranked.truncate(TOP_RISK_FUNCTIONS);
    ranked
}

// ── Markdown rendering ───────────────────────────────────────────────────────

const SEVERITIES: [Severity; 4] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
];

fn severity_icon(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴 Critical",
        Severity::High => "🟠 High",
        Severity::Medium => "🟡 Medium",
        Severity::Low => "⚪ Low",
    }
}

fn render_context_group(out: &mut String, title: &str, findings: &[&RichFinding]) {
    let _ = write!(out, "## {title}\n\n");
    if findings.is_empty() {
        out.push_str("  ✓ No findings in this context.\n\n");
        return;
    }
    for sev in SEVERITIES {
        let group: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == sev)
            .copied()
            .collect();
        if group.is_empty() {
            continue;
        }
        let _ = write!(out, "### {}\n\n", severity_icon(sev));
        for f in &group {
            let conf_tag = match f.rule.confidence {
                Confidence::High => "",
                Confidence::Medium => " *(heuristic)*",
                Confidence::Low => " *(pattern)*",
            };
            let flow = f
                .flow
                .map(|(src, sink)| format!(" (flow: line {src} → line {sink})"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  ⚠ `{}` ({}) — {} in `{}` at line {}{}{}",
                f.rule.id, f.rule.cwe, f.description, f.file, f.line, flow, conf_tag
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

fn render_baselined(out: &mut String, report: &AuditReport) {
    match report.baseline {
        BaselineStatus::Absent => {}
        BaselineStatus::Invalid => {
            let _ = write!(
                out,
                "## Baseline\n\n  ⚠ `{BASELINE_FILE}` is not valid (expected {{\"findings\": [\"<stable_id>\", …]}}); ignored.\n\n"
            );
        }
        BaselineStatus::Loaded { entries } => {
            let mut per_rule: BTreeMap<&str, usize> = BTreeMap::new();
            for f in report.baselined() {
                *per_rule.entry(f.rule.id).or_default() += 1;
            }
            let matched: usize = per_rule.values().sum();
            let _ = write!(
                out,
                "## Baselined (accepted debt, informative)\n\n  `{BASELINE_FILE}`: {entries} entries, {matched} matched; only new findings count as production risk.\n"
            );
            for (rule, n) in per_rule {
                let _ = writeln!(out, "  - `{rule}`: {n}");
            }
            out.push('\n');
        }
    }
}

fn render_top_functions(out: &mut String, ranked: &[FunctionRisk<'_>]) {
    if ranked.is_empty() {
        return;
    }
    out.push_str("## Top Functions to Review\n\n");
    out.push_str("| # | Function | File | Score | Findings | Exposed |\n");
    out.push_str("|---|----------|------|-------|----------|---------|\n");
    for (i, r) in ranked.iter().enumerate() {
        let _ = writeln!(
            out,
            "| {} | `{}` | `{}` | {}.{} | {} | {} |",
            i + 1,
            r.function,
            r.file,
            r.score / 10,
            r.score % 10,
            r.findings,
            if r.exposed { "yes" } else { "no" }
        );
    }
    out.push_str("\n  Use `inspect_symbol` on these functions to review them first.\n\n");
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

/// Gate counts exclude N4 patterns and baselined findings.
fn gate_count(findings: &[RichFinding], ctx: AuditContext, sev: Severity) -> usize {
    findings
        .iter()
        .filter(|f| {
            f.context == ctx && f.severity == sev && f.rule.tier != Tier::Pattern && !f.baselined
        })
        .count()
}

const CONTEXTS: [(&str, AuditContext); 4] = [
    ("production", AuditContext::Production),
    ("test", AuditContext::Test),
    ("fixture", AuditContext::Fixture),
    ("detector_definition", AuditContext::DetectorDefinition),
];

fn render_summary_table(out: &mut String, findings: &[RichFinding]) {
    out.push_str("| Context              | Critical | High | Medium | Low |\n");
    out.push_str("|----------------------|----------|------|--------|-----|\n");
    for (label, ctx) in CONTEXTS {
        let _ = writeln!(
            out,
            "| {label:<20} | {:>8} | {:>4} | {:>6} | {:>3} |",
            gate_count(findings, ctx, Severity::Critical),
            gate_count(findings, ctx, Severity::High),
            gate_count(findings, ctx, Severity::Medium),
            gate_count(findings, ctx, Severity::Low),
        );
    }
    out.push('\n');
}

fn render_markdown(report: &AuditReport) -> String {
    let findings = &report.findings;
    let mut out = String::from("# Security Audit Report\n\n");
    let _ = write!(
        out,
        "Files scanned: {}  Restricted: {}  \
         Findings: {} ({} after deduplication, {} duplicates removed, {} suppressed, {} baselined)\n\n",
        report.files_scanned,
        report.restricted,
        findings.len() + report.dupes_removed,
        findings.len(),
        report.dupes_removed,
        report.suppressed.len(),
        report.baselined().count(),
    );
    out.push_str("  NOTE: Secret values are NEVER included. Only type and location are shown.\n");
    out.push_str(
        "  NOTE: Taint analysis follows calls through function summaries (depth 3); \
         dynamic dispatch and reflection are not resolved.\n\n",
    );

    out.push_str("## Summary\n\n");
    render_summary_table(&mut out, findings);

    let prod: Vec<&RichFinding> = report.production_risk().collect();
    render_context_group(&mut out, "Production Risk", &prod);

    let patterns: Vec<&RichFinding> = report.risk_patterns().collect();
    if !patterns.is_empty() {
        render_context_group(&mut out, "Risk Patterns (informative)", &patterns);
    }

    render_top_functions(&mut out, &rank_functions(findings));

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
    render_baselined(&mut out, report);
    render_suppressed(&mut out, &report.suppressed);
    render_rule_reference(&mut out, findings);

    // Inline JSON summary for CI — deterministic, versioned, secret-free.
    out.push_str("## JSON Summary\n\n```json\n");
    out.push_str(&render_json_summary(report));
    out.push_str("\n```\n");
    out
}

fn finding_json(f: &RichFinding) -> Value {
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
        "function":       f.function,
        "flow":           f.flow.map(|(src, sink)| json!({"source_line": src, "sink_line": sink})),
        "description":    f.description,
        "fingerprint":    f.fingerprint,
        "stable_id":      f.stable_id,
    })
}

fn render_json_summary(report: &AuditReport) -> String {
    let findings = &report.findings;
    let counts = |ctx: AuditContext| {
        json!({
            "critical": gate_count(findings, ctx, Severity::Critical),
            "high":     gate_count(findings, ctx, Severity::High),
            "medium":   gate_count(findings, ctx, Severity::Medium),
            "low":      gate_count(findings, ctx, Severity::Low),
        })
    };
    let suppressed_json: Vec<Value> = report
        .suppressed
        .iter()
        .map(|s| {
            json!({
                "rule_id":     s.finding.rule.id,
                "file":        s.finding.file,
                "line":        s.finding.line,
                "reason":      s.reason,
                "fingerprint": s.finding.fingerprint,
                "stable_id":   s.finding.stable_id,
            })
        })
        .collect();
    let top: Vec<Value> = rank_functions(findings)
        .iter()
        .map(|r| {
            json!({
                "file": r.file,
                "function": r.function,
                "score": f64::from(r.score) / 10.0,
                "findings": r.findings,
                "exposed": r.exposed,
            })
        })
        .collect();
    let baseline = match report.baseline {
        BaselineStatus::Absent => json!({"status": "absent"}),
        BaselineStatus::Invalid => json!({"status": "invalid"}),
        BaselineStatus::Loaded { entries } => json!({"status": "loaded", "entries": entries}),
    };
    let summary = json!({
        "schema_version": SCHEMA_VERSION,
        "files_scanned": report.files_scanned,
        "restricted_files": report.restricted,
        "findings_before_dedup": findings.len() + report.dupes_removed,
        "duplicates_removed": report.dupes_removed,
        "findings_total": findings.len(),
        "suppressed_total": report.suppressed.len(),
        "baselined_total": report.baselined().count(),
        "baseline": baseline,
        "taint_coverage": "inter-procedural-summaries",
        "by_context": {
            "production":          counts(AuditContext::Production),
            "test":                counts(AuditContext::Test),
            "fixture":             counts(AuditContext::Fixture),
            "detector_definition": counts(AuditContext::DetectorDefinition),
        },
        "production_risk": report.production_risk().map(finding_json).collect::<Vec<_>>(),
        "risk_patterns": report.risk_patterns().map(finding_json).collect::<Vec<_>>(),
        "top_risk_functions": top,
        "suppressed": suppressed_json,
    });
    serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_owned())
}

/// Ready-to-save `audit-baseline.json` accepting every current finding.
fn render_baseline(report: &AuditReport) -> String {
    let mut ids: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.stable_id.as_str())
        .collect();
    ids.sort_unstable();
    let doc = json!({
        "version": 1,
        "generated_by": format!("NexusIntelliCore {}", env!("CARGO_PKG_VERSION")),
        "findings": ids,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned())
}

// ── Per-file analysis ────────────────────────────────────────────────────────

/// Runs every detector on one file. Blocking (file I/O + parsing).
/// `preloaded` is the source already read for the summary rounds, if any.
fn audit_file(
    path: &Path,
    rel: &str,
    preloaded: Option<&str>,
    summaries: &Summaries,
) -> (Vec<RichFinding>, Vec<SuppressedFinding>) {
    let owned;
    let source: &str = match preloaded {
        Some(source) => source,
        None => match std::fs::read_to_string(path) {
            Ok(source) => {
                owned = source;
                &owned
            }
            Err(_) => return (Vec::new(), Vec::new()),
        },
    };
    let mut findings: Vec<RichFinding> = Vec::new();

    // Secret detection — location and type only, never the value.
    for (secret_type, line) in sanitizer::detect_all_secrets(source) {
        findings.push(RichFinding::new(
            &rules::HARDCODED_SECRET,
            rules::HARDCODED_SECRET.severity,
            rel,
            line,
            format!("[{secret_type}] detected — value NOT recorded"),
        ));
    }

    let grammar = analyzer::detect_grammar(path);
    if let Some(grammar) = grammar {
        // AST-based detection (tree-sitter; precise, no string-literal FPs).
        findings.extend(
            analyzer::audit_file_ast_with(source, grammar, summaries)
                .into_iter()
                .map(|f| RichFinding::from_analyzer(f, rel)),
        );

        // SQL-injection text heuristic, only where no SQL taint rule exists.
        let sql = &rules::SQL_INJECTION_HEURISTIC;
        if !rules::taint_covers(grammar.name(), sql.category) {
            for (lineno, line) in source.lines().enumerate() {
                let lower = line.to_lowercase();
                if (lower.contains("select ")
                    || lower.contains("insert ")
                    || lower.contains("delete "))
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
    }

    // Infrastructure files (Dockerfile, YAML, properties, shell): N3 rules.
    findings.extend(
        analyzer::infra::audit_infra(path, source)
            .into_iter()
            .map(|f| RichFinding::from_analyzer(f, rel)),
    );

    // Inline test code (Rust `#[cfg(test)]` modules) is test evidence, not
    // production risk, whatever the file path says.
    if let Some(grammar) = grammar {
        let test_lines = analyzer::test_code_lines(source, grammar);
        for f in findings
            .iter_mut()
            .filter(|f| f.context == AuditContext::Production)
        {
            if test_lines
                .iter()
                .any(|&(start, end)| (start..=end).contains(&f.line))
            {
                f.context = AuditContext::Test;
            }
        }
    }

    split_suppressed(source, findings)
}

/// Largest file kept in memory for the cross-file summary rounds.
const MAX_SUMMARY_SOURCE_BYTES: u64 = 1 << 20;

/// Source of a file that has a taint pack and is small enough to summarize.
fn load_taint_source(path: &Path) -> Option<String> {
    let grammar = analyzer::detect_grammar(path)?;
    rules::taint_pack(grammar.name())?;
    if std::fs::metadata(path).ok()?.len() > MAX_SUMMARY_SOURCE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Splits `0..len` into at most one contiguous range per CPU.
fn worker_ranges(len: usize) -> Vec<std::ops::Range<usize>> {
    let workers = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let chunk = len.div_ceil(workers).max(1);
    (0..len)
        .step_by(chunk)
        .map(|start| start..(start + chunk).min(len))
        .collect()
}

/// Project-wide taint summaries: each round resolves calls with the previous
/// round's summaries, so a flow is followed through `SUMMARY_DEPTH` nested
/// calls, across files.
async fn project_summaries(
    files: &Arc<Vec<(PathBuf, String)>>,
    sources: &Arc<Vec<Option<String>>>,
) -> Result<Arc<Summaries>> {
    let mut known = Arc::new(Summaries::default());
    if sources.iter().all(Option::is_none) {
        return Ok(known);
    }
    for _ in 0..analyzer::taint::SUMMARY_DEPTH {
        let mut tasks = JoinSet::new();
        for range in worker_ranges(files.len()) {
            let (files, sources, known) =
                (Arc::clone(files), Arc::clone(sources), Arc::clone(&known));
            tasks.spawn_blocking(move || {
                let mut entries = Vec::new();
                for i in range {
                    let (Some(source), Some(grammar)) =
                        (&sources[i], analyzer::detect_grammar(&files[i].0))
                    else {
                        continue;
                    };
                    entries.extend(analyzer::summarize_file(source, grammar, &known));
                }
                entries
            });
        }
        let mut entries = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            entries.extend(joined?);
        }
        let next = Summaries::from_entries(entries);
        // Fixpoint: another round cannot change anything.
        if next == *known {
            break;
        }
        known = Arc::new(next);
    }
    Ok(known)
}

fn report_order(a: &RichFinding, b: &RichFinding) -> std::cmp::Ordering {
    (a.file.as_str(), a.line, a.rule.id).cmp(&(b.file.as_str(), b.line, b.rule.id))
}

async fn collect_report(proj: &crate::state::ProjectContext) -> Result<AuditReport> {
    let index = proj.index().await?;
    let files_scanned = index.allowed_files.len();
    let restricted = index.restricted_files.len();
    let baseline_restricted = index.is_restricted(&proj.root().join(BASELINE_FILE));
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

    let files = Arc::new(files);

    // Phase 1: read the sources that take part in cross-file taint summaries.
    let mut loads = JoinSet::new();
    for range in worker_ranges(files.len()) {
        let files = Arc::clone(&files);
        loads.spawn_blocking(move || {
            let start = range.start;
            let loaded: Vec<Option<String>> = files[range]
                .iter()
                .map(|(p, _)| load_taint_source(p))
                .collect();
            (start, loaded)
        });
    }
    let mut sources: Vec<Option<String>> = vec![None; files.len()];
    while let Some(joined) = loads.join_next().await {
        let (start, loaded) = joined?;
        for (offset, source) in loaded.into_iter().enumerate() {
            sources[start + offset] = source;
        }
    }
    let sources = Arc::new(sources);

    // Phase 2: function summaries (N2b).
    let summaries = project_summaries(&files, &sources).await?;

    // Phase 3: one blocking task per CPU, each auditing a contiguous chunk.
    let mut tasks = JoinSet::new();
    for range in worker_ranges(files.len()) {
        let (files, sources, summaries) = (
            Arc::clone(&files),
            Arc::clone(&sources),
            Arc::clone(&summaries),
        );
        tasks.spawn_blocking(move || {
            let mut findings = Vec::new();
            let mut suppressed = Vec::new();
            for i in range {
                let (path, rel) = &files[i];
                let (f, s) = audit_file(path, rel, sources[i].as_deref(), &summaries);
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

    let (mut findings, dupes_removed) = dedup(findings);
    let mut seen = HashSet::new();
    suppressed.retain(|s| seen.insert(s.finding.fingerprint.clone()));

    assign_stable_ids(findings.iter_mut());
    assign_stable_ids(suppressed.iter_mut().map(|s| &mut s.finding));

    let root = proj.root().to_path_buf();
    let (baseline, accepted) =
        tokio::task::spawn_blocking(move || load_baseline(&root, baseline_restricted)).await?;
    for f in &mut findings {
        f.baselined = accepted.contains(&f.stable_id);
    }

    Ok(AuditReport {
        findings,
        suppressed,
        files_scanned,
        restricted,
        dupes_removed,
        baseline,
    })
}

// ── Tool entry point ─────────────────────────────────────────────────────────

pub(super) async fn audit_security_measures(
    proj: &crate::state::ProjectContext,
    args: &Value,
) -> Result<Value> {
    let format = match OutputFormat::parse(args) {
        Ok(format) => format,
        Err(message) => return Ok(error_response(message)),
    };
    let report = collect_report(proj).await?;
    let body = match format {
        OutputFormat::Markdown => render_markdown(&report),
        OutputFormat::Sarif => sarif::render(&report),
        OutputFormat::Baseline => render_baseline(&report),
    };

    // Final privacy-gateway pass as an extra safety net.
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized, _) = privacy_gateway::sanitize_security_report(&body, &policy);
    let output = match format {
        OutputFormat::Markdown => format!(
            "[Think like a security auditor: reason about risk, trust boundaries, and attack surface.]\n{sanitized}"
        ),
        // Machine-readable formats stay pure JSON.
        OutputFormat::Sarif | OutputFormat::Baseline => sanitized,
    };
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
            classify_context("src/analyzer/rules/java/taint_sinks.scm"),
            AuditContext::DetectorDefinition
        );
        assert_eq!(
            classify_context("src/sanitizer.rs"),
            AuditContext::DetectorDefinition
        );
        assert_eq!(
            classify_context("src/analyzer/infra.rs"),
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

    fn report(findings: Vec<RichFinding>) -> AuditReport {
        AuditReport {
            findings,
            suppressed: Vec::new(),
            files_scanned: 10,
            restricted: 0,
            dupes_removed: 0,
            baseline: BaselineStatus::Absent,
        }
    }

    fn panic_rule() -> &'static RuleMeta {
        rules::STRUCTURAL_RULES
            .iter()
            .map(|r| &r.meta)
            .find(|m| m.id == "rust-uncaught-panic-unwrap")
            .expect("rust-uncaught-panic-unwrap is registered")
    }

    #[test]
    fn render_json_summary_is_valid_json_and_has_schema_version() {
        let mut f = RichFinding::new(
            unsafe_block_rule(),
            Severity::High,
            "src/lib.rs",
            5,
            "unsafe block".to_owned(),
        );
        f.function = Some("raw_write".to_owned());
        let mut findings = vec![f];
        assign_stable_ids(findings.iter_mut());
        let json_str = render_json_summary(&report(findings));
        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("JSON summary must be valid JSON");
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert!(v["by_context"]["production"]["high"].as_u64().unwrap_or(0) >= 1);
        let entry = &v["production_risk"][0];
        assert_eq!(entry["rule_id"], "rust-unsafe-code-block");
        assert_eq!(entry["legacy_rule_id"], "rust-unsafe");
        assert_eq!(entry["cwe"], "CWE-676");
        assert_eq!(entry["tier"], "structural");
        assert_eq!(entry["function"], "raw_write");
        assert_eq!(
            entry["stable_id"],
            "rust-unsafe-code-block:src/lib.rs:raw_write:1"
        );
    }

    #[test]
    fn stable_ids_do_not_depend_on_line_numbers() {
        let at = |line: usize, function: &str| {
            let mut f = finding_at(line);
            f.function = Some(function.to_owned());
            f
        };
        let mut before = vec![at(10, "a"), at(20, "a"), at(30, "b")];
        let mut after = vec![at(15, "a"), at(28, "a"), at(90, "b")];
        assign_stable_ids(before.iter_mut());
        assign_stable_ids(after.iter_mut());
        let ids = |v: &[RichFinding]| v.iter().map(|f| f.stable_id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&before), ids(&after));
        assert_eq!(before[1].stable_id, "rust-unsafe-code-block:src/foo.rs:a:2");
    }

    #[test]
    fn baselined_and_pattern_findings_leave_the_production_gate() {
        let mut fresh = finding_at(1);
        fresh.stable_id = "fresh".to_owned();
        let mut accepted = finding_at(2);
        accepted.baselined = true;
        let pattern = RichFinding::new(
            panic_rule(),
            Severity::Medium,
            "src/foo.rs",
            3,
            String::new(),
        );
        let r = report(vec![fresh, accepted, pattern]);
        assert_eq!(r.production_risk().count(), 1);
        assert_eq!(r.risk_patterns().count(), 1);
        assert_eq!(r.baselined().count(), 1);
        let v: serde_json::Value =
            serde_json::from_str(&render_json_summary(&r)).expect("valid JSON");
        assert_eq!(v["by_context"]["production"]["high"], 1);
        assert_eq!(v["baselined_total"], 1);
        assert_eq!(v["risk_patterns"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn baseline_file_is_loaded_and_invalid_files_are_reported() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert_eq!(load_baseline(dir.path(), false).0, BaselineStatus::Absent);
        std::fs::write(
            dir.path().join(BASELINE_FILE),
            r#"{"version":1,"findings":["a","b"]}"#,
        )
        .expect("write baseline");
        let (status, ids) = load_baseline(dir.path(), false);
        assert_eq!(status, BaselineStatus::Loaded { entries: 2 });
        assert!(ids.contains("a"));
        assert_eq!(
            load_baseline(dir.path(), true).0,
            BaselineStatus::Absent,
            "restricted baseline is ignored"
        );
        std::fs::write(dir.path().join(BASELINE_FILE), "[1,2]").expect("write baseline");
        assert_eq!(load_baseline(dir.path(), false).0, BaselineStatus::Invalid);
    }

    #[test]
    fn rendered_baseline_round_trips_into_load_baseline() {
        let mut findings = vec![finding_at(1), finding_at(2)];
        assign_stable_ids(findings.iter_mut());
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join(BASELINE_FILE),
            render_baseline(&report(findings)),
        )
        .expect("write baseline");
        let (status, ids) = load_baseline(dir.path(), false);
        assert_eq!(status, BaselineStatus::Loaded { entries: 2 });
        assert!(ids.contains("rust-unsafe-code-block:src/foo.rs:-:2"));
    }

    #[test]
    fn rank_functions_orders_by_weighted_score_and_exposure() {
        let in_fn = |line: usize, function: &str, flow: bool| {
            let mut f = finding_at(line);
            f.function = Some(function.to_owned());
            f.flow = flow.then_some((line, line));
            f
        };
        let findings = vec![
            in_fn(1, "quiet", false),
            in_fn(2, "handler", true),
            in_fn(3, "quiet", false),
        ];
        let ranked = rank_functions(&findings);
        assert_eq!(
            ranked[0].function, "handler",
            "exposure outweighs one extra finding"
        );
        assert!(ranked[0].exposed);
        assert_eq!(ranked[1].findings, 2);
    }

    #[test]
    fn sarif_has_rules_results_flows_and_suppressions() {
        let mut flowed = finding_at(7);
        flowed.flow = Some((3, 7));
        flowed.function = Some("handler".to_owned());
        let mut accepted = finding_at(9);
        accepted.baselined = true;
        let mut findings = vec![flowed, accepted];
        assign_stable_ids(findings.iter_mut());
        let mut r = report(findings);
        r.suppressed.push(SuppressedFinding {
            finding: finding_at(11),
            reason: "audited".to_owned(),
        });
        let v: serde_json::Value =
            serde_json::from_str(&sarif::render(&r)).expect("valid SARIF JSON");
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(
            run["tool"]["driver"]["rules"][0]["id"],
            "rust-unsafe-code-block"
        );
        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["partialFingerprints"]["nexusStableId/v1"],
            "rust-unsafe-code-block:src/foo.rs:handler:1"
        );
        assert_eq!(
            results[0]["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
                ["physicalLocation"]["region"]["startLine"],
            3
        );
        assert_eq!(results[1]["suppressions"][0]["kind"], "external");
        assert_eq!(results[2]["suppressions"][0]["kind"], "inSource");
    }

    #[test]
    fn output_format_parsing() {
        assert_eq!(OutputFormat::parse(&json!({})), Ok(OutputFormat::Markdown));
        assert_eq!(
            OutputFormat::parse(&json!({"format": "sarif"})),
            Ok(OutputFormat::Sarif)
        );
        assert!(OutputFormat::parse(&json!({"format": "xml"})).is_err());
    }

    #[test]
    fn render_context_group_shows_check_mark_when_empty() {
        let mut out = String::new();
        render_context_group(&mut out, "Production Risk", &[]);
        assert!(out.contains('✓'), "empty group must show a check mark");
    }
}
