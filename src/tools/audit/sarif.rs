//! SARIF 2.1.0 rendering of an audit report (GitHub code scanning, IDEs).
//!
//! Messages are the fixed rule descriptions — never source content. Taint
//! flows become `codeFlows`; `nexus-ignore` suppressions and baselined
//! findings are reported as SARIF `suppressions` instead of being dropped.

use serde_json::{json, Value};
use std::collections::BTreeMap;

use super::{AuditContext, AuditReport, RichFinding};
use crate::analyzer::rules::{RuleMeta, Severity};

const STABLE_ID_KEY: &str = "nexusStableId/v1";

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// GitHub's numeric `security-severity` (0.0–10.0).
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
    }
}

fn context_name(c: AuditContext) -> &'static str {
    match c {
        AuditContext::Production => "production",
        AuditContext::Test => "test",
        AuditContext::Fixture => "fixture",
        AuditContext::DetectorDefinition => "detector_definition",
    }
}

fn location(file: &str, line: usize, message: Option<&str>) -> Value {
    let mut loc = json!({
        "physicalLocation": {
            "artifactLocation": { "uri": file, "uriBaseId": "%SRCROOT%" },
            "region": { "startLine": line }
        }
    });
    if let Some(text) = message {
        loc["message"] = json!({ "text": text });
    }
    loc
}

fn rule_json(r: &RuleMeta) -> Value {
    let mut tags = vec![
        "security".to_owned(),
        r.cwe.to_owned(),
        r.category.to_owned(),
    ];
    if let Some(owasp) = r.owasp {
        tags.push(format!("OWASP-{owasp}"));
    }
    json!({
        "id": r.id,
        "shortDescription": { "text": r.description },
        "help": { "text": r.remediation },
        "defaultConfiguration": { "level": level(r.severity) },
        "properties": {
            "tags": tags,
            "cwe": r.cwe,
            "owasp": r.owasp,
            "tier": r.tier,
            "confidence": r.confidence,
            "security-severity": security_severity(r.severity),
        }
    })
}

fn result_json(f: &RichFinding, rule_index: usize, suppression: Option<(&str, &str)>) -> Value {
    let mut result = json!({
        "ruleId": f.rule.id,
        "ruleIndex": rule_index,
        "level": level(f.severity),
        "message": { "text": f.description },
        "locations": [location(&f.file, f.line, None)],
        "partialFingerprints": { STABLE_ID_KEY: f.stable_id },
        "properties": {
            "context": context_name(f.context),
            "security-severity": security_severity(f.severity),
        }
    });
    if let Some(function) = &f.function {
        result["locations"][0]["logicalLocations"] =
            json!([{ "name": function, "kind": "function" }]);
    }
    if let Some((source_line, sink_line)) = f.flow {
        result["codeFlows"] = json!([{
            "threadFlows": [{
                "locations": [
                    { "location": location(&f.file, source_line, Some("user-controlled input")) },
                    { "location": location(&f.file, sink_line, Some("reaches sink")) }
                ]
            }]
        }]);
    }
    if let Some((kind, justification)) = suppression {
        result["suppressions"] = json!([{ "kind": kind, "justification": justification }]);
    }
    result
}

/// Render the whole report as a single-run SARIF 2.1.0 log.
pub(super) fn render(report: &AuditReport) -> String {
    let mut rules: BTreeMap<&str, &RuleMeta> = BTreeMap::new();
    for f in report
        .findings
        .iter()
        .chain(report.suppressed.iter().map(|s| &s.finding))
    {
        rules.insert(f.rule.id, f.rule);
    }
    let index: BTreeMap<&str, usize> = rules.keys().enumerate().map(|(i, id)| (*id, i)).collect();
    let idx = |f: &RichFinding| index.get(f.rule.id).copied().unwrap_or_default();

    let mut results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let suppression = f
                .baselined
                .then_some(("external", "accepted in audit-baseline.json"));
            result_json(f, idx(f), suppression)
        })
        .collect();
    results.extend(report.suppressed.iter().map(|s| {
        result_json(
            &s.finding,
            idx(&s.finding),
            Some(("inSource", s.reason.as_str())),
        )
    }));

    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "NexusIntelliCore",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/gasparoriol/NexusIntelliCore",
                    "rules": rules.values().map(|r| rule_json(r)).collect::<Vec<_>>(),
                }
            },
            "originalUriBaseIds": { "%SRCROOT%": { "description": { "text": "Project root" } } },
            "results": results,
            "properties": {
                "filesScanned": report.files_scanned,
                "restrictedFiles": report.restricted,
            }
        }]
    });
    serde_json::to_string(&log).unwrap_or_else(|_| "{}".to_owned())
}
