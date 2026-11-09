//! SAST v2 Fase 3: SARIF output, baseline adoption flow and N3 infra rules,
//! exercised end to end through the MCP `audit_security_measures` tool.
mod common;
use common::TestMcpClient;
use serde_json::{json, Value};
use std::fs;

fn text_of(response: &str) -> String {
    let v: Value = serde_json::from_str(response).unwrap_or_default();
    v.pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or(response)
        .to_owned()
}

fn audit(root: &str, format: &str) -> String {
    text_of(
        &TestMcpClient::new(root).call_tool("audit_security_measures", json!({ "format": format })),
    )
}

fn summary(markdown: &str) -> Value {
    let start = markdown.find("```json\n").map(|i| i + 8);
    let end = start.and_then(|s| markdown[s..].find("\n```").map(|i| s + i));
    match (start, end) {
        (Some(s), Some(e)) => serde_json::from_str(&markdown[s..e]).unwrap_or_default(),
        _ => Value::Null,
    }
}

const VULNERABLE_PY: &str = "import os\nfrom flask import request\n\ndef ping():\n    os.system(\"ping \" + request.args[\"host\"])\n";

#[test]
fn sarif_output_is_valid_and_carries_flows() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("app.py"), VULNERABLE_PY).expect("write");
    let root = dir.path().to_string_lossy().to_string();

    let sarif: Value =
        serde_json::from_str(&audit(&root, "sarif")).expect("SARIF must be pure JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    let taint = results
        .iter()
        .find(|r| r["ruleId"] == "py-command-injection-taint")
        .expect("taint result present");
    assert_eq!(taint["level"], "error");
    assert_eq!(
        taint["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "app.py"
    );
    assert!(
        taint["codeFlows"].is_array(),
        "taint results carry a codeFlow"
    );
    assert!(taint["partialFingerprints"]["nexusStableId/v1"]
        .as_str()
        .is_some_and(|id| id.starts_with("py-command-injection-taint:app.py:ping:")));
}

#[test]
fn baseline_accepts_existing_findings_and_reports_only_new_ones() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("app.py"), VULNERABLE_PY).expect("write");
    let root = dir.path().to_string_lossy().to_string();

    let before = summary(&audit(&root, "markdown"));
    assert_eq!(before["baseline"]["status"], "absent");
    assert!(before["production_risk"]
        .as_array()
        .is_some_and(|a| !a.is_empty()));

    // Adopt: save the generated baseline at the project root.
    let baseline = audit(&root, "baseline");
    let parsed: Value = serde_json::from_str(&baseline).expect("baseline is JSON");
    assert!(parsed["findings"].as_array().is_some_and(|a| !a.is_empty()));
    fs::write(dir.path().join("audit-baseline.json"), &baseline).expect("write baseline");

    let adopted = summary(&audit(&root, "markdown"));
    assert_eq!(adopted["baseline"]["status"], "loaded");
    assert_eq!(
        adopted["production_risk"],
        json!([]),
        "accepted debt is not production risk"
    );
    assert!(adopted["baselined_total"].as_u64().unwrap_or(0) >= 1);

    // Unrelated edits above the finding do not resurrect it; a new one shows up.
    let edited = format!(
        "# header\n\n{VULNERABLE_PY}\ndef run():\n    os.system(\"ls \" + request.args[\"dir\"])\n"
    );
    fs::write(dir.path().join("app.py"), edited).expect("write");
    let after = summary(&audit(&root, "markdown"));
    let new: Vec<&Value> = after["production_risk"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    assert_eq!(new.len(), 1, "only the new finding counts: {new:?}");
    assert_eq!(new[0]["function"], "run");
}

#[test]
fn dockerfile_rules_run_through_the_tool() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("Dockerfile"),
        "FROM node\nRUN curl -fsSL https://get.example.org | sh\nENV API_TOKEN=abc123def456\nUSER root\n",
    )
    .expect("write");
    let root = dir.path().to_string_lossy().to_string();
    let report = audit(&root, "markdown");
    for rule in [
        "docker-unpinned-base-image",
        "any-download-pipe-to-shell",
        "docker-secret-in-env",
        "docker-root-user",
    ] {
        assert!(report.contains(rule), "{rule} missing:\n{report}");
    }
    assert!(
        !report.contains("abc123def456"),
        "ENV values must never be echoed"
    );
}

#[test]
fn invalid_format_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().to_string_lossy().to_string();
    let response =
        TestMcpClient::new(&root).call_tool("audit_security_measures", json!({ "format": "xml" }));
    assert!(response.contains("Invalid format"), "{response}");
}
