//! SAST v2 Fase 3 (N2b): taint summaries resolved across files, exercised
//! through the MCP `audit_security_measures` tool.
mod common;
use common::TestMcpClient;
use serde_json::{json, Value};
use std::fs;

fn summary_of(root: &str) -> Value {
    let response = TestMcpClient::new(root).call_tool("audit_security_measures", json!({}));
    let v: Value = serde_json::from_str(&response).unwrap_or_default();
    let text = v
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let start = text.find("```json\n").map(|i| i + 8);
    let end = start.and_then(|s| text[s..].find("\n```").map(|i| s + i));
    match (start, end) {
        (Some(s), Some(e)) => serde_json::from_str(&text[s..e]).unwrap_or_default(),
        _ => Value::Null,
    }
}

fn taint_findings(summary: &Value) -> Vec<(String, String)> {
    summary["production_risk"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|f| {
                    f["rule_id"]
                        .as_str()
                        .is_some_and(|id| id.ends_with("-taint"))
                })
                .map(|f| {
                    (
                        f["rule_id"].as_str().unwrap_or_default().to_owned(),
                        f["file"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn flow_crosses_files_through_a_helper() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("runner.py"),
        "import os\n\ndef run_cmd(cmd):\n    os.system(cmd)\n",
    )
    .expect("write");
    fs::write(
        dir.path().join("app.py"),
        "from flask import request\nfrom runner import run_cmd\n\ndef handler():\n    run_cmd(request.args[\"c\"])\n",
    )
    .expect("write");

    let summary = summary_of(&dir.path().to_string_lossy());
    assert_eq!(summary["taint_coverage"], "inter-procedural-summaries");
    assert_eq!(
        taint_findings(&summary),
        vec![("py-command-injection-taint".to_owned(), "app.py".to_owned())],
        "reported at the call site in app.py, not in the source-less helper: {summary}"
    );
}

#[test]
fn ambiguous_names_across_files_are_not_resolved() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("a.py"),
        "import os\n\ndef run(x):\n    os.system(x)\n",
    )
    .expect("write");
    fs::write(dir.path().join("b.py"), "def run(x):\n    print(x)\n").expect("write");
    fs::write(
        dir.path().join("app.py"),
        "from flask import request\n\ndef handler():\n    run(request.args[\"c\"])\n",
    )
    .expect("write");

    let summary = summary_of(&dir.path().to_string_lossy());
    assert!(
        taint_findings(&summary).is_empty(),
        "`run` is defined twice, so the call is not resolved: {summary}"
    );
}

#[test]
fn files_without_taint_support_do_not_break_the_summary_rounds() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("notes.md"), "# notes\n").expect("write");
    fs::write(dir.path().join("style.css"), "a { color: red }\n").expect("write");
    fs::write(
        dir.path().join("lib.rs"),
        "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
    )
    .expect("write");
    let summary = summary_of(&dir.path().to_string_lossy());
    assert!(taint_findings(&summary).is_empty());
    assert_eq!(summary["schema_version"], "3");
}
