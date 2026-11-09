/// Mitigación 04 (baseline) — audit findings baseline.
///
/// Records the current count of production-context findings by rule.
/// A regression (increase) triggers the test; a reduction is allowed and
/// requires updating this baseline.
mod common;
use common::TestMcpClient;

/// Baseline captured 2026-08-18 for the NexusIntelliCore repository at HEAD.
///
/// Update these values only when the resolver, detectors, or the codebase
/// change legitimately. Each increase requires a comment in the PR
/// explaining the new finding.
/// Baseline updated for code formatting adjustment in state and watcher modules.
///
/// SAST v2 Fase 0: the former `rust-unsafe` bucket (92) was entirely
/// `unwrap()`/`expect()` calls mislabeled as unsafe blocks. It is now split into
/// `rust-unsafe-code-*` (real `unsafe`, forbidden by `unsafe_code = "forbid"`)
/// and `rust-uncaught-panic-unwrap`.
const BASELINE_RUST_UNSAFE_CODE: usize = 0;
const BASELINE_RUST_PANIC_UNWRAP: usize = 91;
/// SAST v2 Fase 2: the taint engine must not flag the server's own code.
const BASELINE_TAINT: usize = 0;
const BASELINE_SECRET_DETECTION: usize = 16;

fn extract_json_summary(text: &str) -> serde_json::Value {
    let start = text.find("```json\n").map(|i| i + 8);
    let end = start.and_then(|s| text[s..].find("\n```").map(|i| s + i));
    if let (Some(s), Some(e)) = (start, end) {
        serde_json::from_str(&text[s..e]).unwrap_or_default()
    } else {
        serde_json::Value::Null
    }
}

#[test]
fn audit_production_baseline_is_not_exceeded() {
    let root = env!("CARGO_MANIFEST_DIR");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": { "name": "audit_security_measures", "arguments": {} }
    })
    .to_string();

    let response = TestMcpClient::new(root).call(&request);
    let v: serde_json::Value = serde_json::from_str(&response).unwrap_or_default();
    let text = v
        .pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let summary = extract_json_summary(text);

    let production_risk = summary
        .get("production_risk")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = |pred: &dyn Fn(&str) -> bool| {
        production_risk
            .iter()
            .filter_map(|f| f.get("rule_id").and_then(|v| v.as_str()))
            .filter(|id| pred(id))
            .count()
    };
    let checks = [
        (
            "rust-unsafe-code-*",
            count(&|id| id.starts_with("rust-unsafe-code-")),
            BASELINE_RUST_UNSAFE_CODE,
            "BASELINE_RUST_UNSAFE_CODE",
        ),
        (
            "rust-uncaught-panic-unwrap",
            count(&|id| id == "rust-uncaught-panic-unwrap"),
            BASELINE_RUST_PANIC_UNWRAP,
            "BASELINE_RUST_PANIC_UNWRAP",
        ),
        (
            "*-taint",
            count(&|id| id.ends_with("-taint")),
            BASELINE_TAINT,
            "BASELINE_TAINT",
        ),
        (
            "any-hardcoded-secret",
            count(&|id| id == "any-hardcoded-secret"),
            BASELINE_SECRET_DETECTION,
            "BASELINE_SECRET_DETECTION",
        ),
    ];
    for (rule, actual, baseline, constant) in checks {
        assert!(
            actual <= baseline,
            "audit baseline: {rule} production findings went from {baseline} to {actual}. \
             If this is intentional, update {constant} and document the reason."
        );
    }
}
