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
const BASELINE_RUST_UNSAFE: usize = 79;
const BASELINE_SECRET_DETECTION: usize = 17;

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

    let mut rust_unsafe = 0usize;
    let mut secret_detection = 0usize;
    for finding in &production_risk {
        match finding.get("rule_id").and_then(|v| v.as_str()) {
            Some("rust-unsafe") => rust_unsafe += 1,
            Some("secret-detection") => secret_detection += 1,
            _ => {}
        }
    }

    assert!(
        rust_unsafe <= BASELINE_RUST_UNSAFE,
        "audit baseline: rust-unsafe production findings went from {BASELINE_RUST_UNSAFE} to {rust_unsafe}. \
         If this is intentional, update BASELINE_RUST_UNSAFE and document the reason."
    );
    assert!(
        secret_detection <= BASELINE_SECRET_DETECTION,
        "audit baseline: secret-detection production findings went from {BASELINE_SECRET_DETECTION} to {secret_detection}. \
         If this is intentional, update BASELINE_SECRET_DETECTION and document the reason."
    );
}
