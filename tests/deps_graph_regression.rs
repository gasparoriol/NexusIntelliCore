/// B2 / mitigación 03 — gate de regresión relativa para `resolution_coverage`.
///
/// Ejecuta `get_dependencies_graph` sobre el propio repositorio y compara la
/// cobertura con el baseline. Falla si la caída absoluta supera 0.02.
mod common;
use common::TestMcpClient;

/// Baseline registered on 2026-08-18 for the NexusIntelliCore repository at
/// commit HEAD. Update this constant together with the ADR when the resolver
/// evolves.
const RESOLUTION_COVERAGE_BASELINE: f64 = 0.125;

/// Maximum absolute regression tolerated per release (ADR-0003).
const RESOLUTION_COVERAGE_MAX_ABSOLUTE_DROP: f64 = 0.02;

fn extract_text(response: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(response).unwrap_or_default();
    v.pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_owned()
}

/// Extract JSON payload from the tool response text.
/// The text starts with a bracketed hint line; the JSON follows.
fn extract_graph_json(text: &str) -> serde_json::Value {
    let json_start = text.find('{').unwrap_or(0);
    serde_json::from_str(&text[json_start..]).unwrap_or_default()
}

#[test]
fn resolution_coverage_did_not_regress_beyond_threshold() {
    let root = env!("CARGO_MANIFEST_DIR");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_dependencies_graph",
            "arguments": { "mode": "summary" }
        }
    })
    .to_string();

    let response = TestMcpClient::new(root).call(&request);
    let text = extract_text(&response);
    let graph = extract_graph_json(&text);

    let coverage = graph
        .pointer("/meta/summary/statistics/resolution_coverage")
        .and_then(|v| v.as_f64())
        .expect("resolution_coverage must be present in meta.summary.statistics");

    let drop = RESOLUTION_COVERAGE_BASELINE - coverage;
    assert!(
        drop <= RESOLUTION_COVERAGE_MAX_ABSOLUTE_DROP,
        "resolution_coverage regressed by {drop:.4} (from {} to {coverage:.4}); \
         maximum tolerated drop per release is {RESOLUTION_COVERAGE_MAX_ABSOLUTE_DROP}",
        RESOLUTION_COVERAGE_BASELINE
    );
}
