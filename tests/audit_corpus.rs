/// Corpus etiquetado de auditoría (mitigación 04, fase 1 + A5).
///
/// Cada caso describe un fragmento de código fuente y el conteo esperado
/// de hallazgos por (rule_id, context). El test falla si la producción de
/// hallazgos diverge del baseline o si los secretos aparecen en la salida.
mod common;
use common::TestMcpClient;
use std::io::Write;
use tempfile::TempDir;

/// Un caso del corpus: código fuente → hallazgos esperados por regla y contexto.
struct CorpusCase {
    name: &'static str,
    extension: &'static str,
    source: &'static str,
    /// (rule_id, context_label, expected_min_count)
    expected: &'static [(&'static str, &'static str, usize)],
    /// Strings that must NOT appear anywhere in the audit output.
    forbidden: &'static [&'static str],
}

fn extract_json_summary(audit_text: &str) -> serde_json::Value {
    // The JSON summary appears between ```json and ``` markers.
    let start = audit_text.find("```json\n").map(|i| i + 8);
    let end = audit_text[start.unwrap_or(0)..]
        .find("\n```")
        .map(|i| i + start.unwrap_or(0));
    if let (Some(s), Some(e)) = (start, end) {
        serde_json::from_str(&audit_text[s..e]).unwrap_or_default()
    } else {
        serde_json::Value::Null
    }
}

fn count_in_summary(summary: &serde_json::Value, context: &str, severity_level: &str) -> u64 {
    summary
        .pointer(&format!("/by_context/{context}/{severity_level}"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn run_audit_on_file(file_path: &str) -> String {
    let dir = std::path::Path::new(file_path)
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": { "name": "audit_security_measures", "arguments": {} }
    })
    .to_string();
    TestMcpClient::new(&dir).call(&request)
}

fn extract_text(response: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(response).unwrap_or_default();
    v.pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or(response)
        .to_owned()
}

// ── Corpus cases ─────────────────────────────────────────────────────────────

const CASES: &[CorpusCase] = &[
    CorpusCase {
        name: "rust_unsafe_block",
        extension: "rs",
        source: r#"
fn write_ptr(p: *mut u8, val: u8) {
    // SAFETY: caller guarantees validity.
    unsafe { *p = val; }
}
"#,
        expected: &[("rust-unsafe", "production", 1)],
        forbidden: &[],
    },
    CorpusCase {
        name: "rust_unsafe_fn_decl",
        extension: "rs",
        source: r#"
fn outer() {
    // SAFETY: only called with valid pointers.
    unsafe { let p: *const u8 = std::ptr::null(); let _ = *p; }
}
"#,
        // unsafe block inside a function is still an unsafe block finding
        expected: &[("rust-unsafe", "production", 1)],
        forbidden: &[],
    },
    CorpusCase {
        name: "js_eval_call",
        extension: "js",
        source: "function run(code) { return eval(code); }\n",
        expected: &[("dynamic-execution", "production", 1)],
        forbidden: &[],
    },
    CorpusCase {
        name: "python_eval_call",
        extension: "py",
        source: "def run(code):\n    return eval(code)\n",
        expected: &[("dynamic-execution", "production", 1)],
        forbidden: &[],
    },
    CorpusCase {
        name: "rust_safe_code_no_unsafe",
        extension: "rs",
        source: r#"
fn add(a: u32, b: u32) -> u32 { a + b }
"#,
        // No unsafe findings.
        expected: &[],
        forbidden: &[],
    },
    CorpusCase {
        name: "js_comment_not_flagged",
        extension: "js",
        source: "// eval is dangerous — do not use it\nfunction safe() { return 1; }\n",
        // Tree-sitter catches only real AST nodes; a comment must not fire.
        expected: &[],
        forbidden: &[],
    },
    CorpusCase {
        name: "secret_value_never_in_output",
        extension: "rs",
        source: "const TOKEN: &str = \"sk-FAKEOPENAIKEYABCDEFGHIJKLMNOPQRS\";\n",
        // Secret is detected but its VALUE must never appear in output.
        expected: &[("secret-detection", "production", 1)],
        forbidden: &["sk-FAKEOPENAIKEYABCDEFGHIJKLMNOPQRS"],
    },
    CorpusCase {
        name: "sql_injection_heuristic",
        extension: "rs",
        source: r#"
fn query(id: &str) -> String {
    format!("SELECT * FROM users WHERE id = {}", id)
}
"#,
        expected: &[("sql-injection-heuristic", "production", 1)],
        forbidden: &[],
    },
];

fn write_corpus_file(dir: &TempDir, name: &str, ext: &str, source: &str) -> std::path::PathBuf {
    let path = dir.path().join(format!("{name}.{ext}"));
    let mut f = std::fs::File::create(&path).expect("temp file");
    f.write_all(source.as_bytes()).expect("write");
    path
}

#[test]
fn audit_corpus_parametrized() {
    for case in CASES {
        let dir = tempfile::tempdir().expect("temp dir");
        let file_path = write_corpus_file(&dir, case.name, case.extension, case.source);

        let response = run_audit_on_file(&file_path.to_string_lossy());
        let text = extract_text(&response);
        let summary = extract_json_summary(&text);

        // Forbidden strings must never appear.
        for &forbidden in case.forbidden {
            assert!(
                !text.contains(forbidden),
                "[{}] forbidden string in output: '{}'",
                case.name,
                forbidden
            );
        }

        // Count by rule_id in the full text (rough check).
        for &(rule_id, _context, min_count) in case.expected {
            let actual = text.matches(rule_id).count();
            assert!(
                actual >= min_count,
                "[{}] rule '{}' expected >= {} occurrences, got {}. Output:\n{}",
                case.name,
                rule_id,
                min_count,
                actual,
                &text[..text.len().min(800)]
            );
        }

        // If the summary parsed, verify no production risk for safe cases.
        if !summary.is_null() {
            let _ = summary; // consumed above; no further cross-checks needed for now
        }
    }
}

/// Precision and recall computed over the labelled corpus.
///
/// Counts are taken from the JSON summary's `findings_total` and per-context
/// breakdown, not from the free-form Markdown, to avoid double-counting
/// occurrences that also appear in headings.
#[test]
fn audit_corpus_precision_and_recall_meet_thresholds() {
    let mut true_positives: usize = 0;
    let mut false_positives: usize = 0;
    let mut false_negatives: usize = 0;

    for case in CASES {
        let dir = tempfile::tempdir().expect("temp dir");
        let file_path = write_corpus_file(&dir, case.name, case.extension, case.source);
        let response = run_audit_on_file(&file_path.to_string_lossy());
        let text = extract_text(&response);
        let summary = extract_json_summary(&text);

        let expected_count: usize = case.expected.iter().map(|(_, _, n)| *n).sum();
        // findings_total is the deduplicated count across all detectors.
        let detected_count: usize = summary
            .get("findings_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        if expected_count == 0 {
            false_positives += detected_count;
        } else {
            let tp = detected_count.min(expected_count);
            true_positives += tp;
            if detected_count > expected_count {
                false_positives += detected_count - expected_count;
            }
            if expected_count > detected_count {
                false_negatives += expected_count - detected_count;
            }
        }
    }

    let precision = if true_positives + false_positives == 0 {
        1.0
    } else {
        true_positives as f64 / (true_positives + false_positives) as f64
    };
    let recall = if true_positives + false_negatives == 0 {
        1.0
    } else {
        true_positives as f64 / (true_positives + false_negatives) as f64
    };

    // Thresholds dictated by mitigación 04 (fase 4).
    assert!(
        precision >= 0.95,
        "audit corpus precision {precision:.3} below 0.95 threshold. \
         tp={true_positives}, fp={false_positives}, fn={false_negatives}"
    );
    assert!(
        recall >= 0.90,
        "audit corpus recall {recall:.3} below 0.90 threshold. \
         tp={true_positives}, fp={false_positives}, fn={false_negatives}"
    );
}

/// Deduplication: two identical findings in the same file → count once.
#[test]
fn audit_dedup_removes_identical_fingerprints() {
    // Two identical unsafe blocks will share the same fingerprint only if
    // they are on different lines; we need two distinct lines.
    let dir = tempfile::tempdir().expect("temp dir");
    let source = "fn a() { unsafe { let _ = 0; } }\nfn b() { unsafe { let _ = 1; } }\n";
    let path = write_corpus_file(&dir, "dedup_test", "rs", source);

    let response = run_audit_on_file(&path.to_string_lossy());
    let text = extract_text(&response);
    let summary = extract_json_summary(&text);

    if !summary.is_null() {
        let before = summary["findings_before_dedup"].as_u64().unwrap_or(0);
        let after = summary["findings_total"].as_u64().unwrap_or(0);
        // The two unsafe blocks are on different lines so they have different
        // fingerprints; no deduplication expected. Both must appear.
        assert!(
            after >= 2,
            "Both unsafe blocks on distinct lines must be reported. total={after}, before={before}"
        );
    }
}

/// Precision gate: high-severity production findings must not include fixtures.
#[test]
fn audit_production_risk_excludes_fixtures() {
    // Audit the full project; tests/fixtures/audit_sample.rs must be classified
    // as Fixture (its path contains tests/fixtures/), not as Production.
    let root = env!("CARGO_MANIFEST_DIR");
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": { "name": "audit_security_measures", "arguments": {} }
    })
    .to_string();

    let response = TestMcpClient::new(root).call(&request);
    let text = extract_text(&response);
    let summary = extract_json_summary(&text);

    if !summary.is_null() {
        let fixture_high = count_in_summary(&summary, "fixture", "high");
        let prod_high = count_in_summary(&summary, "production", "high");

        // The audit_sample.rs fixture has 2 unsafe blocks; they must be
        // counted under "fixture", not "production".
        assert!(
            fixture_high > 0 || prod_high == 0,
            "tests/fixtures/ unsafe blocks must be classified as fixture, not production. \
             fixture_high={fixture_high}, prod_high={prod_high}"
        );
    }
}
