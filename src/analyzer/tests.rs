#![allow(clippy::similar_names)]
use super::audit::audit_file_ast;
use super::css::parse_css_file;
use super::docs::{extract_module_doc, extract_preceding_comment};
use super::entrypoints::detect_entrypoints;
use super::functions::extract_signature;
use super::html::{is_angular_component, parse_html_file};
use super::imports::classify_import_kind_from_path;
use super::lang::{detect_grammar, LanguageGrammar, LANGUAGE_REGISTRY};
use super::parse::analyze_file;
use super::types::{
    AuditFindingKind, EntrypointKind, FileAnalysis, FunctionInfo, ImportInfo, ImportKind,
    UseCaseConfidence,
};
use super::use_cases::infer_use_cases;
use std::collections::HashSet;
use std::path::Path;

fn grammar(path: &str) -> &'static dyn LanguageGrammar {
    detect_grammar(Path::new(path)).expect("grammar should be detected")
}

#[test]
fn test_css_detect_language() {
    assert_eq!(grammar("foo.css").name(), "css");
    assert_eq!(grammar("foo.scss").name(), "scss");
    assert_eq!(grammar("foo.html").name(), "html");
    assert_eq!(grammar("foo.htm").name(), "html");
}

#[test]
fn test_parse_css_basic() {
    let source = ".btn { color: red; background: blue; }\n.container { padding: 16px; }";
    let result = parse_css_file(source).expect("CSS parse failed");
    assert_eq!(result.language, "css");
    let rules = result.css_rules.unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].selector, ".btn");
    assert!(rules[0].properties.contains(&"color".to_owned()));
    assert!(rules[0].properties.contains(&"background".to_owned()));
    assert_eq!(rules[1].selector, ".container");
}

#[test]
fn test_parse_css_media_query() {
    let source = "@media (max-width: 768px) { .hero { display: none; } }";
    let result = parse_css_file(source).expect("CSS media parse failed");
    let rules = result.css_rules.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].selector, ".hero");
    assert!(rules[0].media_query.is_some());
}

#[test]
fn test_parse_html_basic() {
    let source = r#"<div class="hero-container"><button (click)="save()">Save</button></div>"#;
    let result = parse_html_file(source).expect("HTML parse failed");
    assert_eq!(result.language, "html");
    let elements = result.html_elements.unwrap();
    let div = elements
        .iter()
        .find(|e| e.tag_name == "div")
        .expect("No div");
    assert!(div.class_names.contains(&"hero-container".to_owned()));
    let btn = elements
        .iter()
        .find(|e| e.tag_name == "button")
        .expect("No button");
    assert!(btn.output_bindings.contains(&"click".to_owned()));
}

#[test]
fn test_html_angular_component_detection() {
    let source = r#"<app-header [title]="pageTitle"></app-header>"#;
    let result = parse_html_file(source).expect("HTML parse failed");
    let elements = result.html_elements.unwrap();
    let comp = elements.iter().find(|e| e.tag_name == "app-header");
    assert!(comp.is_some(), "app-header not found");
    let comp = comp.unwrap();
    assert!(comp.is_angular_component);
    assert!(comp.input_bindings.contains(&"title".to_owned()));
}

#[test]
fn test_is_angular_component() {
    assert!(is_angular_component("app-header"));
    assert!(is_angular_component("my-custom-element"));
    assert!(!is_angular_component("div"));
    assert!(!is_angular_component("font-face")); // SVG built-in
}

#[test]
fn test_scss_returns_empty_analysis() {
    // SCSS files are detected but not parsed — we just record the language
    assert_eq!(grammar("app.scss").name(), "scss");
}

#[test]
fn test_language_registry_has_unique_extensions() {
    let mut seen = HashSet::new();
    for grammar in LANGUAGE_REGISTRY.iter() {
        for ext in grammar.extensions() {
            let inserted = seen.insert(*ext);
            assert!(
                inserted,
                "duplicate extension '{}' found in LANGUAGE_REGISTRY (grammar: {})",
                ext,
                grammar.name()
            );
        }
    }
}

#[test]
fn test_detect_grammar_resolves_each_registered_language() {
    for grammar in LANGUAGE_REGISTRY.iter() {
        let ext = grammar
            .extensions()
            .first()
            .copied()
            .expect("each grammar must declare at least one extension");
        let fake_path = format!("sample.{ext}");
        let detected = detect_grammar(Path::new(&fake_path))
            .expect("detect_grammar should resolve known extension");
        assert_eq!(
            detected.name(),
            grammar.name(),
            "detect_grammar mismatch for extension '{ext}'"
        );
    }
}

// -----------------------------------------------------------------------
// Tests for get_module_summary helpers
// -----------------------------------------------------------------------

#[test]
fn test_extract_preceding_comment_rust_triple_slash() {
    let src =
        "/// Initialises the server.\n/// Returns an error if root is invalid.\npub fn init() {}";
    let lines: Vec<&str> = src.lines().collect();
    // fn is on line 3 (1-based)
    let doc = extract_preceding_comment(&lines, 3);
    assert!(doc.is_some());
    let doc = doc.unwrap();
    assert!(doc.contains("Initialises the server."));
    assert!(doc.contains("Returns an error"));
}

#[test]
fn test_extract_preceding_comment_none_when_no_comment() {
    let src = "\npub fn foo() {}";
    let lines: Vec<&str> = src.lines().collect();
    // fn is on line 2, but line 1 is blank → no comment
    let doc = extract_preceding_comment(&lines, 2);
    assert!(doc.is_none());
}

#[test]
fn test_extract_preceding_comment_on_first_line() {
    let src = "pub fn foo() {}";
    let lines: Vec<&str> = src.lines().collect();
    // before_line = 1 → nothing above it
    let doc = extract_preceding_comment(&lines, 1);
    assert!(doc.is_none());
}

#[test]
fn test_extract_preceding_comment_python_hash() {
    let src = "# Compute the checksum.\ndef checksum(data):\n    pass";
    let lines: Vec<&str> = src.lines().collect();
    let doc = extract_preceding_comment(&lines, 2);
    assert!(doc.is_some());
    assert!(doc.unwrap().contains("Compute the checksum"));
}

#[test]
fn test_extract_preceding_comment_java_block() {
    let src = "/**\n * Parses the request body.\n */\npublic void parse() {}";
    let lines: Vec<&str> = src.lines().collect();
    let doc = extract_preceding_comment(&lines, 4);
    assert!(doc.is_some());
    let doc = doc.unwrap();
    assert!(doc.contains("/**"));
    assert!(doc.contains("Parses the request body."));
}

#[test]
fn test_extract_module_doc_rust() {
    let src = "//! Top-level module doc.\n//! More info.\n\nuse std::io;";
    let doc = extract_module_doc(src, grammar("lib.rs"));
    assert!(doc.is_some());
    let doc = doc.unwrap();
    assert!(doc.contains("Top-level module doc."));
    assert!(doc.contains("More info."));
}

#[test]
fn test_extract_module_doc_rust_no_inner_doc() {
    let src = "// Regular comment\npub fn foo() {}";
    let doc = extract_module_doc(src, grammar("lib.rs"));
    assert!(doc.is_none());
}

#[test]
fn test_extract_module_doc_python_triple_quote() {
    let src = "\"\"\"\nThis module handles authentication.\n\"\"\"\n\ndef login(): pass";
    let doc = extract_module_doc(src, grammar("module.py"));
    assert!(doc.is_some());
    assert!(doc.unwrap().contains("authentication"));
}

#[test]
fn test_extract_module_doc_python_single_line() {
    let src = "\"\"\"Short module doc.\"\"\"\ndef foo(): pass";
    let doc = extract_module_doc(src, grammar("module.py"));
    assert!(doc.is_some());
    assert!(doc.unwrap().contains("Short module doc."));
}

#[test]
fn test_is_public_fn_rust() {
    let lang = grammar("main.rs");
    assert!(lang.is_public_fn("pub fn dispatch()", "dispatch"));
    assert!(!lang.is_public_fn("fn internal()", "internal"));
    assert!(lang.is_public_fn("pub(crate) fn semi()", "semi"));
}

#[test]
fn test_is_public_fn_python_underscore() {
    let lang = grammar("module.py");
    assert!(lang.is_public_fn("def process(data):", "process"));
    assert!(!lang.is_public_fn("def _helper():", "_helper"));
    assert!(!lang.is_public_fn("def __init__(self):", "__init__"));
}

#[test]
fn test_is_public_fn_java() {
    let lang = grammar("Service.java");
    assert!(lang.is_public_fn("public void serve()", "serve"));
    assert!(!lang.is_public_fn("private void serve()", "serve"));
    assert!(!lang.is_public_fn("protected void serve()", "serve"));
}

#[test]
fn test_is_public_class_rust() {
    let lang = grammar("lib.rs");
    let lines = ["pub struct Config {", "    field: u32,", "}"];
    assert!(lang.is_public_class(lines[0], "Config"));

    let lines2 = ["struct Internal {", "}"];
    assert!(!lang.is_public_class(lines2[0], "Internal"));
}

#[test]
fn test_extract_preceding_comment_stops_at_blank_line() {
    let src = "/// Old comment\n\n/// Real doc.\nfn foo() {}";
    let lines: Vec<&str> = src.lines().collect();
    let doc = extract_preceding_comment(&lines, 4);
    assert!(doc.is_some());
    let doc = doc.unwrap();
    assert!(!doc.contains("Old comment"));
    assert!(doc.contains("Real doc."));
}

// --- detect_entrypoints tests ---

fn make_analysis(
    language: &str,
    functions: Vec<FunctionInfo>,
    imports: Vec<ImportInfo>,
) -> FileAnalysis {
    FileAnalysis {
        language: language.to_owned(),
        functions,
        imports,
        ..Default::default()
    }
}

fn make_fn(name: &str, is_public: bool) -> FunctionInfo {
    FunctionInfo {
        name: name.to_owned(),
        qualified_name: name.to_owned(),
        owner_chain: None,
        signature: format!("pub fn {name}()"),
        normalized_signature: Some(format!("pub fn {name}()")),
        body_source: String::new(),
        start_line: 1,
        end_line: 3,
        is_strip_marked: false,
        body_byte_range: None,
        doc_comment: None,
        is_public,
    }
}

fn make_import(path: &str) -> ImportInfo {
    ImportInfo {
        raw: path.to_owned(),
        path: path.to_owned(),
        kind: ImportKind::ExternalLibrary,
        resolved_path: None,
    }
}

#[test]
fn test_detect_main_function_rust() {
    use std::path::PathBuf;
    let analysis = make_analysis("rust", vec![make_fn("main", false)], vec![]);
    let analyses = vec![(PathBuf::from("src/main.rs"), analysis)];
    let entrypoints = detect_entrypoints(&analyses);
    assert_eq!(entrypoints.len(), 1);
    assert_eq!(entrypoints[0].kind, EntrypointKind::MainFunction);
    assert_eq!(entrypoints[0].symbol, Some("main".to_owned()));
}

#[test]
fn test_detect_clap_from_imports() {
    use std::path::PathBuf;
    let analysis = make_analysis(
        "rust",
        vec![make_fn("run", true)],
        vec![make_import("clap::Parser")],
    );
    let analyses = vec![(PathBuf::from("src/cli.rs"), analysis)];
    let entrypoints = detect_entrypoints(&analyses);
    assert!(entrypoints
        .iter()
        .any(|e| matches!(&e.kind, EntrypointKind::CliFramework(n) if n == "clap")));
}

#[test]
fn test_detect_http_framework_from_imports() {
    use std::path::PathBuf;
    let analysis = make_analysis(
        "rust",
        vec![make_fn("serve", true)],
        vec![make_import("axum::Router")],
    );
    let analyses = vec![(PathBuf::from("src/server.rs"), analysis)];
    let entrypoints = detect_entrypoints(&analyses);
    assert!(entrypoints
        .iter()
        .any(|e| matches!(&e.kind, EntrypointKind::HttpFramework(n) if n == "axum")));
}

#[test]
fn test_detect_library_crate_no_main() {
    use std::path::PathBuf;
    let analysis = make_analysis("rust", vec![make_fn("parse_config", true)], vec![]);
    let analyses = vec![(PathBuf::from("src/lib.rs"), analysis)];
    let entrypoints = detect_entrypoints(&analyses);
    assert_eq!(entrypoints.len(), 1);
    assert_eq!(entrypoints[0].kind, EntrypointKind::LibraryCrate);
}

#[test]
fn test_detect_nothing_when_no_signals() {
    use std::path::PathBuf;
    let analysis = make_analysis("rust", vec![make_fn("internal_helper", false)], vec![]);
    let analyses = vec![(PathBuf::from("src/lib.rs"), analysis)];
    let entrypoints = detect_entrypoints(&analyses);
    assert!(entrypoints.is_empty());
}

// --- infer_use_cases tests ---

fn make_fn_with_doc(name: &str, doc: &str) -> FunctionInfo {
    let mut f = make_fn(name, true);
    f.doc_comment = Some(doc.to_owned());
    f
}

#[test]
fn test_infer_use_case_from_doc_comment_verb() {
    use std::path::PathBuf;
    let analysis = make_analysis(
        "rust",
        vec![make_fn_with_doc(
            "send_notification",
            "/// allows sending push notifications to registered users",
        )],
        vec![],
    );
    let analyses = vec![(PathBuf::from("src/notif.rs"), analysis)];
    let cases = infer_use_cases(&analyses);
    assert!(!cases.is_empty());
    assert_eq!(cases[0].confidence, UseCaseConfidence::High);
    assert!(cases[0].description.contains("allows"));
}

#[test]
fn test_group_by_function_name_prefix() {
    use std::path::PathBuf;
    let analysis = make_analysis(
        "rust",
        vec![
            make_fn("parse_json", true),
            make_fn("parse_yaml", true),
            make_fn("parse_toml", true),
        ],
        vec![],
    );
    let analyses = vec![(PathBuf::from("src/parser.rs"), analysis)];
    let cases = infer_use_cases(&analyses);
    assert!(!cases.is_empty());
    let parsing_case = cases
        .iter()
        .find(|c| c.title.contains("Parsing") || c.description.contains("parsing"));
    assert!(parsing_case.is_some());
    assert_eq!(parsing_case.unwrap().confidence, UseCaseConfidence::Medium);
}

#[test]
fn test_no_use_cases_when_data_insufficient() {
    use std::path::PathBuf;
    let analysis = make_analysis("rust", vec![make_fn("do_something", true)], vec![]);
    let analyses = vec![(PathBuf::from("src/lib.rs"), analysis)];
    let cases = infer_use_cases(&analyses);
    assert!(cases.is_empty());
}

#[test]
fn test_high_confidence_beats_medium_for_same_function() {
    use std::path::PathBuf;
    let analysis = make_analysis(
        "rust",
        vec![
            make_fn_with_doc(
                "parse_config",
                "/// allows parsing TOML configuration files",
            ),
            make_fn("parse_yaml", true),
        ],
        vec![],
    );
    let analyses = vec![(PathBuf::from("src/config.rs"), analysis)];
    let cases = infer_use_cases(&analyses);
    assert_eq!(cases[0].confidence, UseCaseConfidence::High);
}

// --- PR1 regression tests ---

#[test]
fn pr1_mcp_strip_in_string_literal_is_not_a_false_positive() {
    let dir = std::env::temp_dir();
    let path = dir.join("pr1_test_string_literal.rs");
    std::fs::write(
        &path,
        "pub fn display_hint() {\n    let msg = \"use // @mcp-strip to hide a body\";\n    println!(\"{}\", msg);\n}\n",
    )
    .unwrap();
    let analysis = analyze_file(&path).expect("analyze_file failed");
    let f = analysis
        .functions
        .iter()
        .find(|f| f.name == "display_hint")
        .expect("Function not found");
    assert!(
        !f.is_strip_marked,
        "@mcp-strip inside a string literal must NOT set is_strip_marked. Got: true"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pr1_body_byte_range_correct_with_generic_signature() {
    let dir = std::env::temp_dir();
    let path = dir.join("pr1_test_generic.rs");
    std::fs::write(
        &path,
        "pub fn transform<K, V>(map: std::collections::HashMap<K, V>) -> Vec<K>\nwhere\n    K: Clone,\n{\n    // @mcp-strip\n    vec![]\n}\n",
    )
    .unwrap();
    let analysis = analyze_file(&path).expect("analyze_file failed");
    let f = analysis
        .functions
        .iter()
        .find(|f| f.name == "transform")
        .expect("Function not found");
    assert!(f.is_strip_marked, "Function must be strip-marked via AST");
    assert!(
        f.body_byte_range.is_some(),
        "body_byte_range must be populated for a Rust function"
    );
    let (start, end) = f.body_byte_range.unwrap();
    let stripped = crate::sanitizer::strip_body_by_range(
        &f.body_source,
        (start, end),
        "rust",
        crate::sanitizer::DEFAULT_STRIP_PLACEHOLDER,
    );
    assert!(
        stripped.contains("HashMap"),
        "Generic type in signature must survive stripping. Got: {stripped}"
    );
    assert!(
        !stripped.contains("vec![]"),
        "Body implementation must be hidden after stripping. Got: {stripped}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pr1_python_first_body_comment_sets_strip_marked() {
    let dir = std::env::temp_dir();
    let path = dir.join("pr1_test_python.py");
    std::fs::write(
        &path,
        "def secret_fn():\n    # @mcp-strip\n    return 'classified'\n",
    )
    .unwrap();
    let analysis = analyze_file(&path).expect("analyze_file failed");
    let f = analysis
        .functions
        .iter()
        .find(|f| f.name == "secret_fn")
        .expect("Python function not found");
    assert!(
        f.is_strip_marked,
        "Python function with # @mcp-strip as first body comment must be strip-marked"
    );
    assert!(
        f.body_byte_range.is_some(),
        "body_byte_range must be populated for Python using AST block ranges"
    );

    let (start, end) = f.body_byte_range.unwrap();
    let stripped = crate::sanitizer::strip_body_by_range(
        &f.body_source,
        (start, end),
        "python",
        crate::sanitizer::DEFAULT_STRIP_PLACEHOLDER,
    );
    assert!(!stripped.contains("classified"));
    let _ = std::fs::remove_file(&path);
}

// --- PR2 regression tests ---

#[test]
fn pr2_rust_external_crate_is_external_library() {
    let dir = std::env::temp_dir();
    let path = dir.join("pr2_test_external.rs");
    std::fs::write(
        &path,
        "use serde;\nuse serde_json::Value;\n\nfn noop() {}\n",
    )
    .unwrap();
    let analysis = analyze_file(&path).expect("analyze_file failed");
    for imp in &analysis.imports {
        assert_eq!(
            imp.kind,
            ImportKind::ExternalLibrary,
            "Rust crate '{}' must be ExternalLibrary, not {:?}",
            imp.path,
            imp.kind
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pr2_rust_crate_self_super_are_internal_local() {
    let dir = std::env::temp_dir();
    let path = dir.join("pr2_test_internal.rs");
    std::fs::write(
        &path,
        "use crate::analyzer;\nuse self::foo;\nuse super::bar;\n\nfn noop() {}\n",
    )
    .unwrap();
    let analysis = analyze_file(&path).expect("analyze_file failed");
    for imp in &analysis.imports {
        assert_eq!(
            imp.kind,
            ImportKind::InternalLocal,
            "Rust import '{}' must be InternalLocal, not {:?}",
            imp.path,
            imp.kind
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pr2_js_relative_imports_are_internal_local() {
    assert_eq!(
        classify_import_kind_from_path("./utils", "javascript"),
        ImportKind::InternalLocal
    );
    assert_eq!(
        classify_import_kind_from_path("../lib/helper", "javascript"),
        ImportKind::InternalLocal
    );
}

#[test]
fn pr2_angular_package_import_is_external_library() {
    assert_eq!(
        classify_import_kind_from_path("@angular/core", "javascript"),
        ImportKind::ExternalLibrary
    );
    assert_eq!(
        classify_import_kind_from_path("@angular/common/http", "javascript"),
        ImportKind::ExternalLibrary
    );
}

// --- PR4 AST-based audit tests ---

#[test]
fn pr4_unsafe_in_comment_is_not_a_false_positive() {
    let source = r"
fn safe_function() {
    // Previously this code used unsafe { ptr.write(0) } — now it's safe.
    let x = 42;
    let _ = x;
}
";
    let findings = audit_file_ast(source, grammar("lib.rs"));
    let unsafe_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == AuditFindingKind::UnsafeCode)
        .collect();
    assert!(
        unsafe_findings.is_empty(),
        "expected no UnsafeCode findings from a comment, got: {unsafe_findings:?}"
    );
}

#[test]
fn pr4_multiline_unsafe_block_is_detected() {
    let source = r"
fn raw_write(ptr: *mut u8, val: u8) {
    unsafe
    {
        *ptr = val;
    }
}
";
    let findings = audit_file_ast(source, grammar("lib.rs"));
    let unsafe_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == AuditFindingKind::UnsafeCode)
        .collect();
    assert!(
        !unsafe_findings.is_empty(),
        "expected at least one UnsafeCode finding for a real unsafe block"
    );
}

#[test]
fn pr4_python_eval_call_generates_finding() {
    let source = r"
def run_user_code(user_input):
    result = eval(user_input)
    return result
";
    let findings = audit_file_ast(source, grammar("module.py"));
    let eval_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == AuditFindingKind::DynamicExecution)
        .collect();
    assert!(
        !eval_findings.is_empty(),
        "expected a DynamicExecution finding for eval() call"
    );
}

#[test]
fn pr4_javascript_new_function_and_eval_generate_dynamic_execution_findings() {
    let source = r#"
function buildRunner(code) {
    const runner = new Function(code);
    return eval(code) + runner();
}
"#;
    let findings = audit_file_ast(source, grammar("module.js"));
    let dynamic_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == AuditFindingKind::DynamicExecution)
        .collect();

    assert!(
        dynamic_findings
            .iter()
            .any(|f| f.description.contains("new Function") && f.line == 3),
        "expected new Function() finding at line 3, got: {dynamic_findings:?}"
    );
    assert!(
        dynamic_findings
            .iter()
            .any(|f| f.description.contains("eval") && f.line == 4),
        "expected eval() finding at line 4, got: {dynamic_findings:?}"
    );
}

#[test]
fn pr4_typescript_inner_html_assignment_generates_insecure_assignment_finding() {
    let source = r#"
function render(raw: string, node: HTMLElement) {
    node.innerHTML = raw;
}
"#;
    let findings = audit_file_ast(source, grammar("component.ts"));
    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == AuditFindingKind::InsecureAssignment)
        .collect();

    assert!(
        sink_findings
            .iter()
            .any(|f| f.description.contains("innerHTML") && f.line == 3),
        "expected innerHTML assignment finding at line 3, got: {sink_findings:?}"
    );
}

#[test]
fn pr4_python_subprocess_shell_true_generates_dynamic_execution_finding() {
    let source = r#"
import subprocess

def run(user_input):
    return subprocess.Popen(user_input, shell=True)
"#;
    let findings = audit_file_ast(source, grammar("module.py"));
    let dynamic_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == AuditFindingKind::DynamicExecution)
        .collect();

    assert!(
        dynamic_findings
            .iter()
            .any(|f| f.description.contains("shell=True") && f.line == 5),
        "expected subprocess shell=True finding at line 5, got: {dynamic_findings:?}"
    );
}

#[test]
fn go_ast_extracts_functions_and_structs() {
    let dir = std::env::temp_dir();
    let path = dir.join("go_ast_extracts_functions_and_structs.go");
    std::fs::write(
        &path,
        r#"package main

import "fmt"

type Service struct {}

func PublicRun() {
    fmt.Println("ok")
}
"#,
    )
    .unwrap();

    let analysis = analyze_file(&path).expect("analyze_file failed");
    assert_eq!(analysis.language, "go");
    assert!(analysis.functions.iter().any(|f| f.name == "PublicRun"));
    assert!(analysis.classes.iter().any(|c| c.name == "Service"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn kotlin_ast_extracts_functions_and_classes() {
    let dir = std::env::temp_dir();
    let path = dir.join("kotlin_ast_extracts_functions_and_classes.kt");
    std::fs::write(
        &path,
        r#"package demo

class Worker {
    fun runTask() {
        println("ok")
    }
}
"#,
    )
    .unwrap();

    let analysis = analyze_file(&path).expect("analyze_file failed");
    assert_eq!(analysis.language, "kotlin");
    assert!(analysis.functions.iter().any(|f| f.name == "runTask"));
    assert!(analysis.classes.iter().any(|c| c.name == "Worker"));

    let _ = std::fs::remove_file(&path);
}
