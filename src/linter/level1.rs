use std::path::Path;

use crate::analyzer::FileAnalysis;

use super::{LintDiagnostic, Severity};

pub fn run_tree_sitter_checks(path: &Path, analysis: &FileAnalysis) -> Vec<LintDiagnostic> {
    let mut diagnostics = Vec::new();
    let source = std::fs::read_to_string(path).unwrap_or_default();
    let language = analysis.language.as_str();
    let language_rules = language_rules(analysis.language.as_str());

    for (line_index, line) in source.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)] // line counts never exceed u32
        let line_number = (line_index + 1) as u32;
        for marker in ["TODO", "FIXME", "HACK"] {
            if line.contains(marker) {
                diagnostics.push(LintDiagnostic {
                    line: line_number,
                    column: 1,
                    severity: Severity::Info,
                    message: format!("{marker} found in comment or code"),
                    rule_id: Some(marker.to_lowercase()),
                    source: "tree-sitter".to_string(),
                });
                break;
            }
        }

        let scan_line = sanitized_line_for_matching(line, language);
        for rule in language_rules {
            if let Some(col_idx) = scan_line.find(rule.pattern) {
                #[allow(clippy::cast_possible_truncation)] // column counts never exceed u32
                let col_number = (col_idx + 1) as u32;
                diagnostics.push(mk_diag(
                    line_number,
                    col_number,
                    rule.message,
                    rule.rule_id,
                ));
            }
        }
    }

    diagnostics
}

#[allow(clippy::struct_field_names)] // `rule_id` is intentionally named after the struct
struct Rule {
    pattern: &'static str,
    message: &'static str,
    rule_id: &'static str,
}

fn language_rules(language: &str) -> &'static [Rule] {
    const JS_TS_RULES: &[Rule] = &[
        Rule {
            pattern: "console.log(",
            message: "console.log() detected",
            rule_id: "no-console",
        },
        Rule {
            pattern: "debugger;",
            message: "debugger statement detected",
            rule_id: "no-debugger",
        },
    ];
    const PYTHON_RULES: &[Rule] = &[
        Rule {
            pattern: "print(",
            message: "print() detected",
            rule_id: "no-print",
        },
        Rule {
            pattern: "import *",
            message: "wildcard import detected",
            rule_id: "import-star",
        },
    ];
    const JAVA_RULES: &[Rule] = &[Rule {
        pattern: "System.out.println(",
        message: "System.out.println() detected",
        rule_id: "no-system-out",
    }];
    const RUST_RULES: &[Rule] = &[
        Rule {
            pattern: "unwrap()",
            message: ".unwrap() detected",
            rule_id: "no-unwrap",
        },
        Rule {
            pattern: "dbg!(",
            message: "debug print detected",
            rule_id: "no-debug-print",
        },
        Rule {
            pattern: "println!(",
            message: "debug print detected",
            rule_id: "no-debug-print",
        },
    ];

    match language {
        "javascript" | "typescript" | "tsx" => JS_TS_RULES,
        "python" => PYTHON_RULES,
        "java" => JAVA_RULES,
        "rust" => RUST_RULES,
        _ => &[],
    }
}

fn mk_diag(line: u32, column: u32, message: &str, rule_id: &str) -> LintDiagnostic {
    LintDiagnostic {
        line,
        column,
        severity: Severity::Warning,
        message: message.to_string(),
        rule_id: Some(rule_id.to_string()),
        source: "tree-sitter".to_string(),
    }
}

fn sanitized_line_for_matching(line: &str, language: &str) -> String {
    let mut bytes = line.as_bytes().to_vec();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let mut idx = 0usize;

    while idx < bytes.len() {
        let current = bytes[idx];

        if in_single {
            bytes[idx] = b' ';
            if escape {
                escape = false;
            } else if current == b'\\' {
                escape = true;
            } else if current == b'\'' {
                in_single = false;
            }
            idx += 1;
            continue;
        }

        if in_double {
            bytes[idx] = b' ';
            if escape {
                escape = false;
            } else if current == b'\\' {
                escape = true;
            } else if current == b'"' {
                in_double = false;
            }
            idx += 1;
            continue;
        }

        if is_line_comment_start(&bytes, idx, language) {
            for byte in bytes.iter_mut().skip(idx) {
                *byte = b' ';
            }
            break;
        }

        if current == b'\'' {
            in_single = true;
            bytes[idx] = b' ';
            idx += 1;
            continue;
        }

        if current == b'"' {
            in_double = true;
            bytes[idx] = b' ';
            idx += 1;
            continue;
        }

        idx += 1;
    }

    String::from_utf8(bytes).unwrap_or_else(|_| line.to_string())
}

fn is_line_comment_start(bytes: &[u8], idx: usize, language: &str) -> bool {
    match language {
        "python" => bytes[idx] == b'#',
        "rust" | "javascript" | "typescript" | "tsx" | "java" | "c" | "csharp" => {
            idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'/'
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::analyzer::FileAnalysis;

    use super::run_tree_sitter_checks;

    fn write_temp_file(content: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nexus_lint_level1_{nanos}.rs"));
        std::fs::write(&path, content).expect("temp file should be writable");
        path
    }

    #[test]
    fn rust_debug_print_reports_real_line_and_column() {
        let source = "fn main() {\n    let x = 1;\n    println!(\"x={}\", x);\n}\n";
        let path = write_temp_file(source);

        let diagnostics = run_tree_sitter_checks(
            &path,
            &FileAnalysis {
                language: "rust".to_string(),
                ..Default::default()
            },
        );

        std::fs::remove_file(&path).ok();

        let diag = diagnostics
            .iter()
            .find(|d| d.rule_id.as_deref() == Some("no-debug-print"))
            .expect("expected no-debug-print diagnostic");

        assert_eq!(diag.line, 3);
        assert_eq!(diag.column, 5);
    }

    #[test]
    fn rust_ignores_debug_print_in_comment_and_string() {
        let source = "fn main() {\n    // println!(\"comment\");\n    let s = \"dbg!(123)\";\n}\n";
        let path = write_temp_file(source);

        let diagnostics = run_tree_sitter_checks(
            &path,
            &FileAnalysis {
                language: "rust".to_string(),
                ..Default::default()
            },
        );

        std::fs::remove_file(&path).ok();

        assert!(
            diagnostics
                .iter()
                .all(|d| d.rule_id.as_deref() != Some("no-debug-print")),
            "no-debug-print should be ignored inside comments and string literals"
        );
    }

    #[test]
    fn python_ignores_print_in_comment_and_string() {
        let source =
            "def run():\n    # print(\"comment\")\n    text = \"print(123)\"\n    return text\n";
        let path = write_temp_file(source);

        let diagnostics = run_tree_sitter_checks(
            &path,
            &FileAnalysis {
                language: "python".to_string(),
                ..Default::default()
            },
        );

        std::fs::remove_file(&path).ok();

        assert!(
            diagnostics
                .iter()
                .all(|d| d.rule_id.as_deref() != Some("no-print")),
            "no-print should be ignored inside comments and string literals"
        );
    }
}
