use anyhow::Result;
use serde_json::Value;
use std::fmt::Write as _;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};
use crate::sanitizer;

#[allow(clippy::too_many_lines)] // Security audit aggregates multiple categories; splitting would lose co-location
#[allow(clippy::items_after_statements)] // Report struct is local to this function for encapsulation
pub(super) async fn audit_security_measures(state: &crate::state::ServerState) -> Result<Value> {
    let index = state.index().await?;

    #[derive(Default)]
    struct Report {
        secrets: Vec<String>,              // (file, line, secret_type) — NO values
        unsafe_blocks: Vec<String>,        // Rust unsafe (AST-based)
        eval_calls: Vec<String>,           // Python/JS eval/exec (AST-based)
        insecure_assignments: Vec<String>, // Dangerous assignments (AST-based)
        sql_risks: Vec<String>,            // potential SQL injection (text heuristic)
    }

    let mut report = Report::default();
    let allowed_files = index.allowed_files.clone();
    let restricted_len = index.restricted_files.len();
    drop(index);

    for file in &allowed_files {
        let Ok(path) = state.validate_path(file) else {
            continue;
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        // Read the file in a spawn_blocking block to avoid blocking the event loop
        let path_clone = path.clone();
        let Ok(source) =
            tokio::task::spawn_blocking(move || std::fs::read_to_string(&path_clone)).await?
        else {
            continue;
        };

        // 4.1 — secret detection (report location, NEVER the value)
        for (secret_type, line) in sanitizer::detect_all_secrets(&source) {
            report.secrets.push(format!(
                "  ⚠ [{secret_type}] detected in {rel} at line {line}"
            ));
        }

        // 4.2 — AST-based structural analysis for unsafe code and eval calls.
        // Using tree-sitter queries prevents false positives from occurrences
        // inside comments or string literals.
        let Some(grammar) = analyzer::detect_grammar(&path) else {
            continue;
        };
        for finding in analyzer::audit_file_ast(&source, grammar) {
            match finding.kind {
                analyzer::AuditFindingKind::UnsafeCode => {
                    report.unsafe_blocks.push(format!(
                        "  ⚠ {} in {rel} at line {}",
                        finding.description, finding.line
                    ));
                }
                analyzer::AuditFindingKind::DynamicExecution => {
                    report.eval_calls.push(format!(
                        "  ⚠ {} in {rel} at line {}",
                        finding.description, finding.line
                    ));
                }
                analyzer::AuditFindingKind::InsecureAssignment => {
                    report.insecure_assignments.push(format!(
                        "  ⚠ {} in {rel} at line {}",
                        finding.description, finding.line
                    ));
                }
            }
        }

        // 4.3 — SQL injection heuristic (text-based; structural AST queries
        // for SQL would require language-specific string-interpolation patterns
        // that are not yet supported by the tree-sitter grammars in use).
        for (lineno, line) in source.lines().enumerate() {
            let lineno = lineno + 1;
            let lower = line.to_lowercase();
            if (lower.contains("select ") || lower.contains("insert ") || lower.contains("delete "))
                && (line.contains('+') || line.contains("format!") || line.contains("concat"))
            {
                report.sql_risks.push(format!(
                    "  ⚠ Potential SQL injection via string concatenation in {rel} at line {lineno}"
                ));
            }
        }
    }

    let mut out = String::from("# Security Audit Report\n\n");

    let _ = write!(
        out,
        "Files scanned: {}\nRestricted files (not scanned): {}\n\n",
        allowed_files.len(),
        restricted_len
    );

    // Secrets section
    out.push_str("## Hardcoded Secrets\n");
    if report.secrets.is_empty() {
        out.push_str("  ✓ No hardcoded secrets detected.\n");
    } else {
        out.push_str("  NOTE: Secret values are NEVER included in this report. Only type and location are shown.\n");
        for s in &report.secrets {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // Unsafe code
    out.push_str("## Unsafe Code Blocks (Rust)\n");
    if report.unsafe_blocks.is_empty() {
        out.push_str("  ✓ No unsafe blocks detected.\n");
    } else {
        for s in &report.unsafe_blocks {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // eval/exec
    out.push_str("## Dynamic Code Execution (eval/exec)\n");
    if report.eval_calls.is_empty() {
        out.push_str("  ✓ No eval/exec calls detected.\n");
    } else {
        for s in &report.eval_calls {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // insecure assignments
    out.push_str("## Insecure Assignments\n");
    if report.insecure_assignments.is_empty() {
        out.push_str("  ✓ No insecure assignments detected.\n");
    } else {
        for s in &report.insecure_assignments {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push('\n');

    // SQL injection
    out.push_str("## SQL Injection Risks\n");
    if report.sql_risks.is_empty() {
        out.push_str("  ✓ No SQL injection patterns detected.\n");
    } else {
        for s in &report.sql_risks {
            out.push_str(s);
            out.push('\n');
        }
    }

    // Summary
    let total_issues = report.secrets.len()
        + report.unsafe_blocks.len()
        + report.eval_calls.len()
        + report.insecure_assignments.len()
        + report.sql_risks.len();
    let _ = write!(out, "\n## Summary\nTotal issues found: {total_issues}\n");

    // Sanitize security report through Privacy Gateway (extra validation layer)
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_report, _redactions) = privacy_gateway::sanitize_security_report(&out, &policy);

    let sanitized_report = format!(
        "[Think like a security auditor: reason about risk, trust boundaries, and attack surface.]\n{sanitized_report}"
    );

    Ok(tool_response(vec![text_content(sanitized_report)]))
}
