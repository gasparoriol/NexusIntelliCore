use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;
use tokio::process::Command;

use super::{LintDiagnostic, LintResult, Severity};

const SOURCE_CLIPPY: &str = "clippy";
const SOURCE_ESLINT: &str = "eslint";
const SOURCE_JAVAC: &str = "javac";
const SOURCE_KTLINT: &str = "ktlint";
const SOURCE_KOTLINC: &str = "kotlinc";
const SOURCE_CPPCHECK: &str = "cppcheck";
const SOURCE_DOTNET: &str = "dotnet";
const SOURCE_MYPY: &str = "mypy";

pub async fn run_external(
    path: &Path,
    root: &Path,
    timeout: Duration,
    language: &str,
) -> Result<LintResult> {
    match language {
        "rust" => run_clippy(path, root, timeout).await,
        "javascript" | "typescript" | "tsx" => run_eslint(path, root, timeout).await,
        "python" => run_mypy(path, root, timeout).await,
        "java" => run_javac(path, root, timeout).await,
        "kotlin" => run_ktlint(path, root, timeout).await,
        "c" => run_cppcheck(path, root, timeout).await,
        "csharp" => run_dotnet_build(path, root, timeout).await,
        _ => Ok(LintResult {
            diagnostics: Vec::new(),
            sources: Vec::new(),
            error: None,
        }),
    }
}

pub fn external_unavailable_notice() -> LintDiagnostic {
    LintDiagnostic {
        line: 1,
        column: 1,
        severity: Severity::Info,
        message: "external linters are disabled or unavailable".to_string(),
        rule_id: Some("external-disabled".to_string()),
        source: "lint".to_string(),
    }
}

async fn run_clippy(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let mut cmd = Command::new("cargo");
    cmd.args(["clippy", "--message-format=json", "--quiet"])
        .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute cargo clippy")?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_CLIPPY,
            "cargo/clippy not found on PATH",
            "clippy-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_CLIPPY,
            "cargo clippy timed out",
            "clippy-timeout",
        ));
    }

    let diagnostics = parse_clippy_output(&output.stdout, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_CLIPPY.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "cargo clippy exited with status {}: {}",
                output.exit_code, output.stderr
            ))
        } else {
            None
        },
    })
}

async fn run_eslint(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let eslint_local = root.join("node_modules").join(".bin").join("eslint");
    let eslint_bin = if eslint_local.exists() {
        eslint_local
    } else {
        PathBuf::from("eslint")
    };

    let mut cmd = Command::new(&eslint_bin);
    cmd.args([
        "--format",
        "json",
        "--no-error-on-unmatched-pattern",
        &path.to_string_lossy(),
    ])
    .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .with_context(|| format!("failed to execute {}", eslint_bin.to_string_lossy()))?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_ESLINT,
            "eslint not found (global or local node_modules/.bin/eslint)",
            "eslint-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_ESLINT,
            "eslint timed out",
            "eslint-timeout",
        ));
    }

    let diagnostics = parse_eslint_output(&output.stdout, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_ESLINT.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "eslint exited with status {}: {}",
                output.exit_code, output.stderr
            ))
        } else {
            None
        },
    })
}

async fn run_mypy(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let mut cmd = Command::new("mypy");
    cmd.args([
        &path.to_string_lossy(),
        "--show-column-numbers",
        "--show-error-codes",
        "--hide-error-context",
        "--no-color-output",
        "--no-error-summary",
    ])
    .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute mypy")?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_MYPY,
            "mypy not found on PATH",
            "mypy-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(SOURCE_MYPY, "mypy timed out", "mypy-timeout"));
    }

    let diagnostics = parse_mypy_output(&output.stdout, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_MYPY.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "mypy exited with status {}: {}",
                output.exit_code, output.stderr
            ))
        } else {
            None
        },
    })
}

async fn run_javac(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let output_dir = std::env::temp_dir().join("nexusintellicore-javac-out");
    let _ = std::fs::create_dir_all(&output_dir);

    let mut cmd = Command::new("javac");
    cmd.args([
        "-Xlint",
        "-Xdiags:verbose",
        "-proc:none",
        "-d",
        &output_dir.to_string_lossy(),
        &path.to_string_lossy(),
    ])
    .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute javac")?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_JAVAC,
            "javac not found on PATH",
            "javac-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_JAVAC,
            "javac timed out",
            "javac-timeout",
        ));
    }

    let combined = combine_streams(&output.stdout, &output.stderr);
    let diagnostics = parse_javac_output(&combined, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_JAVAC.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "javac exited with status {}: {}",
                output.exit_code, combined
            ))
        } else {
            None
        },
    })
}

async fn run_ktlint(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let mut cmd = Command::new("ktlint");
    cmd.arg(path).current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute ktlint")?;

    if output.not_found {
        return run_kotlinc(path, root, timeout).await;
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_KTLINT,
            "ktlint timed out",
            "ktlint-timeout",
        ));
    }

    let combined = combine_streams(&output.stdout, &output.stderr);
    let diagnostics = parse_ktlint_output(&combined, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_KTLINT.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "ktlint exited with status {}: {}",
                output.exit_code, combined
            ))
        } else {
            None
        },
    })
}

async fn run_kotlinc(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let output_target = std::env::temp_dir().join("nexusintellicore-kotlinc-out.jar");

    let mut cmd = Command::new("kotlinc");
    cmd.args(["-d"])
        .arg(&output_target)
        .arg(path)
        .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute kotlinc")?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_KOTLINC,
            "ktlint and kotlinc not found on PATH",
            "kotlin-linters-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_KOTLINC,
            "kotlinc timed out",
            "kotlinc-timeout",
        ));
    }

    let combined = combine_streams(&output.stdout, &output.stderr);
    let diagnostics = parse_kotlinc_output(&combined, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_KOTLINC.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "kotlinc exited with status {}: {}",
                output.exit_code, combined
            ))
        } else {
            None
        },
    })
}

async fn run_cppcheck(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let mut cmd = Command::new("cppcheck");
    cmd.args([
        "--template={file}:{line}:{column}:{severity}:{id}:{message}",
        "--enable=warning,style,performance,portability,information",
        "--quiet",
        &path.to_string_lossy(),
    ])
    .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute cppcheck")?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_CPPCHECK,
            "cppcheck not found on PATH",
            "cppcheck-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_CPPCHECK,
            "cppcheck timed out",
            "cppcheck-timeout",
        ));
    }

    let combined = combine_streams(&output.stdout, &output.stderr);
    let diagnostics = parse_cppcheck_output(&combined, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_CPPCHECK.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "cppcheck exited with status {}: {}",
                output.exit_code, combined
            ))
        } else {
            None
        },
    })
}

async fn run_dotnet_build(path: &Path, root: &Path, timeout: Duration) -> Result<LintResult> {
    let Some(project_file) = find_nearest_project_file(path, root, &["csproj", "sln"]) else {
        return Ok(with_notice(
            SOURCE_DOTNET,
            "no .csproj or .sln found for C# linting",
            "dotnet-project-missing",
        ));
    };

    let mut cmd = Command::new("dotnet");
    cmd.args([
        "build",
        &project_file.to_string_lossy(),
        "--nologo",
        "-v",
        "minimal",
        "/p:GenerateFullPaths=true",
    ])
    .current_dir(root);

    let output = run_command(cmd, timeout)
        .await
        .context("failed to execute dotnet build")?;

    if output.not_found {
        return Ok(with_notice(
            SOURCE_DOTNET,
            "dotnet SDK not found on PATH",
            "dotnet-unavailable",
        ));
    }
    if output.timed_out {
        return Ok(with_notice(
            SOURCE_DOTNET,
            "dotnet build timed out",
            "dotnet-timeout",
        ));
    }

    let combined = combine_streams(&output.stdout, &output.stderr);
    let diagnostics = parse_dotnet_output(&combined, path, root);
    Ok(LintResult {
        diagnostics,
        sources: vec![SOURCE_DOTNET.to_string()],
        error: if output.exit_code > 1 {
            Some(format!(
                "dotnet build exited with status {}: {}",
                output.exit_code, combined
            ))
        } else {
            None
        },
    })
}

struct CommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
    not_found: bool,
}

async fn run_command(mut cmd: Command, timeout: Duration) -> Result<CommandOutput> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let result = tokio::time::timeout(timeout, cmd.output()).await;
    match result {
        Err(_) => Ok(CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: -1,
            timed_out: true,
            not_found: false,
        }),
        Ok(Err(err)) => {
            if err.kind() == ErrorKind::NotFound {
                return Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: -1,
                    timed_out: false,
                    not_found: true,
                });
            }
            Err(err).context("process spawn failed")
        }
        Ok(Ok(output)) => Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            timed_out: false,
            not_found: false,
        }),
    }
}

fn parse_clippy_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if value.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            continue;
        }

        let message = &value["message"];
        let level = message
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("info");
        let text = message
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("clippy finding")
            .to_string();
        let rule_id = message
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let spans = message
            .get("spans")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let best_span = spans.into_iter().find(|span| {
            let file_name = span
                .get("file_name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let is_primary = span
                .get("is_primary")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            is_primary && path_matches_target(file_name, target, root)
        });

        let Some(span) = best_span else {
            continue;
        };

        #[allow(clippy::cast_possible_truncation)]
        // span values are source line numbers, never exceed u32
        let line = span.get("line_start").and_then(Value::as_u64).unwrap_or(1) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let column = span
            .get("column_start")
            .and_then(Value::as_u64)
            .unwrap_or(1) as u32;
        diagnostics.push(LintDiagnostic {
            line,
            column,
            severity: map_severity(level),
            message: text,
            rule_id,
            source: SOURCE_CLIPPY.to_string(),
        });
    }

    diagnostics
}

fn parse_eslint_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(stdout) else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    let files = value.as_array().cloned().unwrap_or_default();
    for file_item in files {
        let file_path = file_item
            .get("filePath")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !path_matches_target(file_path, target, root) {
            continue;
        }

        let messages = file_item
            .get("messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for msg in messages {
            diagnostics.push(LintDiagnostic {
                #[allow(clippy::cast_possible_truncation)] // eslint line/col are 1-based small ints
                line: msg.get("line").and_then(Value::as_u64).unwrap_or(1) as u32,
                #[allow(clippy::cast_possible_truncation)]
                column: msg.get("column").and_then(Value::as_u64).unwrap_or(1) as u32,
                severity: map_eslint_severity(msg.get("severity").and_then(Value::as_u64)),
                message: msg
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("eslint finding")
                    .to_string(),
                rule_id: msg
                    .get("ruleId")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                source: SOURCE_ESLINT.to_string(),
            });
        }
    }

    diagnostics
}

fn parse_mypy_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.splitn(4, ':');
        let file = parts.next().unwrap_or_default().trim();
        let line_s = parts.next().unwrap_or_default().trim();
        let col_or_level = parts.next().unwrap_or_default().trim();
        let rest = parts.next().unwrap_or_default().trim();

        if !path_matches_target(file, target, root) {
            continue;
        }

        let line_num = line_s.parse::<u32>().unwrap_or(1);
        if let Ok(col_num) = col_or_level.parse::<u32>() {
            if let Some((severity, message, rule_id)) = parse_mypy_rest(rest) {
                diagnostics.push(LintDiagnostic {
                    line: line_num,
                    column: col_num,
                    severity,
                    message,
                    rule_id,
                    source: SOURCE_MYPY.to_string(),
                });
            }
            continue;
        }

        let merged = format!("{col_or_level}: {rest}");
        if let Some((severity, message, rule_id)) = parse_mypy_rest(&merged) {
            diagnostics.push(LintDiagnostic {
                line: line_num,
                column: 1,
                severity,
                message,
                rule_id,
                source: SOURCE_MYPY.to_string(),
            });
        }
    }

    diagnostics
}

fn parse_javac_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.splitn(4, ':');
        let file = parts.next().unwrap_or_default().trim();
        let line_s = parts.next().unwrap_or_default().trim();
        let level = parts.next().unwrap_or_default().trim();
        let message = parts.next().unwrap_or_default().trim();

        if !path_matches_target(file, target, root) {
            continue;
        }

        let Ok(line_num) = line_s.parse::<u32>() else {
            continue;
        };
        if !matches!(level, "error" | "warning") {
            continue;
        }

        diagnostics.push(LintDiagnostic {
            line: line_num,
            column: 1,
            severity: map_severity(level),
            message: message.to_string(),
            rule_id: Some(format!("javac-{level}")),
            source: SOURCE_JAVAC.to_string(),
        });
    }

    diagnostics
}

fn parse_ktlint_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let pattern = Regex::new(
        r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): (?P<message>.+?)(?: \((?P<rule>[^)]+)\))?$",
    )
    .expect("ktlint regex must compile");
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let Some(caps) = pattern.captures(line.trim()) else {
            continue;
        };

        let file = caps.name("file").map(|m| m.as_str()).unwrap_or_default();
        if !path_matches_target(file, target, root) {
            continue;
        }

        let line_num = caps
            .name("line")
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(1);
        let column = caps
            .name("column")
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(1);
        let message = caps.name("message").map_or_else(
            || "ktlint finding".to_string(),
            |m| m.as_str().trim().to_string(),
        );
        let rule_id = caps.name("rule").map(|m| m.as_str().trim().to_string());

        diagnostics.push(LintDiagnostic {
            line: line_num,
            column,
            severity: Severity::Warning,
            message,
            rule_id,
            source: SOURCE_KTLINT.to_string(),
        });
    }

    diagnostics
}

fn parse_kotlinc_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let colon_pattern = Regex::new(
        r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): (?P<level>error|warning): (?P<message>.+)$",
    )
    .expect("kotlinc colon regex must compile");
    let prefixed_pattern = Regex::new(
        r"^(?:e|w): (?P<file>.+?): \((?P<line>\d+), (?P<column>\d+)\): (?P<message>.+)$",
    )
    .expect("kotlinc prefixed regex must compile");
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();

        if let Some(caps) = colon_pattern.captures(trimmed) {
            let file = caps.name("file").map(|m| m.as_str()).unwrap_or_default();
            if !path_matches_target(file, target, root) {
                continue;
            }

            let line_num = caps
                .name("line")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(1);
            let column = caps
                .name("column")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(1);
            let level = caps.name("level").map_or("warning", |m| m.as_str());
            let message = caps.name("message").map_or_else(
                || "kotlinc finding".to_string(),
                |m| m.as_str().trim().to_string(),
            );

            diagnostics.push(LintDiagnostic {
                line: line_num,
                column,
                severity: map_severity(level),
                message,
                rule_id: Some(format!("kotlinc-{level}")),
                source: SOURCE_KOTLINC.to_string(),
            });
            continue;
        }

        if let Some(caps) = prefixed_pattern.captures(trimmed) {
            let file = caps.name("file").map(|m| m.as_str()).unwrap_or_default();
            if !path_matches_target(file, target, root) {
                continue;
            }

            let line_num = caps
                .name("line")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(1);
            let column = caps
                .name("column")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(1);
            let message = caps.name("message").map_or_else(
                || "kotlinc finding".to_string(),
                |m| m.as_str().trim().to_string(),
            );
            let severity = if trimmed.starts_with("e:") {
                Severity::Error
            } else {
                Severity::Warning
            };
            let rule_id = if trimmed.starts_with("e:") {
                Some("kotlinc-error".to_string())
            } else {
                Some("kotlinc-warning".to_string())
            };

            diagnostics.push(LintDiagnostic {
                line: line_num,
                column,
                severity,
                message,
                rule_id,
                source: SOURCE_KOTLINC.to_string(),
            });
        }
    }

    diagnostics
}

fn parse_cppcheck_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.splitn(6, ':');
        let file = parts.next().unwrap_or_default().trim();
        let line_s = parts.next().unwrap_or_default().trim();
        let col_s = parts.next().unwrap_or_default().trim();
        let severity_s = parts.next().unwrap_or_default().trim();
        let rule_id_s = parts.next().unwrap_or_default().trim();
        let message = parts.next().unwrap_or_default().trim();

        if !path_matches_target(file, target, root) {
            continue;
        }

        let Ok(line_num) = line_s.parse::<u32>() else {
            continue;
        };
        let column = col_s.parse::<u32>().unwrap_or(1);
        diagnostics.push(LintDiagnostic {
            line: line_num,
            column,
            severity: map_severity(severity_s),
            message: message.to_string(),
            rule_id: (!rule_id_s.is_empty()).then(|| rule_id_s.to_string()),
            source: SOURCE_CPPCHECK.to_string(),
        });
    }

    diagnostics
}

fn parse_dotnet_output(stdout: &str, target: &Path, root: &Path) -> Vec<LintDiagnostic> {
    let pattern = Regex::new(
        r"^(?P<file>.+?)\((?P<line>\d+),(?P<column>\d+)\): (?P<level>error|warning) (?P<code>[^:]+): (?P<message>.+?)(?: \s\[.*\])?$",
    )
    .expect("dotnet regex must compile");
    let mut diagnostics = Vec::new();

    for line in stdout.lines() {
        let Some(caps) = pattern.captures(line.trim()) else {
            continue;
        };

        let file = caps.name("file").map(|m| m.as_str()).unwrap_or_default();
        if !path_matches_target(file, target, root) {
            continue;
        }

        let line_num = caps
            .name("line")
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(1);
        let column = caps
            .name("column")
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(1);
        let level = caps.name("level").map_or("warning", |m| m.as_str());
        let code = caps.name("code").map(|m| m.as_str().trim().to_string());
        let message = caps.name("message").map_or_else(
            || "dotnet finding".to_string(),
            |m| m.as_str().trim().to_string(),
        );

        diagnostics.push(LintDiagnostic {
            line: line_num,
            column,
            severity: map_severity(level),
            message,
            rule_id: code,
            source: SOURCE_DOTNET.to_string(),
        });
    }

    diagnostics
}

fn parse_mypy_rest(rest: &str) -> Option<(Severity, String, Option<String>)> {
    let (level, message_part) = rest.split_once(':')?;
    let message_trimmed = message_part.trim();
    let (message, rule_id) = if let Some(start) = message_trimmed.rfind('[') {
        if message_trimmed.ends_with(']') && start > 0 {
            let msg = message_trimmed[..start].trim_end().to_string();
            let code = message_trimmed[start + 1..message_trimmed.len() - 1].to_string();
            (msg, Some(code))
        } else {
            (message_trimmed.to_string(), None)
        }
    } else {
        (message_trimmed.to_string(), None)
    };

    Some((map_severity(level.trim()), message, rule_id))
}

fn map_eslint_severity(value: Option<u64>) -> Severity {
    match value.unwrap_or(1) {
        2 => Severity::Error,
        1 => Severity::Warning,
        _ => Severity::Info,
    }
}

fn map_severity(level: &str) -> Severity {
    match level {
        "error" => Severity::Error,
        "warning" | "warn" | "style" | "performance" | "portability" => Severity::Warning,
        _ => Severity::Info,
    }
}

fn combine_streams(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_string(),
        (true, false) => stderr.to_string(),
        (false, false) => format!("{stdout}\n{stderr}"),
    }
}

fn with_notice(source: &str, message: &str, rule_id: &str) -> LintResult {
    LintResult {
        diagnostics: vec![LintDiagnostic {
            line: 1,
            column: 1,
            severity: Severity::Info,
            message: message.to_string(),
            rule_id: Some(rule_id.to_string()),
            source: source.to_string(),
        }],
        sources: vec![source.to_string()],
        error: None,
    }
}

fn path_matches_target(candidate: &str, target: &Path, root: &Path) -> bool {
    if candidate.is_empty() {
        return false;
    }

    let target_norm = normalize_path(target);
    let target_rel_norm = target
        .strip_prefix(root)
        .ok()
        .map(normalize_path)
        .unwrap_or_default();

    let candidate_path = PathBuf::from(candidate);
    let candidate_norm = if candidate_path.is_absolute() {
        normalize_path(&candidate_path)
    } else {
        normalize_path(&root.join(candidate_path))
    };

    if candidate_norm == target_norm {
        return true;
    }

    if !target_rel_norm.is_empty() {
        return candidate_norm.ends_with(&format!("/{target_rel_norm}"));
    }

    false
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn find_nearest_project_file(path: &Path, root: &Path, extensions: &[&str]) -> Option<PathBuf> {
    let mut current = path.parent()?;
    loop {
        if let Some(found) = find_project_file_in_dir(current, extensions) {
            return Some(found);
        }
        if current == root {
            break;
        }
        current = current.parent()?;
    }

    find_project_file_in_dir(root, extensions)
}

fn find_project_file_in_dir(dir: &Path, extensions: &[&str]) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default();
        if extensions.contains(&ext) {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        parse_clippy_output, parse_cppcheck_output, parse_dotnet_output, parse_eslint_output,
        parse_javac_output, parse_kotlinc_output, parse_ktlint_output, parse_mypy_output,
        path_matches_target,
    };

    #[test]
    fn parses_clippy_json_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/main.rs");
        let stdout = r#"{"reason":"compiler-message","message":{"level":"warning","message":"called unwrap","code":{"code":"clippy::unwrap_used"},"spans":[{"file_name":"src/main.rs","line_start":42,"column_start":9,"is_primary":true}]}}
{"reason":"compiler-message","message":{"level":"warning","message":"other file","code":{"code":"clippy::x"},"spans":[{"file_name":"src/lib.rs","line_start":10,"column_start":1,"is_primary":true}]}}"#;

        let diagnostics = parse_clippy_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 42);
        assert_eq!(diagnostics[0].column, 9);
    }

    #[test]
    fn parses_eslint_json_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/app.ts");
        let stdout = r#"[{"filePath":"/repo/src/app.ts","messages":[{"line":3,"column":7,"severity":2,"message":"Unexpected console statement.","ruleId":"no-console"}]}]"#;

        let diagnostics = parse_eslint_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 3);
        assert_eq!(diagnostics[0].column, 7);
    }

    #[test]
    fn parses_mypy_text_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/pkg/a.py");
        let stdout = "pkg/a.py:8:15: error: Incompatible return value type  [return-value]\npkg/b.py:1:1: error: Other\n";

        let diagnostics = parse_mypy_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 8);
        assert_eq!(diagnostics[0].column, 15);
    }

    #[test]
    fn parses_javac_text_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/App.java");
        let stdout = "/repo/src/App.java:12: warning: [unchecked] unchecked conversion\n/repo/src/Other.java:2: error: cannot find symbol\n";

        let diagnostics = parse_javac_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 12);
        assert_eq!(diagnostics[0].rule_id.as_deref(), Some("javac-warning"));
    }

    #[test]
    fn parses_ktlint_text_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/App.kt");
        let stdout = "/repo/src/App.kt:4:13: Unnecessary semicolon (standard:semicolon)\n/repo/src/Other.kt:1:1: Something else (standard:other)\n";

        let diagnostics = parse_ktlint_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 4);
        assert_eq!(diagnostics[0].column, 13);
        assert_eq!(
            diagnostics[0].rule_id.as_deref(),
            Some("standard:semicolon")
        );
    }

    #[test]
    fn parses_cppcheck_text_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/main.c");
        let stdout = "/repo/src/main.c:7:3:warning:memleak:Memory leak: ptr\n/repo/src/other.c:1:1:error:id:Other\n";

        let diagnostics = parse_cppcheck_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 7);
        assert_eq!(diagnostics[0].column, 3);
        assert_eq!(diagnostics[0].rule_id.as_deref(), Some("memleak"));
    }

    #[test]
    fn parses_kotlinc_text_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/App.kt");
        let stdout = "/repo/src/App.kt:8:17: error: unresolved reference: foo\n/repo/src/Other.kt:1:1: warning: something else\n";

        let diagnostics = parse_kotlinc_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 8);
        assert_eq!(diagnostics[0].column, 17);
        assert_eq!(diagnostics[0].rule_id.as_deref(), Some("kotlinc-error"));
    }

    #[test]
    fn parses_kotlinc_prefixed_text_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/App.kt");
        let stdout = "w: /repo/src/App.kt: (3, 5): Variable is never used\n";

        let diagnostics = parse_kotlinc_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 3);
        assert_eq!(diagnostics[0].column, 5);
        assert_eq!(diagnostics[0].rule_id.as_deref(), Some("kotlinc-warning"));
    }

    #[test]
    fn parses_dotnet_build_output_and_filters_by_target() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/App.cs");
        let stdout = "/repo/src/App.cs(10,15): warning CS0219: The variable 'x' is assigned but its value is never used [/repo/App.csproj]\n/repo/src/Other.cs(1,1): error CS1002: ; expected [/repo/App.csproj]\n";

        let diagnostics = parse_dotnet_output(stdout, target, root);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 10);
        assert_eq!(diagnostics[0].column, 15);
        assert_eq!(diagnostics[0].rule_id.as_deref(), Some("CS0219"));
    }

    #[test]
    fn path_matching_handles_relative_and_absolute() {
        let root = Path::new("/repo");
        let target = Path::new("/repo/src/main.rs");

        assert!(path_matches_target("src/main.rs", target, root));
        assert!(path_matches_target("/repo/src/main.rs", target, root));
        assert!(!path_matches_target("src/lib.rs", target, root));
    }
}
