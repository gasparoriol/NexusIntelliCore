use super::types::{Entrypoint, EntrypointKind, FileAnalysis};
use std::path::PathBuf;

/// Scan `analyses` and return detected entrypoints.
///
/// Operates entirely on data already in memory — no new I/O or parsing.
#[allow(clippy::too_many_lines)] // Mapping table for framework specific entrypoints
pub fn detect_entrypoints(analyses: &[(PathBuf, FileAnalysis)]) -> Vec<Entrypoint> {
    const CLI_MARKERS: &[(&str, &str)] = &[
        ("clap", "clap"),
        ("structopt", "structopt"),
        ("argparse", "argparse"),
        ("click", "click"),
        ("typer", "typer"),
        ("commander", "commander"),
        ("yargs", "yargs"),
        ("picocli", "picocli"),
        ("commons-cli", "commons-cli"),
    ];

    const HTTP_MARKERS: &[(&str, &str)] = &[
        ("actix_web", "actix-web"),
        ("actix-web", "actix-web"),
        ("axum", "axum"),
        ("warp", "warp"),
        ("rocket", "rocket"),
        ("fastapi", "fastapi"),
        ("flask", "flask"),
        ("django", "django"),
        ("express", "express"),
        ("fastify", "fastify"),
        ("springframework", "spring-boot"),
        ("spring-boot", "spring-boot"),
        ("quarkus", "quarkus"),
        ("hyper", "hyper"),
    ];

    let mut result: Vec<Entrypoint> = Vec::new();
    let mut found_main = false;
    let mut has_public_api = false;
    let mut cli_found = false;
    let mut http_found = false;

    for (path, analysis) in analyses {
        // Main function
        for func in &analysis.functions {
            if func.name == "main" {
                found_main = true;
                result.push(Entrypoint {
                    kind: EntrypointKind::MainFunction,
                    file: path.clone(),
                    symbol: Some("main".to_owned()),
                    signature: Some(func.signature.clone()),
                });
                break;
            }
        }

        // Python __main__ sentinel (appears as a string literal `"__main__"`)
        if analysis.language == "python" {
            for lit in &analysis.string_literals {
                if lit.value == "__main__" {
                    found_main = true;
                    result.push(Entrypoint {
                        kind: EntrypointKind::MainFunction,
                        file: path.clone(),
                        symbol: Some("__main__".to_owned()),
                        signature: None,
                    });
                    break;
                }
            }
        }

        // Framework detection via imports
        for imp in &analysis.imports {
            let imp_lower = imp.path.to_lowercase();
            if !cli_found {
                for (marker, name) in CLI_MARKERS {
                    if imp_lower.contains(marker) {
                        cli_found = true;
                        result.push(Entrypoint {
                            kind: EntrypointKind::CliFramework((*name).to_owned()),
                            file: path.clone(),
                            symbol: None,
                            signature: None,
                        });
                        break;
                    }
                }
            }
            if !http_found {
                for (marker, name) in HTTP_MARKERS {
                    if imp_lower.contains(marker) {
                        http_found = true;
                        result.push(Entrypoint {
                            kind: EntrypointKind::HttpFramework((*name).to_owned()),
                            file: path.clone(),
                            symbol: None,
                            signature: None,
                        });
                        break;
                    }
                }
            }
        }

        if analysis.functions.iter().any(|f| f.is_public)
            || analysis.classes.iter().any(|c| c.is_public)
        {
            has_public_api = true;
        }
    }

    // No main found but public API exists → library
    if !found_main && has_public_api && result.is_empty() {
        result.push(Entrypoint {
            kind: EntrypointKind::LibraryCrate,
            file: PathBuf::new(),
            symbol: None,
            signature: None,
        });
    }

    result
}
