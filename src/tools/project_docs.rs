use anyhow::Result;
use serde_json::Value;

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

pub(super) async fn generate_project_docs(
    sections: Vec<String>,
    public_only: bool,
    max_files: usize,
    language: &str,
) -> Result<Value> {
    let state = crate::state::ServerState::get();
    let policy = privacy_gateway::PrivacyPolicy::default();

    // --- Phase 1: build index and select files ---
    let index = state.index().await?;
    let root = state.root().to_path_buf();
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Project")
        .to_owned();

    let all_files = index.allowed_files.clone();
    drop(index);

    if all_files.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No accessible files found. The project may be fully restricted by .mcpignore."
                .to_owned(),
        )]));
    }

    // Prioritise files by depth (shallower = more likely to be core modules)
    let mut sorted_files = all_files.clone();
    sorted_files.sort_by_key(|p| {
        p.strip_prefix(&root)
            .map(|rel| rel.components().count())
            .unwrap_or(usize::MAX)
    });
    sorted_files.truncate(max_files);

    // --- Phase 2: collect FileAnalysis for each selected file ---
    let mut analyses: Vec<(std::path::PathBuf, analyzer::FileAnalysis)> = Vec::new();
    for path in &sorted_files {
        if let Ok(a) = state.get_analysis(path).await {
            analyses.push((path.clone(), a));
        } // skip unreadable files silently
    }

    if analyses.is_empty() {
        return Ok(tool_response(vec![text_content(
            "No files could be analysed. Check that the project contains supported source files."
                .to_owned(),
        )]));
    }

    // --- Phase 3: detect entrypoints and infer use cases (on in-memory data) ---
    let entrypoints = analyzer::detect_entrypoints(&analyses);
    let inferred_cases = analyzer::infer_use_cases(&analyses);

    // --- Phase 4: build output ---
    let (h1, h2, h3, lbl_overview, lbl_usage, lbl_api, lbl_use_cases, lbl_no_doc, lbl_truncated) =
        if language == "es" {
            (
                "#", "##", "###",
                "Descripción general",
                "Cómo usar la aplicación",
                "API pública",
                "Casos de uso",
                "(sin documentación)",
                "> ⚠ Salida truncada: se alcanzó el límite de 2 MB. Usa `get_module_summary` en ficheros individuales para la referencia completa de la API.",
            )
        } else {
            (
                "#", "##", "###",
                "Overview",
                "How to use it",
                "Public API",
                "Use cases",
                "(undocumented)",
                "> ⚠ Output truncated: 2 MB limit reached. Use `get_module_summary` on individual files for the full API reference.",
            )
        };

    const OUTPUT_LIMIT: usize = 2 * 1024 * 1024; // 2 MB

    let mut out = String::new();
    out.push_str(&format!("{h1} {project_name}\n\n"));

    let want = |s: &str| sections.iter().any(|sec| sec == s);

    // --- Section: Overview ---
    if want("overview") {
        out.push_str(&format!("{h2} {lbl_overview}\n\n"));

        // Languages used
        let mut lang_counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (_, a) in &analyses {
            *lang_counts.entry(a.language.clone()).or_insert(0) += 1;
        }
        let lang_list: Vec<String> = lang_counts
            .iter()
            .map(|(l, n)| format!("{} ({})", l, n))
            .collect();
        out.push_str(&format!("**Languages:** {}\n\n", lang_list.join(", ")));

        // Total public symbols
        let total_pub_fns: usize = analyses
            .iter()
            .map(|(_, a)| a.functions.iter().filter(|f| f.is_public).count())
            .sum();
        let total_pub_types: usize = analyses
            .iter()
            .map(|(_, a)| a.classes.iter().filter(|c| c.is_public).count())
            .sum();
        let documented_fns: usize = analyses
            .iter()
            .map(|(_, a)| {
                a.functions
                    .iter()
                    .filter(|f| f.is_public && f.doc_comment.is_some())
                    .count()
            })
            .sum();
        out.push_str(&format!(
            "**Public symbols:** {} functions, {} types ({} documented)\n\n",
            total_pub_fns, total_pub_types, documented_fns
        ));

        // Best module-level doc found
        let best_doc = analyses
            .iter()
            .filter_map(|(_, a)| a.module_doc.as_deref())
            .next();

        if let Some(doc) = best_doc {
            let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, &policy);
            out.push_str(&clean);
            out.push_str("\n\n");
        } else if language == "es" {
            out.push_str(
                "> No se encontró documentación a nivel de módulo. La siguiente descripción se \
                 infiere de la estructura del proyecto y los nombres de los símbolos.\n\n",
            );
        } else {
            out.push_str(
                "> No module-level documentation found. The following is inferred from the \
                 project structure and symbol names.\n\n",
            );
        }

        // Files analysed note
        if sorted_files.len() < all_files.len() {
            let note = if language == "es" {
                format!(
                    "> Nota: se analizaron {} de {} ficheros accesibles (límite `max_files`).\n\n",
                    sorted_files.len(),
                    all_files.len()
                )
            } else {
                format!(
                    "> Note: analysed {} of {} accessible files (`max_files` limit).\n\n",
                    sorted_files.len(),
                    all_files.len()
                )
            };
            out.push_str(&note);
        }
    }

    // --- Section: Usage ---
    if want("usage") {
        out.push_str(&format!("{h2} {lbl_usage}\n\n"));

        if entrypoints.is_empty() {
            if language == "es" {
                out.push_str(
                    "No se pudieron determinar los puntos de entrada mediante análisis estático.\n\n",
                );
            } else {
                out.push_str("Entry points could not be determined from static analysis.\n\n");
            }
        }

        for ep in &entrypoints {
            match &ep.kind {
                analyzer::EntrypointKind::MainFunction => {
                    let file_name = ep
                        .file
                        .strip_prefix(&root)
                        .unwrap_or(&ep.file)
                        .display()
                        .to_string();
                    if let Some(ref sig) = ep.signature {
                        let (clean_sig, _) = privacy_gateway::sanitize_output_text(sig, &policy);
                        out.push_str(&format!(
                            "{h3} Binary executable\n\n\
                             Entry point: `{}` in `{}`\n\n\
                             ```\n{}\n```\n\n",
                            ep.symbol.as_deref().unwrap_or("main"),
                            file_name,
                            clean_sig
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} Executable entry point\n\n\
                             `{}` in `{}`\n\n",
                            ep.symbol.as_deref().unwrap_or("main"),
                            file_name
                        ));
                    }
                }
                analyzer::EntrypointKind::CliFramework(name) => {
                    let file_name = ep
                        .file
                        .strip_prefix(&root)
                        .unwrap_or(&ep.file)
                        .display()
                        .to_string();
                    if language == "es" {
                        out.push_str(&format!(
                            "{h3} Interfaz de línea de comandos ({})\n\n\
                             Se detectó el framework CLI **{}** en `{}`.\n\n",
                            name, name, file_name
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} Command-line interface ({})\n\n\
                             CLI framework **{}** detected in `{}`.\n\n",
                            name, name, file_name
                        ));
                    }
                }
                analyzer::EntrypointKind::HttpFramework(name) => {
                    let file_name = ep
                        .file
                        .strip_prefix(&root)
                        .unwrap_or(&ep.file)
                        .display()
                        .to_string();
                    if language == "es" {
                        out.push_str(&format!(
                            "{h3} Servidor HTTP ({})\n\n\
                             Se detectó el framework HTTP **{}** en `{}`.\n\n",
                            name, name, file_name
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} HTTP server ({})\n\n\
                             HTTP framework **{}** detected in `{}`.\n\n",
                            name, name, file_name
                        ));
                    }
                }
                analyzer::EntrypointKind::LibraryCrate => {
                    if language == "es" {
                        out.push_str(&format!(
                            "{h3} Librería / módulo reutilizable\n\n\
                             No se encontró función `main`. Este proyecto expone una API pública \
                             pensada para ser importada como dependencia.\n\n"
                        ));
                    } else {
                        out.push_str(&format!(
                            "{h3} Library / reusable module\n\n\
                             No `main` function found. This project exposes a public API \
                             designed to be imported as a dependency.\n\n"
                        ));
                    }
                }
            }
        }
    }

    // --- Section: API ---
    if want("api") {
        out.push_str(&format!("{h2} {lbl_api}\n\n"));

        // Group analyses by file; skip files with no public symbols
        let mut api_entry_count = 0usize;
        const MAX_API_ENTRIES: usize = 30;

        'files: for (path, analysis) in &analyses {
            let pub_fns: Vec<_> = if public_only {
                analysis.functions.iter().filter(|f| f.is_public).collect()
            } else {
                analysis.functions.iter().collect()
            };
            let pub_types: Vec<_> = if public_only {
                analysis.classes.iter().filter(|c| c.is_public).collect()
            } else {
                analysis.classes.iter().collect()
            };

            if pub_fns.is_empty() && pub_types.is_empty() {
                continue;
            }

            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string();

            out.push_str(&format!("{h3} `{}`\n\n", rel));

            // Module doc as a brief description
            if let Some(ref mdoc) = analysis.module_doc {
                let first_line = mdoc
                    .lines()
                    .find(|l| {
                        let t = l
                            .trim()
                            .trim_start_matches("//!")
                            .trim_start_matches("///")
                            .trim_start_matches("//")
                            .trim();
                        !t.is_empty()
                    })
                    .map(|l| {
                        l.trim()
                            .trim_start_matches("//!")
                            .trim_start_matches("///")
                            .trim_start_matches("//")
                            .trim()
                            .to_owned()
                    })
                    .unwrap_or_default();
                if !first_line.is_empty() {
                    let (clean, _) = privacy_gateway::sanitize_doc_comment(&first_line, &policy);
                    out.push_str(&format!("{}\n\n", clean));
                }
            }

            // Types table
            if !pub_types.is_empty() {
                out.push_str("| Type | Kind | Description |\n|---|---|---|\n");
                for cls in &pub_types {
                    let desc = cls
                        .doc_comment
                        .as_ref()
                        .and_then(|d| {
                            d.lines()
                                .find(|l| {
                                    let t = l
                                        .trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim();
                                    !t.is_empty()
                                })
                                .map(|l| {
                                    l.trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim()
                                        .to_owned()
                                })
                        })
                        .unwrap_or_else(|| lbl_no_doc.to_owned());
                    let (clean_desc, _) = privacy_gateway::sanitize_doc_comment(&desc, &policy);
                    out.push_str(&format!(
                        "| `{}` | {} | {} |\n",
                        cls.name, cls.kind, clean_desc
                    ));
                    api_entry_count += 1;
                    if api_entry_count >= MAX_API_ENTRIES {
                        out.push_str(&format!(
                            "\n> ⚠ API section truncated at {} entries. Use `get_module_summary` for the full list.\n\n",
                            MAX_API_ENTRIES
                        ));
                        break 'files;
                    }
                }
                out.push('\n');
            }

            // Functions table
            if !pub_fns.is_empty() {
                out.push_str("| Function | Description |\n|---|---|\n");
                for func in &pub_fns {
                    let desc = func
                        .doc_comment
                        .as_ref()
                        .and_then(|d| {
                            d.lines()
                                .find(|l| {
                                    let t = l
                                        .trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim();
                                    !t.is_empty()
                                })
                                .map(|l| {
                                    l.trim()
                                        .trim_start_matches("///")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim()
                                        .to_owned()
                                })
                        })
                        .unwrap_or_else(|| lbl_no_doc.to_owned());
                    let (clean_sig, _) =
                        privacy_gateway::sanitize_output_text(&func.signature, &policy);
                    let (clean_desc, _) = privacy_gateway::sanitize_doc_comment(&desc, &policy);
                    let strip_note = if func.is_strip_marked {
                        " `[restricted]`"
                    } else {
                        ""
                    };
                    out.push_str(&format!(
                        "| `{}`{} | {} |\n",
                        clean_sig, strip_note, clean_desc
                    ));
                    api_entry_count += 1;
                    if api_entry_count >= MAX_API_ENTRIES {
                        out.push_str(&format!(
                            "\n> ⚠ API section truncated at {} entries. Use `get_module_summary` for the full list.\n\n",
                            MAX_API_ENTRIES
                        ));
                        break 'files;
                    }
                }
                out.push('\n');
            }

            // Size guard: bail before the output grows unbounded
            if out.len() > OUTPUT_LIMIT {
                out.push_str(lbl_truncated);
                out.push('\n');
                // Final sanitization and return early
                let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
                return Ok(tool_response(vec![text_content(sanitized_out)]));
            }
        }
    }

    // --- Section: Use cases ---
    if want("use_cases") {
        if !inferred_cases.is_empty() {
            out.push_str(&format!("{h2} {lbl_use_cases}\n\n"));
            for uc in &inferred_cases {
                let confidence_label = match uc.confidence {
                    analyzer::UseCaseConfidence::High => "",
                    analyzer::UseCaseConfidence::Medium => " *(inferred)*",
                    analyzer::UseCaseConfidence::Low => " *(low confidence)*",
                };
                out.push_str(&format!(
                    "{h3} {}{}\n\n{}\n\n",
                    uc.title, confidence_label, uc.description
                ));
            }
        } else if language == "es" {
            out.push_str(&format!("{h2} {lbl_use_cases}\n\n"));
            out.push_str(
                "> No se pudieron inferir casos de uso con suficiente confianza a partir de \
                 la documentación disponible. Usa `get_module_summary` en los módulos \
                 principales para obtener la API detallada.\n\n",
            );
        } else {
            out.push_str(&format!("{h2} {lbl_use_cases}\n\n"));
            out.push_str(
                "> Use cases could not be reliably inferred from available documentation. \
                 Use `get_module_summary` on core modules for the detailed API.\n\n",
            );
        }
    }

    // --- Final output size check and sanitization ---
    if out.len() > OUTPUT_LIMIT {
        // Truncate at a safe boundary and append notice
        let mut truncated = out[..OUTPUT_LIMIT].to_owned();
        truncated.push_str("\n\n");
        truncated.push_str(lbl_truncated);
        out = truncated;
    }

    let (sanitized_out, _) = privacy_gateway::sanitize_output_text(&out, &policy);
    Ok(tool_response(vec![text_content(sanitized_out)]))
}
