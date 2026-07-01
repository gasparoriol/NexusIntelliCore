use crate::analyzer;
use crate::privacy_gateway;
use std::fmt::Write as _;

use super::data::ProjectDocsData;
use super::format::{doc_comment_first_line, relative_path_string};
use super::i18n::Labels;

const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const MAX_API_ENTRIES: usize = 30;

pub(super) struct RenderInput<'a> {
    pub data: &'a ProjectDocsData,
    pub labels: &'a Labels,
    pub sections: &'a [String],
    pub public_only: bool,
    pub policy: &'a privacy_gateway::PrivacyPolicy,
}

pub(super) fn render_document(input: &RenderInput<'_>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{} {}\n", input.labels.h1, input.data.project_name);

    if wants(input.sections, "overview") {
        render_overview(&mut out, input);
    }
    if wants(input.sections, "usage") {
        render_usage(&mut out, input);
    }
    if wants(input.sections, "api") {
        render_api(&mut out, input);
    }
    if wants(input.sections, "use_cases") {
        render_use_cases(&mut out, input);
    }

    if out.len() > OUTPUT_LIMIT {
        let mut limit = OUTPUT_LIMIT;
        while !out.is_char_boundary(limit) {
            limit -= 1;
        }
        let mut truncated = out[..limit].to_owned();
        truncated.push_str("\n\n");
        truncated.push_str(input.labels.output_truncated);
        out = truncated;
    }

    out
}

fn wants(sections: &[String], name: &str) -> bool {
    sections.iter().any(|section| section == name)
}

fn render_overview(out: &mut String, input: &RenderInput<'_>) {
    let _ = writeln!(out, "{} {}\n", input.labels.h2, input.labels.overview);

    let mut lang_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (_, analysis) in &input.data.analyses {
        *lang_counts.entry(analysis.language.clone()).or_insert(0) += 1;
    }
    let lang_list: Vec<String> = lang_counts
        .iter()
        .map(|(language, count)| format!("{language} ({count})"))
        .collect();
    let _ = writeln!(
        out,
        "**{}:** {}\n",
        input.labels.languages,
        lang_list.join(", ")
    );

    let total_pub_fns: usize = input
        .data
        .analyses
        .iter()
        .map(|(_, analysis)| {
            analysis
                .functions
                .iter()
                .filter(|function| function.is_public)
                .count()
        })
        .sum();
    let total_pub_types: usize = input
        .data
        .analyses
        .iter()
        .map(|(_, analysis)| {
            analysis
                .classes
                .iter()
                .filter(|class| class.is_public)
                .count()
        })
        .sum();
    let documented_fns: usize = input
        .data
        .analyses
        .iter()
        .map(|(_, analysis)| {
            analysis
                .functions
                .iter()
                .filter(|function| function.is_public && function.doc_comment.is_some())
                .count()
        })
        .sum();
    let _ = writeln!(
        out,
        "**{}:** {} {}, {} {} ({} {})\n",
        input.labels.public_symbols,
        total_pub_fns,
        input.labels.functions,
        total_pub_types,
        input.labels.types,
        documented_fns,
        input.labels.documented
    );

    let best_doc = input
        .data
        .analyses
        .iter()
        .find_map(|(_, analysis)| analysis.module_doc.as_deref());

    if let Some(doc) = best_doc {
        let (clean, _) = privacy_gateway::sanitize_doc_comment(doc, input.policy);
        out.push_str(&clean);
        out.push_str("\n\n");
    } else {
        out.push_str(input.labels.no_module_doc);
        out.push_str("\n\n");
    }

    if input.data.selected_files.len() < input.data.all_files.len() {
        let _ = writeln!(
            out,
            "{}\n",
            input
                .labels
                .analyzed_files_note(input.data.selected_files.len(), input.data.all_files.len())
        );
    }
}

fn render_usage(out: &mut String, input: &RenderInput<'_>) {
    let _ = writeln!(out, "{} {}\n", input.labels.h2, input.labels.usage);

    if input.data.entrypoints.is_empty() {
        out.push_str(input.labels.no_entrypoints);
        out.push_str("\n\n");
    }

    for entrypoint in &input.data.entrypoints {
        match &entrypoint.kind {
            analyzer::EntrypointKind::MainFunction => {
                let file_name = relative_path_string(&input.data.root, &entrypoint.file);
                if let Some(signature) = &entrypoint.signature {
                    let (clean_signature, _) =
                        privacy_gateway::sanitize_output_text(signature, input.policy);
                    let _ = writeln!(
                        out,
                        "{} {}\n\n{}: `{}` {} `{}`\n\n```\n{}\n```\n",
                        input.labels.h3,
                        input.labels.binary_executable,
                        input.labels.entry_point,
                        entrypoint.symbol.as_deref().unwrap_or("main"),
                        input.labels.entry_point_preposition,
                        file_name,
                        clean_signature
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "{} {}\n\n`{}` {} `{}`\n",
                        input.labels.h3,
                        input.labels.executable_entry_point,
                        entrypoint.symbol.as_deref().unwrap_or("main"),
                        input.labels.entry_point_preposition,
                        file_name
                    );
                }
            }
            analyzer::EntrypointKind::CliFramework(name) => {
                let file_name = relative_path_string(&input.data.root, &entrypoint.file);
                let _ = writeln!(
                    out,
                    "{} {} ({})\n\n{} **{}** {} `{}`.\n",
                    input.labels.h3,
                    input.labels.cli_heading,
                    name,
                    input.labels.cli_text,
                    name,
                    input.labels.detected_preposition,
                    file_name
                );
            }
            analyzer::EntrypointKind::HttpFramework(name) => {
                let file_name = relative_path_string(&input.data.root, &entrypoint.file);
                let _ = writeln!(
                    out,
                    "{} {} ({})\n\n{} **{}** {} `{}`.\n",
                    input.labels.h3,
                    input.labels.http_heading,
                    name,
                    input.labels.http_text,
                    name,
                    input.labels.detected_preposition,
                    file_name
                );
            }
            analyzer::EntrypointKind::LibraryCrate => {
                let _ = writeln!(
                    out,
                    "{} {}\n\n{}\n",
                    input.labels.h3, input.labels.library_heading, input.labels.library_text
                );
            }
        }
    }
}

fn render_api(out: &mut String, input: &RenderInput<'_>) {
    let _ = writeln!(out, "{} {}\n", input.labels.h2, input.labels.api);

    let mut api_entry_count = 0usize;

    'files: for (path, analysis) in &input.data.analyses {
        let pub_fns: Vec<_> = if input.public_only {
            analysis
                .functions
                .iter()
                .filter(|function| function.is_public)
                .collect()
        } else {
            analysis.functions.iter().collect()
        };
        let pub_types: Vec<_> = if input.public_only {
            analysis
                .classes
                .iter()
                .filter(|class| class.is_public)
                .collect()
        } else {
            analysis.classes.iter().collect()
        };

        if pub_fns.is_empty() && pub_types.is_empty() {
            continue;
        }

        let rel = relative_path_string(&input.data.root, path);
        let _ = writeln!(out, "{} `{}`\n", input.labels.h3, rel);

        if let Some(first_line) = analysis
            .module_doc
            .as_deref()
            .and_then(doc_comment_first_line)
        {
            let (clean, _) = privacy_gateway::sanitize_doc_comment(&first_line, input.policy);
            if !clean.is_empty() {
                let _ = writeln!(out, "{clean}\n");
            }
        }

        if !pub_types.is_empty() {
            let _ = writeln!(
                out,
                "| {} | Kind | {} |\n|---|---|---|",
                input.labels.type_header, input.labels.description_header
            );
            for class in &pub_types {
                let desc = class
                    .doc_comment
                    .as_deref()
                    .and_then(doc_comment_first_line)
                    .unwrap_or(input.labels.no_documentation.to_owned());
                let (clean_desc, _) = privacy_gateway::sanitize_doc_comment(&desc, input.policy);
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {} |",
                    class.name, class.kind, clean_desc
                );
                api_entry_count += 1;
                if api_entry_count >= MAX_API_ENTRIES {
                    let _ = writeln!(out, "\n{}\n", input.labels.api_truncated(MAX_API_ENTRIES));
                    break 'files;
                }
            }
            out.push('\n');
        }

        if !pub_fns.is_empty() {
            let _ = writeln!(
                out,
                "| {} | {} |\n|---|---|",
                input.labels.function_header, input.labels.description_header
            );
            for function in &pub_fns {
                let desc = function
                    .doc_comment
                    .as_deref()
                    .and_then(doc_comment_first_line)
                    .unwrap_or(input.labels.no_documentation.to_owned());
                let (clean_signature, _) =
                    privacy_gateway::sanitize_output_text(&function.signature, input.policy);
                let (clean_desc, _) = privacy_gateway::sanitize_doc_comment(&desc, input.policy);
                let strip_note = if function.is_strip_marked {
                    input.labels.restricted_suffix
                } else {
                    ""
                };
                let _ = writeln!(out, "| `{clean_signature}`{strip_note} | {clean_desc} |",);
                api_entry_count += 1;
                if api_entry_count >= MAX_API_ENTRIES {
                    let _ = writeln!(out, "\n{}\n", input.labels.api_truncated(MAX_API_ENTRIES));
                    break 'files;
                }
            }
            out.push('\n');
        }
    }
}

fn render_use_cases(out: &mut String, input: &RenderInput<'_>) {
    let _ = writeln!(out, "{} {}\n", input.labels.h2, input.labels.use_cases);

    if input.data.inferred_cases.is_empty() {
        out.push_str(input.labels.use_cases_missing);
        out.push_str("\n\n");
        return;
    }

    for use_case in &input.data.inferred_cases {
        let confidence_label = match use_case.confidence {
            analyzer::UseCaseConfidence::High => "",
            analyzer::UseCaseConfidence::Medium => input.labels.inferred_suffix,
            analyzer::UseCaseConfidence::Low => input.labels.low_confidence_suffix,
        };
        let _ = writeln!(
            out,
            "{} {title}{confidence_label}\n\n{description}\n",
            input.labels.h3,
            title = use_case.title,
            description = use_case.description
        );
    }
}
