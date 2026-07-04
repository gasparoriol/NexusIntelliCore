use super::types::{FileAnalysis, InferredUseCase, UseCaseConfidence};
use std::path::PathBuf;

/// Infer practical use cases from public API names and doc-comments.
///
/// Strategy:
/// 1. **High** — doc-comment lines containing action verbs (`allows`, `enables`, …).
/// 2. **Medium** — public functions grouped by semantic name prefix (`create_*`, …),
///    groups of ≥ 2 functions.
///
/// Low-confidence items are kept only when nothing better was found.
#[allow(clippy::too_many_lines)] // Verb lists and heuristics mapping logic
pub fn infer_use_cases(analyses: &[(PathBuf, FileAnalysis)]) -> Vec<InferredUseCase> {
    const VERB_PREFIXES: &[(&str, &str)] = &[
        ("create_", "Creating"),
        ("new_", "Creating"),
        ("build_", "Building"),
        ("generate_", "Generating"),
        ("parse_", "Parsing"),
        ("read_", "Reading"),
        ("load_", "Loading"),
        ("write_", "Writing"),
        ("save_", "Saving"),
        ("export_", "Exporting"),
        ("import_", "Importing"),
        ("validate_", "Validating"),
        ("check_", "Checking"),
        ("verify_", "Verifying"),
        ("search_", "Searching"),
        ("find_", "Finding"),
        ("query_", "Querying"),
        ("get_", "Retrieving"),
        ("fetch_", "Fetching"),
        ("send_", "Sending"),
        ("process_", "Processing"),
        ("handle_", "Handling"),
        ("convert_", "Converting"),
        ("transform_", "Transforming"),
        ("analyze_", "Analyzing"),
        ("audit_", "Auditing"),
        ("inspect_", "Inspecting"),
        ("refresh_", "Refreshing"),
        ("update_", "Updating"),
        ("delete_", "Deleting"),
        ("remove_", "Removing"),
    ];

    const DOC_VERBS: &[&str] = &[
        "use this",
        "useful for",
        "allows",
        "enables",
        "use when",
        "use it to",
        "can be used",
        "is used to",
        "provides",
        "supports",
    ];

    let mut use_cases: Vec<InferredUseCase> = Vec::new();

    // --- Pass 1: High confidence — explicit doc-comment phrases ---
    for (_, analysis) in analyses {
        for func in &analysis.functions {
            if !func.is_public {
                continue;
            }
            if let Some(ref doc) = func.doc_comment {
                let doc_lower = doc.to_lowercase();
                for verb in DOC_VERBS {
                    if doc_lower.contains(verb) {
                        let sentence = doc
                            .lines()
                            .find(|l| l.to_lowercase().contains(verb))
                            .map(|l| {
                                l.trim()
                                    .trim_start_matches("///")
                                    .trim_start_matches("//")
                                    .trim_start_matches('#')
                                    .trim()
                                    .to_owned()
                            })
                            .unwrap_or_default();

                        if sentence.len() > 10 {
                            let already = use_cases.iter().any(|uc| {
                                uc.confidence == UseCaseConfidence::High
                                    && uc.functions.contains(&func.name)
                            });
                            if !already {
                                use_cases.push(InferredUseCase {
                                    title: format!("Using `{}`", func.name),
                                    description: sentence,
                                    functions: vec![func.name.clone()],
                                    confidence: UseCaseConfidence::High,
                                });
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    // --- Pass 2: Medium confidence — function name prefix grouping ---
    {
        use std::collections::HashMap;
        let mut prefix_groups: HashMap<&str, Vec<String>> = HashMap::new();

        for (_, analysis) in analyses {
            for func in &analysis.functions {
                if !func.is_public {
                    continue;
                }
                for (prefix, _) in VERB_PREFIXES {
                    if func.name.starts_with(prefix) {
                        prefix_groups
                            .entry(prefix)
                            .or_default()
                            .push(func.name.clone());
                        break;
                    }
                }
            }
        }

        for (prefix, fns) in &prefix_groups {
            if fns.len() < 2 {
                continue;
            }
            let label = VERB_PREFIXES
                .iter()
                .find(|(p, _)| p == prefix)
                .map_or("Working with", |(_, l)| *l);

            let already_covered = use_cases.iter().any(|uc| {
                uc.confidence == UseCaseConfidence::High
                    && uc.functions.iter().any(|f| fns.contains(f))
            });
            if already_covered {
                continue;
            }

            let sample: Vec<&str> = fns.iter().take(3).map(String::as_str).collect();
            use_cases.push(InferredUseCase {
                title: format!("{label} data"),
                description: format!(
                    "Functions such as `{}` provide {} capabilities.",
                    sample.join("`, `"),
                    label.to_lowercase()
                ),
                functions: fns.clone(),
                confidence: UseCaseConfidence::Medium,
            });
        }
    }

    // Sort High → Medium → Low; truncate to 8
    use_cases.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    use_cases.truncate(8);

    use_cases
}
