use super::types::{FileAnalysis, PatternMatch};

/// Run heuristic checks against a `FileAnalysis` to find common design patterns.
pub fn detect_patterns(analysis: &FileAnalysis, file_path: &str) -> Vec<PatternMatch> {
    let mut found = Vec::new();

    let fn_names: Vec<&str> = analysis.functions.iter().map(|f| f.name.as_str()).collect();

    // Singleton — static INSTANCE field + get_instance / instance / singleton
    if fn_names.iter().any(|n| {
        matches!(
            *n,
            "instance" | "get_instance" | "singleton" | "getInstance"
        )
    }) {
        found.push(PatternMatch {
            pattern: "Singleton".to_owned(),
            evidence: "Found instance() / get_instance() / getInstance() method".to_owned(),
            file: file_path.to_owned(),
            line: analysis
                .functions
                .iter()
                .find(|f| {
                    matches!(
                        f.name.as_str(),
                        "instance" | "get_instance" | "singleton" | "getInstance"
                    )
                })
                .map(|f| f.start_line)
                .unwrap_or(0),
        });
    }

    // Builder — fn build(self) + multiple fn with_*
    let with_count = fn_names.iter().filter(|n| n.starts_with("with_")).count();
    let has_build = fn_names.iter().any(|n| *n == "build" || *n == "finish");
    if with_count >= 2 && has_build {
        found.push(PatternMatch {
            pattern: "Builder".to_owned(),
            evidence: format!("{} with_*() methods + build()/finish() method", with_count),
            file: file_path.to_owned(),
            line: analysis
                .functions
                .iter()
                .find(|f| f.name.starts_with("with_"))
                .map(|f| f.start_line)
                .unwrap_or(0),
        });
    }

    // Factory — class/struct named *Factory or create_*/make_* functions
    let factory_class = analysis
        .classes
        .iter()
        .any(|c| c.name.to_lowercase().contains("factory"));
    let create_fns = fn_names
        .iter()
        .filter(|n| n.starts_with("create_") || n.starts_with("make_") || n.starts_with("new_"))
        .count();
    if factory_class || create_fns >= 2 {
        found.push(PatternMatch {
            pattern: "Factory".to_owned(),
            evidence: if factory_class {
                "Found *Factory class".to_owned()
            } else {
                format!("{} create_*/make_*/new_*() methods", create_fns)
            },
            file: file_path.to_owned(),
            line: 0,
        });
    }

    // Observer — subscribe/unsubscribe/notify/on_* methods
    let has_subscribe = fn_names
        .iter()
        .any(|n| *n == "subscribe" || *n == "register");
    let has_notify = fn_names
        .iter()
        .any(|n| *n == "notify" || *n == "emit" || *n == "publish" || *n == "dispatch");
    if has_subscribe && has_notify {
        found.push(PatternMatch {
            pattern: "Observer".to_owned(),
            evidence: "Found subscribe()/register() + notify()/emit() methods".to_owned(),
            file: file_path.to_owned(),
            line: 0,
        });
    }

    // Repository — find_*/save/delete methods grouped in a struct/class
    let find_count = fn_names
        .iter()
        .filter(|n| n.starts_with("find_") || n.starts_with("get_by"))
        .count();
    let has_save = fn_names
        .iter()
        .any(|n| *n == "save" || *n == "insert" || *n == "persist");
    let has_delete = fn_names.iter().any(|n| *n == "delete" || *n == "remove");
    if find_count >= 1 && has_save && has_delete {
        found.push(PatternMatch {
            pattern: "Repository".to_owned(),
            evidence: format!(
                "{} find_*()/get_by_*() + save() + delete() methods",
                find_count
            ),
            file: file_path.to_owned(),
            line: 0,
        });
    }

    // Strategy — trait/interface + multiple implementations named *Strategy
    let has_strategy_name = analysis
        .classes
        .iter()
        .any(|c| c.name.to_lowercase().contains("strategy"));
    if has_strategy_name {
        found.push(PatternMatch {
            pattern: "Strategy".to_owned(),
            evidence: "Found class/struct/trait with 'Strategy' in name".to_owned(),
            file: file_path.to_owned(),
            line: analysis
                .classes
                .iter()
                .find(|c| c.name.to_lowercase().contains("strategy"))
                .map(|c| c.start_line)
                .unwrap_or(0),
        });
    }

    found
}
