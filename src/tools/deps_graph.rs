use anyhow::Result;
use serde_json::{json, Value};

use crate::analyzer;
use crate::privacy_gateway;
use crate::protocol::{text_content, tool_response};

pub(super) async fn get_dependencies_graph() -> Result<Value> {
    let state = crate::state::ServerState::get();
    let index = state.index().await?;
    let allowed_files = index.allowed_files.clone();
    let restricted_files = index.restricted_files.clone();
    drop(index);

    // Build a per-file classified dependency map:
    // relative_path → { internal, restricted, external, unresolved }
    let mut file_deps: serde_json::Map<String, Value> = serde_json::Map::new();

    for file in &allowed_files {
        let path = match state.validate_path(file) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let index_read = state.index().await?;
        let rel = index_read.relative(&path).to_string_lossy().into_owned();
        drop(index_read);

        let analysis = match state.get_analysis(&path).await {
            Ok(a) => a,
            Err(_) => continue,
        };

        let mut internal: Vec<String> = Vec::new();
        let mut restricted: Vec<String> = Vec::new();
        let mut external: Vec<String> = Vec::new();
        let mut unresolved_list: Vec<String> = Vec::new();

        for imp in &analysis.imports {
            let (resolved_str, kind, _) =
                resolve_import_path(imp, &path, &allowed_files, &restricted_files);
            match kind {
                analyzer::ImportKind::InternalLocal => internal.push(resolved_str),
                analyzer::ImportKind::InternalRestricted => restricted.push(resolved_str),
                analyzer::ImportKind::ExternalLibrary => external.push(imp.path.clone()),
                analyzer::ImportKind::Unresolved => unresolved_list.push(imp.path.clone()),
            }
        }

        file_deps.insert(
            rel,
            json!({
                "internal":   internal,
                "restricted": restricted,
                "external":   external,
                "unresolved": unresolved_list,
            }),
        );
    }

    let result = Value::Object(file_deps);

    // Sanitize through Privacy Gateway
    let policy = privacy_gateway::PrivacyPolicy::default();
    let (sanitized_graph, _redactions) =
        privacy_gateway::sanitize_dependency_graph(&result, &policy);

    Ok(tool_response(vec![text_content(
        serde_json::to_string_pretty(&sanitized_graph).unwrap_or_default(),
    )]))
}

/// Resolve an import to a project-relative path and classify its kind.
///
/// Resolution rules:
/// - `ExternalLibrary` imports are returned as-is (no file lookup).
/// - Relative paths (`./`, `../`) are resolved against `from_file`'s parent
///   directory; we try common source extensions if no extension is present.
/// - Rust `crate::`/`self::`/`super::` and Python/Java dot-notation are
///   normalised and looked up by suffix in the allowed/restricted file lists.
fn resolve_import_path(
    imp: &analyzer::ImportInfo,
    from_file: &std::path::Path,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    // External libraries never resolve to a project file.
    if imp.kind == ImportKind::ExternalLibrary {
        return (imp.path.clone(), ImportKind::ExternalLibrary, None);
    }

    let path = &imp.path;

    // Relative paths — resolve against the importing file's parent directory.
    if path.starts_with("./") || path.starts_with("../") {
        let base = from_file.parent().unwrap_or(std::path::Path::new("/"));
        let candidate = base.join(path);
        for ext in &["", "rs", "ts", "tsx", "js", "py", "java"] {
            let with_ext = if ext.is_empty() {
                candidate.clone()
            } else {
                candidate.with_extension(ext)
            };
            let canon = with_ext
                .components()
                .fold(std::path::PathBuf::new(), |mut acc, c| {
                    match c {
                        std::path::Component::ParentDir => {
                            acc.pop();
                        }
                        std::path::Component::CurDir => {}
                        other => acc.push(other),
                    }
                    acc
                });
            if allowed_files.contains(&canon) {
                let rel = canon.to_string_lossy().into_owned();
                return (rel, ImportKind::InternalLocal, Some(canon));
            }
            if restricted_files.contains(&canon) {
                let rel = canon.to_string_lossy().into_owned();
                return (rel, ImportKind::InternalRestricted, Some(canon));
            }
        }
        return (path.to_owned(), ImportKind::Unresolved, None);
    }

    // Non-relative internal references: normalise separator and search by suffix.
    let normalised = if path.contains("::") {
        path.replace("::", "/")
    } else if path.contains('.') && !path.contains('/') {
        path.replace('.', "/")
    } else {
        path.to_owned()
    };
    let mut normalised = normalised.trim_matches('/').to_owned();

    if normalised.starts_with("crate/") {
        normalised = normalised["crate/".len()..].to_owned();
    } else if normalised.starts_with("self/") {
        normalised = normalised["self/".len()..].to_owned();
    }
    while normalised.starts_with("super/") {
        normalised = normalised["super/".len()..].to_owned();
    }

    for file in allowed_files {
        let file_str = file.to_string_lossy();
        let stem = file_str
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");
        if stem.ends_with(&normalised) || file_str.contains(&normalised) {
            let rel = file_str.into_owned();
            return (rel, ImportKind::InternalLocal, Some(file.clone()));
        }
    }
    for file in restricted_files {
        let file_str = file.to_string_lossy();
        let stem = file_str
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");
        if stem.ends_with(&normalised) || file_str.contains(&normalised) {
            let rel = file_str.into_owned();
            return (rel, ImportKind::InternalRestricted, Some(file.clone()));
        }
    }

    (normalised, ImportKind::Unresolved, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{ImportInfo, ImportKind};
    use std::path::{Path, PathBuf};

    #[test]
    fn test_resolve_import_path_rust_crate() {
        let allowed = vec![
            PathBuf::from("src/main.rs"),
            PathBuf::from("src/analyzer.rs"),
            PathBuf::from("src/tools/deps_graph.rs"),
        ];
        let restricted = vec![];

        let imp = ImportInfo {
            raw: "use crate::analyzer;".to_owned(),
            path: "crate::analyzer".to_owned(),
            kind: ImportKind::InternalLocal,
            resolved_path: None,
        };

        let (resolved, kind, path_opt) = resolve_import_path(
            &imp,
            Path::new("src/main.rs"),
            &allowed,
            &restricted,
        );

        assert_eq!(kind, ImportKind::InternalLocal);
        assert_eq!(resolved, "src/analyzer.rs");
        assert_eq!(path_opt, Some(PathBuf::from("src/analyzer.rs")));
    }

    #[test]
    fn test_resolve_import_path_rust_super() {
        let allowed = vec![
            PathBuf::from("src/main.rs"),
            PathBuf::from("src/state.rs"),
            PathBuf::from("src/tools/deps_graph.rs"),
        ];
        let restricted = vec![];

        let imp = ImportInfo {
            raw: "use super::super::state;".to_owned(),
            path: "super::super::state".to_owned(),
            kind: ImportKind::InternalLocal,
            resolved_path: None,
        };

        let (resolved, kind, path_opt) = resolve_import_path(
            &imp,
            Path::new("src/tools/deps_graph.rs"),
            &allowed,
            &restricted,
        );

        assert_eq!(kind, ImportKind::InternalLocal);
        assert_eq!(resolved, "src/state.rs");
        assert_eq!(path_opt, Some(PathBuf::from("src/state.rs")));
    }

    #[test]
    fn test_resolve_import_path_external() {
        let allowed = vec![];
        let restricted = vec![];

        let imp = ImportInfo {
            raw: "use serde_json::Value;".to_owned(),
            path: "serde_json::Value".to_owned(),
            kind: ImportKind::ExternalLibrary,
            resolved_path: None,
        };

        let (resolved, kind, path_opt) = resolve_import_path(
            &imp,
            Path::new("src/main.rs"),
            &allowed,
            &restricted,
        );

        assert_eq!(kind, ImportKind::ExternalLibrary);
        assert_eq!(resolved, "serde_json::Value");
        assert!(path_opt.is_none());
    }
}

