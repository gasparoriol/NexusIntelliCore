use crate::analyzer;

pub(crate) fn resolve_import_path(
    imp: &analyzer::ImportInfo,
    from_file: &std::path::Path,
    source_language: &str,
    state: Option<&crate::state::ServerState>,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    let path = &imp.path;

    if let Some(resolved) = resolve_ts_alias_import(
        source_language,
        path,
        from_file,
        state,
        allowed_files,
        restricted_files,
    ) {
        return resolved;
    }

    if imp.kind == ImportKind::ExternalLibrary {
        return (imp.path.clone(), ImportKind::ExternalLibrary, None);
    }

    if path.starts_with("./") || path.starts_with("../") {
        return resolve_relative_import_path(path, from_file, allowed_files, restricted_files);
    }

    resolve_non_relative_import_path(path, allowed_files, restricted_files)
}

pub(crate) fn resolve_ts_alias_import(
    source_language: &str,
    path: &str,
    from_file: &std::path::Path,
    state: Option<&crate::state::ServerState>,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> Option<(String, analyzer::ImportKind, Option<std::path::PathBuf>)> {
    use analyzer::ImportKind;

    if !matches!(source_language, "javascript" | "typescript" | "tsx")
        || path.starts_with("./")
        || path.starts_with("../")
    {
        return None;
    }

    let alias_target = state.and_then(|s| s.resolve_ts_path_alias(path, from_file))?;
    if let Some((rel, kind, resolved)) =
        classify_project_path(&alias_target, allowed_files, restricted_files)
    {
        return Some((rel, kind, Some(resolved)));
    }

    if let Ok(canon) = std::fs::canonicalize(&alias_target) {
        if let Some((rel, kind, resolved)) =
            classify_project_path(&canon, allowed_files, restricted_files)
        {
            return Some((rel, kind, Some(resolved)));
        }
    }

    Some((path.to_owned(), ImportKind::Unresolved, None))
}

pub(crate) fn classify_project_path(
    candidate: &std::path::Path,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> Option<(String, analyzer::ImportKind, std::path::PathBuf)> {
    use analyzer::ImportKind;

    if allowed_files.contains(&candidate.to_path_buf()) {
        let rel = candidate.to_string_lossy().into_owned();
        return Some((rel, ImportKind::InternalLocal, candidate.to_path_buf()));
    }
    if restricted_files.contains(&candidate.to_path_buf()) {
        let rel = candidate.to_string_lossy().into_owned();
        return Some((rel, ImportKind::InternalRestricted, candidate.to_path_buf()));
    }

    None
}

pub(crate) fn resolve_relative_import_path(
    path: &str,
    from_file: &std::path::Path,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    let base = from_file.parent().unwrap_or(std::path::Path::new("/"));
    let candidate = base.join(path);
    for ext in &["", "rs", "ts", "tsx", "js", "py", "java"] {
        let with_ext = if ext.is_empty() {
            candidate.clone()
        } else {
            candidate.with_extension(ext)
        };
        let normalised = normalise_path(&with_ext);
        if let Some((rel, kind, resolved)) =
            classify_project_path(&normalised, allowed_files, restricted_files)
        {
            return (rel, kind, Some(resolved));
        }
    }

    (path.to_owned(), ImportKind::Unresolved, None)
}

pub(crate) fn normalise_path(path: &std::path::Path) -> std::path::PathBuf {
    path.components()
        .fold(std::path::PathBuf::new(), |mut acc, component| {
            match component {
                std::path::Component::ParentDir => {
                    acc.pop();
                }
                std::path::Component::CurDir => {}
                other => acc.push(other),
            }
            acc
        })
}

pub(crate) fn resolve_non_relative_import_path(
    path: &str,
    allowed_files: &[std::path::PathBuf],
    restricted_files: &[std::path::PathBuf],
) -> (String, analyzer::ImportKind, Option<std::path::PathBuf>) {
    use analyzer::ImportKind;

    let normalised = normalise_internal_reference(path);

    if let Some(matched) = find_matching_file(&normalised, allowed_files) {
        let rel = matched.to_string_lossy().into_owned();
        return (rel, ImportKind::InternalLocal, Some(matched));
    }
    if let Some(matched) = find_matching_file(&normalised, restricted_files) {
        let rel = matched.to_string_lossy().into_owned();
        return (rel, ImportKind::InternalRestricted, Some(matched));
    }

    (normalised, ImportKind::Unresolved, None)
}

pub(crate) fn normalise_internal_reference(path: &str) -> String {
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

    normalised
}

pub(crate) fn find_matching_file(
    normalised: &str,
    files: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    for file in files {
        let file_str = file.to_string_lossy();
        let stem = file_str
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".java")
            .trim_end_matches(".tsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".js");

        if stem == normalised || stem.ends_with(&format!("/{normalised}")) {
            return Some(file.clone());
        }
    }

    None
}
