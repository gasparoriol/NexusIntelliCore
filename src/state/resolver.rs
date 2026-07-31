use anyhow::{Context, Result};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct TsPathAliasRule {
    pub pattern: String,
    pub targets: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TsPathAliasConfig {
    pub config_dir: PathBuf,
    pub base_url: Option<PathBuf>,
    pub rules: Vec<TsPathAliasRule>,
}

pub struct PathResolver;

impl PathResolver {
    pub fn validate_path(root: &Path, requested: &Path) -> Result<PathBuf> {
        let requested_text = requested.display().to_string();
        let canonical = std::fs::canonicalize(requested)
            .with_context(|| format!("Path does not exist or is inaccessible: {requested_text}"))?;

        anyhow::ensure!(
            canonical.starts_with(root),
            "Access denied: {} is outside the project root {}",
            requested.display(),
            root.display()
        );

        Ok(canonical)
    }

    pub fn discover_ts_path_aliases(root: &Path) -> Vec<TsPathAliasConfig> {
        let mut configs = Vec::new();
        let walker = WalkBuilder::new(root)
            .hidden(false)
            .ignore(true)
            .git_ignore(true)
            .build();

        for entry in walker.flatten() {
            let p = entry.path();
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name != "tsconfig.json" && name != "jsconfig.json" {
                continue;
            }

            if let Some(cfg) = parse_ts_path_alias_config(p) {
                configs.push(cfg);
            }
        }

        configs.sort_by_key(|cfg| std::cmp::Reverse(cfg.config_dir.components().count()));
        configs
    }

    pub fn resolve_ts_path_alias(
        aliases: &[TsPathAliasConfig],
        import_path: &str,
        importer_path: &Path,
    ) -> Option<PathBuf> {
        if !import_path.starts_with('@') && !import_path.starts_with("src/") {
            return None;
        }

        for config in aliases {
            for rule in &config.rules {
                let Some(wildcard) = match_alias_pattern(&rule.pattern, import_path) else {
                    continue;
                };

                for target in &rule.targets {
                    let substituted = apply_alias_target(target, &wildcard);
                    let base = if let Some(base_url) = &config.base_url {
                        config.config_dir.join(base_url).join(&substituted)
                    } else {
                        config.config_dir.join(&substituted)
                    };

                    let normalized = normalize_relative_path(&base);
                    for candidate in expand_ts_alias_candidates(normalized) {
                        if candidate.is_file() {
                            return std::fs::canonicalize(&candidate).ok();
                        }
                    }
                }
            }
        }

        let importer_dir = importer_path.parent().unwrap_or_else(|| Path::new("."));
        let direct_candidate = importer_dir.join(import_path);
        let normalized_direct = normalize_relative_path(&direct_candidate);
        for candidate in expand_ts_alias_candidates(normalized_direct) {
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate).ok();
            }
        }

        None
    }
}

pub fn parse_ts_path_alias_config(config_path: &Path) -> Option<TsPathAliasConfig> {
    let raw = std::fs::read_to_string(config_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let compiler = parsed.get("compilerOptions")?.as_object()?;
    let paths = compiler.get("paths")?.as_object()?;

    let mut rules = Vec::new();
    for (pattern, values) in paths {
        let targets = values
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !targets.is_empty() {
            rules.push(TsPathAliasRule {
                pattern: pattern.to_string(),
                targets,
            });
        }
    }

    if rules.is_empty() {
        return None;
    }

    let base_url = compiler
        .get("baseUrl")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    Some(TsPathAliasConfig {
        config_dir: config_path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        base_url,
        rules,
    })
}

pub fn match_alias_pattern(pattern: &str, import_path: &str) -> Option<String> {
    if let Some(star) = pattern.find('*') {
        let prefix = &pattern[..star];
        let suffix = &pattern[star + 1..];
        if import_path.starts_with(prefix)
            && import_path.ends_with(suffix)
            && import_path.len() >= prefix.len() + suffix.len()
        {
            return Some(import_path[prefix.len()..import_path.len() - suffix.len()].to_string());
        }
        return None;
    }

    if pattern == import_path {
        Some(String::new())
    } else {
        None
    }
}

pub fn apply_alias_target(target: &str, wildcard: &str) -> String {
    if target.contains('*') {
        target.replacen('*', wildcard, 1)
    } else {
        target.to_owned()
    }
}

pub fn normalize_relative_path(path: &Path) -> PathBuf {
    path.components().fold(PathBuf::new(), |mut acc, comp| {
        match comp {
            std::path::Component::ParentDir => {
                acc.pop();
            }
            std::path::Component::CurDir => {}
            other => acc.push(other),
        }
        acc
    })
}

pub fn expand_ts_alias_candidates(base: PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if base.extension().is_some() {
        out.push(base);
        return out;
    }

    out.push(base.clone());
    for ext in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
        out.push(base.with_extension(ext));
    }
    for ext in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
        out.push(base.join(format!("index.{ext}")));
    }
    out
}

pub fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::Value::String(s.clone()).to_string(),
        serde_json::Value::Array(items) => {
            let rendered = items
                .iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{rendered}]")
        }
        serde_json::Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(a, _)| *a);
            let rendered = entries
                .into_iter()
                .map(|(k, v)| {
                    let rendered_key = serde_json::Value::String(k.clone()).to_string();
                    format!("{rendered_key}:{}", canonicalize_json(v))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}
