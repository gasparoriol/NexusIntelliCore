/// Phase 2: File Indexer
///
/// Walks the project tree while respecting `.gitignore` and a custom
/// `.mcpignore` file.  Files matched by `.mcpignore` are placed in the
/// `restricted` list and will be labelled "(Acceso Restringido)" in the
/// directory tree, but their contents will never be sent to the LLM.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

const MAX_RENDER_DEPTH: usize = 2;
const MAX_RENDER_FILES: usize = 8;
const MAX_RENDER_DIRS: usize = 8;

/// Typed indexer rendering limits — governs the depth and breadth of
/// `render_tree` and related summarisation.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct IndexerLimits {
    pub max_render_depth: usize,
    pub max_render_files_per_dir: usize,
    pub max_render_dirs_per_dir: usize,
}

#[allow(dead_code)]
impl IndexerLimits {
    pub const fn defaults() -> Self {
        Self {
            max_render_depth: MAX_RENDER_DEPTH,
            max_render_files_per_dir: MAX_RENDER_FILES,
            max_render_dirs_per_dir: MAX_RENDER_DIRS,
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FileIndex {
    pub root: PathBuf,
    /// Files accessible for analysis.
    pub allowed_files: Vec<PathBuf>,
    /// Files whose contents are access-restricted (from .mcpignore).
    pub restricted_files: Vec<PathBuf>,
    /// Compiled glob matcher from .mcpignore.
    mcpignore_matcher: Option<GlobSet>,
}

impl FileIndex {
    /// Create an empty index placeholder.
    ///
    /// This allows the server to start and respond to MCP lifecycle requests
    /// immediately, while the full filesystem walk can be deferred until the
    /// first tool that actually needs indexed files.
    #[allow(dead_code)]
    pub fn empty(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            allowed_files: Vec::new(),
            restricted_files: Vec::new(),
            mcpignore_matcher: None,
        }
    }

    /// Build the index by walking `root`.
    pub fn build(root: &Path) -> Result<Self> {
        let mcpignore_patterns = load_mcpignore(root);
        let matcher = build_glob_set(&mcpignore_patterns)?;
        let (allowed, restricted) = walk_files(root, matcher.as_ref())?;

        Ok(Self {
            root: root.to_path_buf(),
            allowed_files: allowed,
            restricted_files: restricted,
            mcpignore_matcher: matcher,
        })
    }

    /// Returns `true` when `path` is covered by a `.mcpignore` rule.
    pub fn is_restricted(&self, path: &Path) -> bool {
        let rel = path
            .strip_prefix(&self.root)
            .ok()
            .map(Path::to_path_buf)
            .or_else(|| {
                if !path.is_absolute() {
                    return None;
                }

                let canonical_root = std::fs::canonicalize(&self.root).ok()?;
                let canonical_path = std::fs::canonicalize(path).ok()?;
                canonical_path
                    .strip_prefix(canonical_root)
                    .ok()
                    .map(Path::to_path_buf)
            })
            .unwrap_or_else(|| path.to_path_buf());

        self.mcpignore_matcher
            .as_ref()
            .is_some_and(|matcher| matcher.is_match(&rel))
    }

    /// Strip the root prefix so paths are relative for display.
    pub fn relative(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.root).unwrap_or(path).to_path_buf()
    }

    /// Render the directory tree as a plain-text string.
    ///
    /// Restricted files are annotated with `(Acceso Restringido)`.
    pub fn render_tree(&self) -> String {
        let mut root = TreeNode::default();

        let mut all: Vec<(PathBuf, bool)> = self
            .allowed_files
            .iter()
            .map(|p| (self.relative(p), false))
            .chain(
                self.restricted_files
                    .iter()
                    .map(|p| (self.relative(p), true)),
            )
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));

        for (rel, restricted) in all {
            root.insert(&rel, restricted);
        }

        let stats = root.stats();
        let mut lines = vec![format!(
            "{}/ [files: {}, dirs: {}, restricted: {}]",
            self.root.display(),
            stats.files,
            stats.dirs,
            stats.restricted
        )];
        root.render_into(&mut lines, 0);

        lines.join("\n")
    }
}

#[derive(Default)]
struct TreeNode {
    files: Vec<(String, bool)>,
    dirs: std::collections::BTreeMap<String, TreeNode>,
}

#[derive(Default)]
struct TreeStats {
    files: usize,
    dirs: usize,
    restricted: usize,
}

impl TreeNode {
    fn insert(&mut self, path: &Path, restricted: bool) {
        let mut node = self;
        let mut parts = path.components().peekable();

        while let Some(part) = parts.next() {
            let name = part.as_os_str().to_string_lossy().into_owned();
            if parts.peek().is_none() {
                node.files.push((name, restricted));
            } else {
                node = node.dirs.entry(name).or_default();
            }
        }
    }

    fn stats(&self) -> TreeStats {
        let mut stats = TreeStats {
            files: self.files.len(),
            dirs: self.dirs.len(),
            restricted: self
                .files
                .iter()
                .filter(|(_, restricted)| *restricted)
                .count(),
        };

        for child in self.dirs.values() {
            let child_stats = child.stats();
            stats.files += child_stats.files;
            stats.dirs += child_stats.dirs;
            stats.restricted += child_stats.restricted;
        }

        stats
    }

    fn render_into(&self, lines: &mut Vec<String>, depth: usize) {
        let indent = "  ".repeat(depth + 1);

        for (idx, (name, restricted)) in self.files.iter().enumerate() {
            if idx >= MAX_RENDER_FILES {
                lines.push(format!(
                    "{indent}... (+{} more files)",
                    self.files.len() - MAX_RENDER_FILES
                ));
                break;
            }

            if *restricted {
                lines.push(format!("{indent}{name}  (Acceso Restringido)"));
            } else {
                lines.push(format!("{indent}{name}"));
            }
        }

        for (idx, (name, child)) in self.dirs.iter().enumerate() {
            if idx >= MAX_RENDER_DIRS {
                lines.push(format!(
                    "{indent}... (+{} more directories)",
                    self.dirs.len() - MAX_RENDER_DIRS
                ));
                break;
            }

            let stats = child.stats();
            lines.push(format!(
                "{}{name}/ [files: {}, dirs: {}, restricted: {}]",
                indent, stats.files, stats.dirs, stats.restricted
            ));

            if depth + 1 < MAX_RENDER_DEPTH {
                child.render_into(lines, depth + 1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn load_mcpignore(root: &Path) -> Vec<String> {
    let path = root.join(".mcpignore");
    std::fs::read_to_string(&path)
        .map(|content| {
            content
                .lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .map(|l| l.trim().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn build_glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Some(rel_pat) = pattern.strip_prefix('/') {
            let glob1 =
                Glob::new(rel_pat).with_context(|| format!("Invalid glob pattern: {pattern}"))?;
            builder.add(glob1);
            let glob2 = Glob::new(&format!("{rel_pat}/**"))
                .with_context(|| format!("Invalid glob pattern: {pattern}/**"))?;
            builder.add(glob2);
        } else {
            let glob1 =
                Glob::new(pattern).with_context(|| format!("Invalid glob pattern: {pattern}"))?;
            builder.add(glob1);
            let glob2 = Glob::new(&format!("**/{pattern}"))
                .with_context(|| format!("Invalid glob pattern: **/{pattern}"))?;
            builder.add(glob2);
            let glob3 = Glob::new(&format!("{pattern}/**"))
                .with_context(|| format!("Invalid glob pattern: {pattern}/**"))?;
            builder.add(glob3);
            let glob4 = Glob::new(&format!("**/{pattern}/**"))
                .with_context(|| format!("Invalid glob pattern: **/{pattern}/**"))?;
            builder.add(glob4);
        }
    }
    Ok(Some(builder.build()?))
}

fn walk_files(root: &Path, matcher: Option<&GlobSet>) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut allowed: Vec<PathBuf> = Vec::new();
    let mut restricted: Vec<PathBuf> = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .ignore(true) // Respect .gitignore
        .git_ignore(true)
        .build();

    for entry in walker {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }

        let path = entry.path().to_path_buf();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let rel_str = rel.to_string_lossy();

        // Skip the Rust build output and VCS metadata
        if rel_str.starts_with("target/") || rel_str.starts_with(".git/") {
            continue;
        }

        let is_restricted = matcher.as_ref().is_some_and(|m| m.is_match(rel));

        if is_restricted {
            restricted.push(path);
        } else {
            allowed.push(path);
        }
    }

    Ok((allowed, restricted))
}

#[cfg(test)]
mod tests {
    use super::FileIndex;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_root(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "nexusintellicore_{test_name}_{}_{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(&root).expect("temp root should be created");
        root
    }

    #[test]
    fn rebuild_moves_file_from_allowed_to_restricted_after_mcpignore_change() {
        let root = make_temp_root("rebuild_restriction");
        let secret = root.join("src/secret.rs");
        std::fs::create_dir_all(secret.parent().expect("parent should exist"))
            .expect("src dir should be created");
        std::fs::write(&secret, "fn hidden() {}\n").expect("fixture file should be written");

        let initial = FileIndex::build(&root).expect("initial index should build");
        assert!(
            initial.allowed_files.iter().any(|p| p == &secret),
            "secret file should start as allowed"
        );
        assert!(
            !initial.restricted_files.iter().any(|p| p == &secret),
            "secret file should not start as restricted"
        );

        std::fs::write(root.join(".mcpignore"), "src/secret.rs\n")
            .expect(".mcpignore should be written");

        let rebuilt = FileIndex::build(&root).expect("rebuilt index should build");
        assert!(
            rebuilt.restricted_files.iter().any(|p| p == &secret),
            "secret file should become restricted after refresh"
        );
        assert!(
            !rebuilt.allowed_files.iter().any(|p| p == &secret),
            "secret file should leave allowed files after refresh"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn is_restricted_accepts_relative_paths() {
        let root = make_temp_root("relative_path_check");
        let secret = root.join("src/secret.rs");
        std::fs::create_dir_all(secret.parent().expect("parent should exist"))
            .expect("src dir should be created");
        std::fs::write(&secret, "fn hidden() {}\n").expect("fixture file should be written");
        std::fs::write(root.join(".mcpignore"), "src/secret.rs\n")
            .expect(".mcpignore should be written");

        let index = FileIndex::build(&root).expect("index should build");
        assert!(index.is_restricted(std::path::Path::new("src/secret.rs")));
        assert!(index.is_restricted(&secret));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn indexer_limits_defaults_match_constants() {
        let l = super::IndexerLimits::defaults();
        assert_eq!(l.max_render_depth, super::MAX_RENDER_DEPTH);
        assert_eq!(l.max_render_files_per_dir, super::MAX_RENDER_FILES);
        assert_eq!(l.max_render_dirs_per_dir, super::MAX_RENDER_DIRS);
    }
}
