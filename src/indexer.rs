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

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        match &self.mcpignore_matcher {
            Some(matcher) => matcher.is_match(rel),
            None => false,
        }
    }

    /// Strip the root prefix so paths are relative for display.
    pub fn relative(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.root).unwrap_or(path).to_path_buf()
    }

    /// Render the directory tree as a plain-text string.
    ///
    /// Restricted files are annotated with `(Acceso Restringido)`.
    pub fn render_tree(&self) -> String {
        use std::collections::BTreeMap;

        // Collect all paths (allowed + restricted) with their restriction flag
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

        // Build a nested BTreeMap: dir → list of (filename, restricted)
        let mut dirs: BTreeMap<PathBuf, Vec<(String, bool)>> = BTreeMap::new();

        for (rel, restricted) in &all {
            let parent = rel.parent().unwrap_or(Path::new("")).to_path_buf();
            let filename = rel
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            dirs.entry(parent)
                .or_default()
                .push((filename, *restricted));
        }

        let mut lines = vec![format!("{}/", self.root.display())];

        for (dir, files) in &dirs {
            let depth = dir.components().count();
            let indent = "  ".repeat(depth);
            if depth > 0 {
                lines.push(format!("{}{}/ ", indent, dir.display()));
            }
            let file_indent = "  ".repeat(depth + 1);
            for (name, restricted) in files {
                if *restricted {
                    lines.push(format!("{}{}  (Acceso Restringido)", file_indent, name));
                } else {
                    lines.push(format!("{}{}", file_indent, name));
                }
            }
        }

        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn load_mcpignore(root: &Path) -> Vec<String> {
    let path = root.join(".mcpignore");
    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| l.trim().to_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn build_glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Some(rel_pat) = pattern.strip_prefix('/') {
            let glob1 =
                Glob::new(rel_pat).with_context(|| format!("Invalid glob pattern: {}", pattern))?;
            builder.add(glob1);
            let glob2 = Glob::new(&format!("{}/**", rel_pat))
                .with_context(|| format!("Invalid glob pattern: {}/**", pattern))?;
            builder.add(glob2);
        } else {
            let glob1 =
                Glob::new(pattern).with_context(|| format!("Invalid glob pattern: {}", pattern))?;
            builder.add(glob1);
            let glob2 = Glob::new(&format!("**/{}", pattern))
                .with_context(|| format!("Invalid glob pattern: **/{}", pattern))?;
            builder.add(glob2);
            let glob3 = Glob::new(&format!("{}/**", pattern))
                .with_context(|| format!("Invalid glob pattern: {}/**", pattern))?;
            builder.add(glob3);
            let glob4 = Glob::new(&format!("**/{}/**", pattern))
                .with_context(|| format!("Invalid glob pattern: **/{}/**", pattern))?;
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
        let entry = entry?;
        let ft = match entry.file_type() {
            Some(ft) => ft,
            None => continue,
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

        let is_restricted = match matcher {
            Some(m) => m.is_match(rel),
            None => false,
        };

        if is_restricted {
            restricted.push(path);
        } else {
            allowed.push(path);
        }
    }

    Ok((allowed, restricted))
}
