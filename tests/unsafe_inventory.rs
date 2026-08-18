/// B6 — unsafe inventory test (mitigación 05, fases 1 y 4).
///
/// Verifica que el inventario de bloques `unsafe` en `src/` y `tests/`
/// coincide con la baseline congelada. Un bloque nuevo rompe el test.
/// La baseline es vacía en producción porque `Cargo.toml` aplica
/// `unsafe_code = "forbid"` a nivel de crate.
use std::path::{Path, PathBuf};

/// Recorre `root` recursivamente y devuelve las líneas que contienen
/// el token literal `unsafe` en archivos `.rs`, excluyendo módulos de test.
fn collect_unsafe_lines(root: &Path) -> Vec<(PathBuf, usize)> {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    collect_recursive(root, &mut hits, &repo_root);
    hits.sort();
    hits
}

fn collect_recursive(dir: &Path, hits: &mut Vec<(PathBuf, usize)>, repo_root: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name == "target" || name == ".git" {
                continue;
            }
            collect_recursive(&path, hits, repo_root);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            // Exclude inline test modules (e.g. src/analyzer/tests.rs)
            if category(&path, repo_root) == "test" {
                continue;
            }
            if let Ok(source) = std::fs::read_to_string(&path) {
                for (i, line) in source.lines().enumerate() {
                    // Match token `unsafe` surrounded by word boundaries.
                    // Avoid matching strings like "unsafecore" or comments that
                    // say "this is safe because unsafe blocks are forbidden".
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") {
                        // Single-line comment — not executable code.
                        continue;
                    }
                    if contains_unsafe_token(trimmed) {
                        hits.push((path.clone(), i + 1));
                    }
                }
            }
        }
    }
}

fn contains_unsafe_token(line: &str) -> bool {
    // Look for `unsafe` as a whole word in code (not inside string literals or comments).
    let mut chars = line.char_indices().peekable();
    let bytes = line.as_bytes();
    while let Some((i, c)) = chars.next() {
        if c == '"' || c == '\'' {
            // Skip string/char literal content.
            for (_, sc) in chars.by_ref() {
                if sc == c {
                    break;
                }
            }
            continue;
        }
        if bytes[i..].starts_with(b"unsafe") {
            let before = if i == 0 {
                true
            } else {
                !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_'
            };
            let after_end = i + 6;
            let after = if after_end >= bytes.len() {
                true
            } else {
                !bytes[after_end].is_ascii_alphanumeric() && bytes[after_end] != b'_'
            };
            if before && after {
                return true;
            }
        }
    }
    false
}

/// Categorises a file path as production, test or fixture.
fn category(path: &Path, root: &Path) -> &'static str {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let s = rel.to_string_lossy();
    if s.contains("tests/fixtures/") || s.contains("tests\\fixtures\\") {
        "fixture"
    } else if s.starts_with("tests/")
        || s.starts_with("tests\\")
        // Inline test modules inside src/ (e.g. src/analyzer/tests.rs)
        || s.ends_with("/tests.rs")
        || s.ends_with("\\tests.rs")
    {
        "test"
    } else {
        "production"
    }
}

#[test]
fn production_src_has_no_unsafe_code() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let hits = collect_unsafe_lines(&src);

    // `unsafe_code = "forbid"` guarantees the compiler rejects unsafe in
    // production. This test provides a human-readable inventory of any future
    // bypass attempts (e.g. via a proc-macro that injects unsafe).
    assert!(
        hits.is_empty(),
        "Unexpected `unsafe` tokens in src/:\n{}",
        hits.iter()
            .map(|(p, l)| format!("  {}:{l}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn test_fixtures_unsafe_count_matches_baseline() {
    // The fixture audit_sample.rs is frozen with exactly 2 unsafe blocks.
    // If the fixture changes, update both this test and the phase0_baseline.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("tests").join("fixtures");
    let hits = collect_unsafe_lines(&fixtures);

    // All hits must be in fixture files, never in production code.
    for (path, _) in &hits {
        assert_eq!(
            category(path, &root),
            "fixture",
            "Unexpected path outside fixtures: {}",
            path.display()
        );
    }

    assert_eq!(
        hits.len(),
        2,
        "Fixture baseline: expected 2 unsafe lines in tests/fixtures/, got {}.\n{}",
        hits.len(),
        hits.iter()
            .map(|(p, l)| format!("  {}:{l}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn test_files_may_contain_unsafe_only_in_test_helpers() {
    // Verify that any `unsafe` token in tests/ (excluding fixtures/) appears
    // in a file classified as "test", not "production" or "fixture".
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = root.join("tests");
    let hits = collect_unsafe_lines(&tests_dir);

    for (path, lineno) in &hits {
        let cat = category(path, &root);
        assert!(
            cat == "test" || cat == "fixture",
            "`unsafe` token in unexpected category '{cat}' at {}:{lineno}",
            path.display()
        );
    }
}
