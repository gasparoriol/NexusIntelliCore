use super::docs::extract_preceding_comment;
use super::lang::Lang;
use super::query::run_named_query;
use super::types::FunctionInfo;
use anyhow::Result;
use tree_sitter::Language;

pub(crate) fn extract_functions(
    root: tree_sitter::Node<'_>,
    source: &str,
    lang: &Lang,
    ts_lang: &Language,
) -> Result<Vec<FunctionInfo>> {
    let query_str = match lang {
        Lang::Rust => "(function_item name: (identifier) @name) @fn",
        Lang::Python => "(function_definition name: (identifier) @name) @fn",
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            // function_declaration + class method_definition +
            // interface method_signature + const/let arrow/function expressions
            "[(function_declaration name: (identifier) @name) @fn \
              (method_definition name: (property_identifier) @name) @fn \
              (method_signature name: (property_identifier) @name) @fn \
              (variable_declarator name: (identifier) @name \
                value: [(arrow_function) (function_expression)]) @fn]"
        }
        Lang::Java => {
            "[(method_declaration name: (identifier) @name) @fn \
              (constructor_declaration name: (identifier) @name) @fn]"
        }
        Lang::C => {
            // Captures plain functions; pointer-returning functions
            // (ptr_declarator wrapping function_declarator) are not covered here.
            "(function_definition \
               declarator: (function_declarator \
                 declarator: (identifier) @name)) @fn"
        }
        Lang::CSharp => {
            "[(method_declaration name: (identifier) @name) @fn \
              (constructor_declaration name: (identifier) @name) @fn \
              (operator_declaration) @fn \
              (destructor_declaration name: (identifier) @name) @fn]"
        }
        Lang::Kotlin | Lang::Unknown | Lang::Css | Lang::Scss | Lang::Sass | Lang::Html => {
            return Ok(vec![])
        }
    };

    let source_lines: Vec<&str> = source.lines().collect();
    run_named_query(ts_lang, query_str, root, source, |_match_idx, caps| {
        // caps: list of (capture_name, node, text)
        let fn_node = caps.iter().find(|(name, _, _)| *name == "fn")?;
        let name_cap = caps.iter().find(|(name, _, _)| *name == "name")?;

        let fn_node_ts = fn_node.1;
        let fn_text = &source[fn_node_ts.byte_range()];
        let name_text = name_cap.2.clone();
        let owner_chain = extract_owner_chain(fn_node_ts, source, lang);

        // Use the AST body-node boundary to correctly delimit the signature.
        // find_body_node only returns block-style bodies, so expression arrow
        // functions fall through to extract_signature (no truncation risk).
        let signature = {
            let fn_start = fn_node_ts.start_byte();
            match find_body_node(fn_node_ts) {
                Some(body_node) if body_node.start_byte() > fn_start => {
                    source[fn_start..body_node.start_byte()].trim().to_owned()
                }
                _ => extract_signature(fn_text),
            }
        };
        let qualified_name = build_qualified_name(&name_text, owner_chain.as_deref(), lang);
        let normalized_signature = normalize_signature(&signature);
        // Python `comment` nodes are tree-sitter "extras" whose position inside
        // the body block is not guaranteed across parser versions. Regex-based
        // detection is safe for Python because `#` in a string literal is
        // extremely unlikely to form a `# @mcp-strip` annotation. For all
        // C-style languages we use the AST path to avoid false positives from
        // `// @mcp-strip` appearing inside a string literal.
        let is_strip = match lang {
            Lang::Python => crate::sanitizer::has_mcp_strip(fn_text),
            _ => has_mcp_strip_in_ast(fn_node_ts, source.as_bytes()),
        };
        let start_line = fn_node_ts.start_position().row + 1;
        let doc_comment = extract_preceding_comment(&source_lines, start_line);
        let is_public = is_public_fn(&signature, &name_text, lang);

        // Populate body_byte_range for C-style brace-delimited bodies.
        // Python uses indentation; body_byte_range is intentionally None.
        let fn_start_byte = fn_node_ts.start_byte();
        let body_byte_range = match lang {
            Lang::Python => None,
            _ => find_body_node(fn_node_ts).map(|body_node| {
                let inner_start = (body_node.start_byte() + 1).saturating_sub(fn_start_byte);
                let inner_end = body_node
                    .end_byte()
                    .saturating_sub(fn_start_byte)
                    .saturating_sub(1);
                (inner_start, inner_end)
            }),
        };

        Some(FunctionInfo {
            name: name_text,
            qualified_name,
            owner_chain,
            signature,
            normalized_signature,
            body_source: fn_text.to_owned(),
            start_line,
            end_line: fn_node_ts.end_position().row + 1,
            is_strip_marked: is_strip,
            body_byte_range,
            doc_comment,
            is_public,
        })
    })
}

fn extract_owner_chain(node: tree_sitter::Node<'_>, source: &str, lang: &Lang) -> Option<String> {
    let mut owners: Vec<String> = Vec::new();
    let mut current = node.parent();

    while let Some(parent) = current {
        match lang {
            Lang::Rust => {
                if parent.kind() == "impl_item" {
                    if let Some(ty) = parent.child_by_field_name("type") {
                        let text = source[ty.byte_range()].trim();
                        if !text.is_empty() {
                            owners.push(text.to_owned());
                        }
                    }
                }
            }
            Lang::Python => {
                if parent.kind() == "class_definition" {
                    if let Some(name) = parent.child_by_field_name("name") {
                        let text = source[name.byte_range()].trim();
                        if !text.is_empty() {
                            owners.push(text.to_owned());
                        }
                    }
                }
            }
            Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
                if parent.kind() == "class_declaration" {
                    if let Some(name) = parent.child_by_field_name("name") {
                        let text = source[name.byte_range()].trim();
                        if !text.is_empty() {
                            owners.push(text.to_owned());
                        }
                    }
                }
            }
            Lang::Java => {
                if matches!(
                    parent.kind(),
                    "class_declaration"
                        | "interface_declaration"
                        | "enum_declaration"
                        | "record_declaration"
                        | "annotation_type_declaration"
                ) {
                    if let Some(name) = parent.child_by_field_name("name") {
                        let text = source[name.byte_range()].trim();
                        if !text.is_empty() {
                            owners.push(text.to_owned());
                        }
                    }
                }
            }
            Lang::CSharp => {
                if matches!(
                    parent.kind(),
                    "class_declaration"
                        | "interface_declaration"
                        | "struct_declaration"
                        | "enum_declaration"
                ) {
                    if let Some(name) = parent.child_by_field_name("name") {
                        let text = source[name.byte_range()].trim();
                        if !text.is_empty() {
                            owners.push(text.to_owned());
                        }
                    }
                }
            }
            Lang::Kotlin
            | Lang::C
            | Lang::Css
            | Lang::Scss
            | Lang::Sass
            | Lang::Html
            | Lang::Unknown => {}
        }
        current = parent.parent();
    }

    if owners.is_empty() {
        None
    } else {
        owners.reverse();
        let sep = if matches!(lang, Lang::Rust) {
            "::"
        } else {
            "."
        };
        Some(owners.join(sep))
    }
}

fn build_qualified_name(name: &str, owner_chain: Option<&str>, lang: &Lang) -> String {
    if let Some(owner) = owner_chain {
        let sep = if matches!(lang, Lang::Rust) {
            "::"
        } else {
            "."
        };
        format!("{}{}{}", owner, sep, name)
    } else {
        name.to_owned()
    }
}

fn normalize_signature(signature: &str) -> Option<String> {
    let normalized = signature.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Detect `@mcp-strip` via AST comment nodes rather than full-text regex.
fn has_mcp_strip_in_ast(func_node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    const MARKER: &[u8] = b"@mcp-strip";

    // Case 1: comment node immediately preceding the function in the same scope
    if let Some(prev) = func_node.prev_named_sibling() {
        if prev.kind().contains("comment") {
            let text = &source[prev.start_byte()..prev.end_byte()];
            if text.windows(MARKER.len()).any(|w| w == MARKER) {
                return true;
            }
        }
    }

    // Case 2: scan leading children of the body block for a comment with @mcp-strip.
    if let Some(body) = func_node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind().contains("comment") {
                let text = &source[child.start_byte()..child.end_byte()];
                if text.windows(MARKER.len()).any(|w| w == MARKER) {
                    return true;
                }
            } else if child.is_named() {
                // First real statement found — stop scanning.
                break;
            }
        }
    }

    false
}

/// Find the block body of a function-like AST node.
fn find_body_node(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let body = node.child_by_field_name("body").or_else(|| {
        // variable_declarator: look inside the arrow/function_expression value
        node.child_by_field_name("value")
            .and_then(|val| val.child_by_field_name("body"))
    })?;

    // Only block-style bodies delimit signatures reliably.
    if matches!(
        body.kind(),
        "block" | "statement_block" | "compound_statement"
    ) {
        Some(body)
    } else {
        None
    }
}

/// Extract function signature (text before the opening brace / body).
pub fn extract_signature(fn_source: &str) -> String {
    if let Some(pos) = fn_source.find('{') {
        fn_source[..pos].trim().to_owned()
    } else {
        // Python: find the last ':' that's followed by a newline (body start)
        let mut depth = 0i32; // track parenthesis nesting
        for (i, ch) in fn_source.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ':' if depth == 0 => {
                    return fn_source[..=i].trim().to_owned();
                }
                _ => {}
            }
        }
        fn_source.trim().to_owned()
    }
}

/// Determine if a function is publicly visible (language-aware heuristic).
pub(crate) fn is_public_fn(signature: &str, name: &str, lang: &Lang) -> bool {
    match lang {
        Lang::Rust => signature.starts_with("pub ") || signature.starts_with("pub("),
        Lang::Java => signature.contains("public "),
        Lang::Python => !name.starts_with('_'),
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            !name.starts_with('_') && !signature.contains("private ") && !signature.contains("#")
        }
        Lang::CSharp => signature.contains("public "),
        Lang::C => true,
        _ => true,
    }
}
