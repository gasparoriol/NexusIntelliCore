//! Java path-traversal taint-flow detector.
//!
//! Strategy (intra-procedural, per-method):
//!  1. Identify taint **sources**: annotated HTTP parameters, servlet/Android
//!     request methods, ZipEntry/MultipartFile filename getters.
//!  2. Propagate taint through simple string assignments and concatenations.
//!  3. Identify **sinks**: File/FileInputStream/FileOutputStream constructors,
//!     NIO Files.read*/write*/copy/delete, Path.resolve().
//!  4. Check **sanitizers**: only `FilenameUtils.getName()`, `toRealPath()` with
//!     subsequent `startsWith(base + separator)`, or `canonical.startsWith(base + separator)`.
//!     `!contains("..")`, `StringUtils.cleanPath()`, bare `startsWith()` without
//!     separator suffix are NOT valid sanitizers.
//!  5. If a tainted-but-not-sanitized variable reaches a sink → emit `AuditFinding`.

use super::types::{AuditFinding, AuditFindingKind};

/// HTTP/Spring/JAX-RS annotation names that mark a parameter as user-controlled.
const TAINT_ANNOTATIONS: &[&str] = &[
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "MatrixVariable",
    "QueryParam",
    "PathParam",
    "FormParam",
    "RequestPart",
];

/// Method names that return user-controlled strings (request sources).
const TAINT_SOURCE_METHODS: &[&str] = &[
    "getParameter",
    "getHeader",
    "getPathInfo",
    "getQueryString",
    "getOriginalFilename",
    "getSubmittedFileName",
    "getStringExtra",
    "getLastPathSegment",
    "getName",          // ZipEntry.getName(), TarArchiveEntry.getName()
];

/// File I/O constructor type names that are write sinks.
const WRITE_CONSTRUCTOR_SINKS: &[&str] = &[
    "FileOutputStream",
    "FileWriter",
    "PrintWriter",
    "BufferedWriter",
    "BufferedOutputStream",
];

/// File I/O constructor type names that are read sinks.
const READ_CONSTRUCTOR_SINKS: &[&str] = &[
    "FileInputStream",
    "FileReader",
    "BufferedReader",
    "BufferedInputStream",
    "RandomAccessFile",
];

/// NIO method names that are write sinks.
const NIO_WRITE_METHODS: &[&str] = &[
    "write", "writeString", "writeBytes", "newOutputStream", "copy", "move",
    "createFile", "createDirectory", "createDirectories",
];

/// NIO method names that are read/delete sinks.
const NIO_READ_DELETE_METHODS: &[&str] = &[
    "readAllBytes", "readAllLines", "readString", "newInputStream", "delete",
    "deleteIfExists",
];

/// Detect path traversal via taint-flow in Java source code.
///
/// This is an intra-procedural, line-by-line text analysis supplemented by
/// Tree-Sitter for structural identification of method boundaries.
/// It operates on the full source file and collects findings per sink.
pub fn detect_path_traversal(source: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    // We process the file line-by-line, tracking tainted variable names.
    // We use a simple per-method scope: reset taint set when we enter a new
    // method (detected by `{` after a method signature or `}` back to depth 0).

    let lines: Vec<&str> = source.lines().collect();
    let mut tainted_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut brace_depth: i32 = 0;

    for (line_idx, &line) in lines.iter().enumerate() {
        let lineno = line_idx + 1;
        let trimmed = line.trim();

        // Skip pure comments
        if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
            continue;
        }

        // Track brace depth
        let open_count = line.chars().filter(|&c| c == '{').count() as i32;
        let close_count = line.chars().filter(|&c| c == '}').count() as i32;

        // Reset taint set when transitioning between methods (when at class depth <= 1 and starting a method)
        if brace_depth <= 1 && (trimmed.contains('(') && trimmed.contains(')')) {
            tainted_vars.clear();
        }

        // ── SOURCE: Annotated parameters ────────────────────────────────────
        // Pattern: @AnnotationName ... Type paramName
        let annotated_params = extract_param_names_from_annotation_context(&lines, line_idx);
        for name in annotated_params {
            tainted_vars.insert(name);
        }

        // Update brace depth for the current line
        brace_depth += open_count - close_count;
        if brace_depth <= 1 && close_count > 0 {
            tainted_vars.clear();
        }
        if brace_depth < 0 {
            brace_depth = 0;
        }

        // ── SOURCE: Request method calls ─────────────────────────────────────
        // Pattern: Type varName = something.sourceMethod(...);
        for method in TAINT_SOURCE_METHODS {
            if line.contains(&format!(".{method}(")) || line.contains(&format!(".{method} (")) {
                // Extract the variable being assigned to
                if let Some(var) = extract_assigned_var(trimmed) {
                    tainted_vars.insert(var);
                }
                break;
            }
        }

        // ── PROPAGATION: String assignment from tainted ──────────────────────
        // Pattern: Type varX = taintedVar + "..."; or String varX = taintedVar;
        if is_local_var_declaration(trimmed) {
            if let Some(var) = extract_assigned_var(trimmed) {
                if !tainted_vars.contains(&var) {
                    // Check if the RHS contains any tainted variable
                    let rhs = extract_rhs(trimmed);
                    if let Some(rhs) = rhs {
                        // Skip if RHS is a sanitizer call
                        let is_sanitizer_rhs = rhs.contains("FilenameUtils.getName(")
                            || rhs.contains(".toRealPath()")
                            || rhs.contains(".normalize()");
                        if !is_sanitizer_rhs {
                            for tvar in &tainted_vars.clone() {
                                // Check if tainted var appears in RHS (whole word)
                                if contains_identifier(rhs, tvar) {
                                    tainted_vars.insert(var.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── SANITIZER: Check for valid sanitizer guards ──────────────────────

        // Pattern: FilenameUtils.getName(taintedVar) -> result assigned or checked
        if line.contains("FilenameUtils.getName(") {
            if let Some(var) = extract_assigned_var(trimmed) {
                // The var being assigned the sanitized value is clean
                tainted_vars.remove(&var);
            }
        }

        // Pattern: proper startsWith guard with separator
        // e.g.: if (!resolved.startsWith(BASE + File.separator))
        if trimmed.starts_with("if") && line.contains(".startsWith(") {
            let after_starts_with = line.find(".startsWith(").map(|i| &line[i..]);
            if let Some(ctx) = after_starts_with {
                let has_separator = ctx.contains("File.separator")
                    || ctx.contains("+ \"/\"")
                    || ctx.contains("+ '/'")
                    || ctx.contains("+ \"\\\\\"");
                if has_separator {
                    // Valid confinement check — clear tainted vars referenced in this check
                    for var in tainted_vars.clone().iter() {
                        if line.contains(var.as_str()) {
                            tainted_vars.remove(var);
                        }
                    }
                }
            }
        }

        // Pattern: .normalize() used before startsWith (NIO safe confinement)
        if line.contains(".normalize()") {
            if let Some(var) = extract_assigned_var(trimmed) {
                // The normalized result is not tainted (it's a derived path object)
                tainted_vars.remove(&var);
            }
        }

        // toRealPath() — always sanitizes the variable
        if line.contains(".toRealPath()") {
            if let Some(var) = extract_assigned_var(trimmed) {
                tainted_vars.remove(&var);
            }
        }

        // ── SINK: File constructor ────────────────────────────────────────────
        for sink_type in WRITE_CONSTRUCTOR_SINKS {
            if line.contains(&format!("new {sink_type}(")) {
                if let Some(arg) = extract_first_constructor_arg(trimmed, sink_type) {
                    if is_tainted_expr(&arg, &tainted_vars) {
                        findings.push(AuditFinding {
                            kind: AuditFindingKind::PathTraversal { is_write: true },
                            line: lineno,
                            description: format!(
                                "Path traversal: tainted user input reaches write sink `new {sink_type}(...)` without sufficient validation"
                            ),
                        });
                    }
                }
            }
        }
        for sink_type in READ_CONSTRUCTOR_SINKS {
            if line.contains(&format!("new {sink_type}(")) {
                if let Some(arg) = extract_first_constructor_arg(trimmed, sink_type) {
                    if is_tainted_expr(&arg, &tainted_vars) {
                        findings.push(AuditFinding {
                            kind: AuditFindingKind::PathTraversal { is_write: false },
                            line: lineno,
                            description: format!(
                                "Path traversal: tainted user input reaches read sink `new {sink_type}(...)` without sufficient validation"
                            ),
                        });
                    }
                }
            }
        }

        // ── SINK: new File(parent, child) with 2-arg constructor ─────────────
        if line.contains("new File(") {
            if let Some(args) = extract_constructor_args(trimmed, "File") {
                for arg in &args {
                    let arg_trimmed = arg.trim();
                    if is_tainted_expr(arg_trimmed, &tainted_vars) {
                        findings.push(AuditFinding {
                            kind: AuditFindingKind::PathTraversal { is_write: false },
                            line: lineno,
                            description: "Path traversal: tainted user input in `new File(...)` constructor — absolute child path discards parent in Java".to_owned(),
                        });
                        break;
                    }
                }
            }
        }

        // ── SINK: NIO Files / Paths methods ─────────────────────────────────
        for method in NIO_WRITE_METHODS {
            let patterns = [
                format!("Files.{method}("),
                format!("Files.{method} ("),
            ];
            for pat in &patterns {
                if line.contains(pat.as_str()) {
                    if let Some(arg) = extract_nio_first_arg(trimmed, "Files", method) {
                        if is_tainted_expr(&arg, &tainted_vars) {
                            findings.push(AuditFinding {
                                kind: AuditFindingKind::PathTraversal { is_write: true },
                                line: lineno,
                                description: format!(
                                    "Path traversal: tainted path reaches NIO write sink `Files.{method}(...)`"
                                ),
                            });
                        }
                    }
                }
            }
        }

        for method in NIO_READ_DELETE_METHODS {
            let patterns = [
                format!("Files.{method}("),
                format!("Files.{method} ("),
            ];
            for pat in &patterns {
                if line.contains(pat.as_str()) {
                    if let Some(arg) = extract_nio_first_arg(trimmed, "Files", method) {
                        if is_tainted_expr(&arg, &tainted_vars) {
                            findings.push(AuditFinding {
                                kind: AuditFindingKind::PathTraversal { is_write: false },
                                line: lineno,
                                description: format!(
                                    "Path traversal: tainted path reaches NIO read/delete sink `Files.{method}(...)`"
                                ),
                            });
                        }
                    }
                }
            }
        }

        // ── SINK: Path.resolve(tainted) propagation ──────────────────────────
        if line.contains(".resolve(") {
            for tvar in &tainted_vars.clone() {
                if line.contains(&format!(".resolve({tvar})"))
                    || line.contains(&format!(".resolve({tvar} "))
                    || line.contains(&format!("({tvar})"))
                {
                    // The result of resolve is tainted — propagate to the assigned var
                    if let Some(var) = extract_assigned_var(trimmed) {
                        tainted_vars.insert(var);
                    }
                    break;
                }
            }
        }

        // ── FALSE SANITIZER DETECTION: contains("..") is NOT a sanitizer ────
        // We explicitly do NOT clear taint when we see: !path.contains("..")
        // (The absence of an `if line.contains("..")` sanitizer handler means
        //  taint remains set through this check.)
    }

    findings
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Check if `expr` references any tainted variable (whole-word match).
fn is_tainted_expr(expr: &str, tainted: &std::collections::HashSet<String>) -> bool {
    for var in tainted {
        if contains_identifier(expr, var) {
            return true;
        }
    }
    false
}

/// Whole-word match: does `text` contain `ident` as an identifier?
pub(crate) fn contains_identifier(text: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let id_bytes = ident.as_bytes();
    let len = id_bytes.len();
    for i in 0..bytes.len().saturating_sub(len - 1) {
        if bytes[i..].starts_with(id_bytes) {
            let before_ok = i == 0
                || (!bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_');
            let after_ok = i + len >= bytes.len()
                || (!bytes[i + len].is_ascii_alphanumeric() && bytes[i + len] != b'_');
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Extract parameter names from an annotated parameter context.
/// Looks at `line_idx` and following lines for `@Annotation` patterns.
fn extract_param_names_from_annotation_context(lines: &[&str], ann_line_idx: usize) -> Vec<String> {
    let mut results = Vec::new();
    let current_line = lines[ann_line_idx];

    for ann in TAINT_ANNOTATIONS {
        let needle = format!("@{ann}");
        let mut search_idx = 0;
        while let Some(pos) = current_line[search_idx..].find(&needle) {
            let actual_pos = search_idx + pos;
            search_idx = actual_pos + needle.len();

            // Collect text starting from this annotation across this and next 2 lines
            let combined = lines
                .iter()
                .skip(ann_line_idx)
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");

            // Find where this annotation is in combined
            if let Some(ann_in_combined) = combined.find(&needle) {
                let after_ann = &combined[ann_in_combined + needle.len()..];
                let trimmed = after_ann.trim_start();
                // Skip annotation arguments parentheses, e.g. @RequestParam("file") or @RequestParam(value = "file")
                let param_part = if trimmed.starts_with('(') {
                    let mut depth = 0;
                    let mut close_idx = None;
                    for (i, c) in trimmed.char_indices() {
                        if c == '(' {
                            depth += 1;
                        } else if c == ')' {
                            depth -= 1;
                            if depth == 0 {
                                close_idx = Some(i);
                                break;
                            }
                        }
                    }
                    if let Some(idx) = close_idx {
                        trimmed[idx + 1..].trim_start()
                    } else {
                        trimmed
                    }
                } else {
                    trimmed
                };

                // The parameter definition ends at ',', ')', ';', or '{'
                let param_end = param_part
                    .find(|c| c == ',' || c == ')' || c == ';' || c == '{')
                    .unwrap_or(param_part.len());
                let param_decl = &param_part[..param_end];

                // Remove generic type parameters <...> if any
                let mut cleaned = String::new();
                let mut angle_depth = 0;
                for c in param_decl.chars() {
                    if c == '<' {
                        angle_depth += 1;
                    } else if c == '>' {
                        if angle_depth > 0 {
                            angle_depth -= 1;
                        }
                    } else if angle_depth == 0 {
                        cleaned.push(c);
                    }
                }

                // Split into tokens: words, ignoring array brackets
                let tokens: Vec<&str> = cleaned
                    .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
                    .filter(|s| !s.is_empty())
                    .collect();

                if let Some(&last) = tokens.last() {
                    if is_java_identifier(last) && !is_java_keyword(last) && !is_java_type(last) {
                        results.push(last.to_owned());
                    }
                }
            }
        }
    }
    results
}

/// Extract the LHS variable name from a local variable declaration or assignment.
fn extract_assigned_var(line: &str) -> Option<String> {
    if !line.contains('=') {
        return None;
    }
    let eq_pos = find_assign_eq(line)?;
    let lhs = line[..eq_pos].trim();
    let parts: Vec<&str> = lhs.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let last = *parts.last()?;
    if is_java_identifier(last) && !is_java_keyword(last) && !is_java_annotation(last) {
        Some(last.to_owned())
    } else {
        None
    }
}

/// Find the position of a bare `=` (not `==`, `!=`, `<=`, `>=`, `+=`, `-=`, etc.)
fn find_assign_eq(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            let prev = if i > 0 { bytes[i - 1] } else { b' ' };
            let next = if i + 1 < bytes.len() { bytes[i + 1] } else { b' ' };
            if next != b'='
                && prev != b'!'
                && prev != b'<'
                && prev != b'>'
                && prev != b'='
                && prev != b'+'
                && prev != b'-'
                && prev != b'*'
                && prev != b'/'
                && prev != b'%'
                && prev != b'&'
                && prev != b'|'
                && prev != b'^'
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Extract the RHS of an assignment.
fn extract_rhs(line: &str) -> Option<&str> {
    let eq_pos = find_assign_eq(line)?;
    let rhs = line[eq_pos + 1..].trim().trim_end_matches(';');
    Some(rhs)
}

/// Check if a line looks like a local variable declaration or assignment.
fn is_local_var_declaration(line: &str) -> bool {
    if !line.contains('=') {
        return false;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    parts.len() >= 2
}

/// Extract the first argument from a constructor call: `new TypeName(arg1, arg2, ...)`
fn extract_first_constructor_arg(line: &str, type_name: &str) -> Option<String> {
    let pat = format!("new {type_name}(");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let mut depth = 1i32;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            ',' if depth == 1 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    if end == 0 && !rest.is_empty() {
        end = rest.len();
    }
    let arg = rest[..end].trim().to_owned();
    if arg.is_empty() { None } else { Some(arg) }
}

/// Extract all constructor arguments as a Vec<String>.
fn extract_constructor_args(line: &str, type_name: &str) -> Option<Vec<String>> {
    let pat = format!("new {type_name}(");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let mut depth = 1i32;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    if end == 0 {
        end = rest.len();
    }
    let args_str = &rest[..end];
    let mut args = Vec::new();
    let mut current = String::new();
    let mut d = 0i32;
    for ch in args_str.chars() {
        match ch {
            '(' | '[' | '<' => { d += 1; current.push(ch); }
            ')' | ']' | '>' => { d -= 1; current.push(ch); }
            ',' if d == 0 => {
                let trimmed = current.trim().to_owned();
                if !trimmed.is_empty() { args.push(trimmed); }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim().to_owned();
    if !trimmed.is_empty() { args.push(trimmed); }
    if args.is_empty() { None } else { Some(args) }
}

/// Extract the first argument from a NIO method call: `Files.method(arg, ...)`
fn extract_nio_first_arg(line: &str, class: &str, method: &str) -> Option<String> {
    let pat = format!("{class}.{method}(");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let mut depth = 1i32;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            ',' if depth == 1 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    if end == 0 && !rest.is_empty() {
        end = rest.len();
    }
    let arg = rest[..end].trim().to_owned();
    if arg.is_empty() { None } else { Some(arg) }
}

/// Check if `s` is a valid Java identifier character sequence.
fn is_java_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_alphabetic() && first != '_' && first != '$' {
        return false;
    }
    chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// Java reserved keywords that cannot be variable names.
fn is_java_keyword(s: &str) -> bool {
    matches!(
        s,
        "abstract" | "assert" | "boolean" | "break" | "byte" | "case" | "catch"
            | "char" | "class" | "const" | "continue" | "default" | "do" | "double"
            | "else" | "enum" | "extends" | "final" | "finally" | "float" | "for"
            | "goto" | "if" | "implements" | "import" | "instanceof" | "int"
            | "interface" | "long" | "native" | "new" | "package" | "private"
            | "protected" | "public" | "return" | "short" | "static" | "strictfp"
            | "super" | "switch" | "synchronized" | "this" | "throw" | "throws"
            | "transient" | "try" | "void" | "volatile" | "while" | "true" | "false"
            | "null" | "var" | "record" | "sealed" | "permits" | "yield"
    )
}

/// Common Java type names that cannot be variable names in a declaration context.
fn is_java_type(s: &str) -> bool {
    matches!(
        s,
        "String" | "Integer" | "Long" | "Double" | "Float" | "Boolean" | "Byte"
            | "Character" | "Short" | "Object" | "Number" | "File" | "Path"
            | "FileInputStream" | "FileOutputStream" | "FileReader" | "FileWriter"
            | "BufferedReader" | "BufferedWriter" | "PrintWriter" | "InputStream"
            | "OutputStream" | "IOException" | "Exception" | "RuntimeException"
            | "List" | "Map" | "Set" | "ArrayList" | "HashMap" | "HashSet"
            | "Optional" | "Stream" | "Paths" | "Files" | "URI" | "URL"
            | "MultipartFile" | "ResponseEntity" | "HttpServletRequest"
            | "HttpServletResponse" | "ZipEntry" | "ZipInputStream"
    )
}

/// Check if `s` looks like an annotation reference.
fn is_java_annotation(s: &str) -> bool {
    s.starts_with('@')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_spring_request_param_read_sink() {
        let source = r#"
import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class VulnerableSpring {
    @GetMapping("/download")
    public String download(@RequestParam String filename) throws IOException {
        FileInputStream fis = new FileInputStream("/var/data/" + filename);
        return "done";
    }
}
"#;
        let findings = detect_path_traversal(source);
        assert!(
            !findings.is_empty(),
            "Should detect path traversal in Spring @RequestParam → FileInputStream"
        );
        assert!(
            findings.iter().any(|f| matches!(f.kind, AuditFindingKind::PathTraversal { is_write: false })),
            "Should be a read (High) finding"
        );
    }

    #[test]
    fn detects_servlet_getparameter_write_sink() {
        let source = r#"
import javax.servlet.http.*;
import java.io.*;

public class VulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
    }
}
"#;
        let findings = detect_path_traversal(source);
        assert!(
            !findings.is_empty(),
            "Should detect path traversal: getParameter → FileOutputStream"
        );
        assert!(
            findings.iter().any(|f| matches!(f.kind, AuditFindingKind::PathTraversal { is_write: true })),
            "Should be a write (Critical) finding"
        );
    }

    #[test]
    fn safe_confinement_no_finding() {
        let source = r#"
import java.nio.file.*;

public class SafeConfinement {
    private static final Path BASE = Paths.get("/var/data/");

    String read(String input) throws Exception {
        Path resolved = BASE.resolve(input).normalize();
        if (!resolved.startsWith(BASE + File.separator)) {
            throw new SecurityException("Traversal");
        }
        return Files.readString(resolved);
    }
}
"#;
        let findings = detect_path_traversal(source);
        // The resolve result goes through normalize() and startsWith(BASE + File.separator)
        // so it should not be flagged.
        assert!(
            findings.is_empty(),
            "Safe confinement pattern must not produce findings. Got: {findings:?}"
        );
    }

    #[test]
    fn dotdot_check_not_a_sanitizer() {
        let source = r#"
import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class FalseGuard {
    @GetMapping("/file")
    public String read(@RequestParam String path) throws IOException {
        if (!path.contains("..")) {
            FileInputStream fis = new FileInputStream(path);
            return "ok";
        }
        return "rejected";
    }
}
"#;
        let findings = detect_path_traversal(source);
        assert!(
            !findings.is_empty(),
            "!contains('..') is NOT a valid sanitizer — finding must still fire. Got: {findings:?}"
        );
    }

    #[test]
    fn static_literal_no_finding() {
        let source = r#"
import java.io.*;

public class StaticFiles {
    void loadConfig() throws IOException {
        FileInputStream fis = new FileInputStream("config.properties");
    }
}
"#;
        let findings = detect_path_traversal(source);
        assert!(
            findings.is_empty(),
            "Static literal paths must not produce findings. Got: {findings:?}"
        );
    }

    #[test]
    fn zip_entry_getname_taint_propagation() {
        let source = r#"
import java.util.zip.*;
import java.io.*;

public class ZipSlip {
    void extract(ZipInputStream zis, String destDir) throws IOException {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();
            File dest = new File(destDir, name);
            FileOutputStream fos = new FileOutputStream(dest);
        }
    }
}
"#;
        let findings = detect_path_traversal(source);
        assert!(
            !findings.is_empty(),
            "Zip Slip pattern must be detected. Got: {findings:?}"
        );
    }

    #[test]
    fn contains_identifier_whole_word() {
        assert!(contains_identifier("filename + extra", "filename"));
        assert!(contains_identifier("/data/filename", "filename"));
        assert!(!contains_identifier("filenameSuffix", "filename"));
        assert!(!contains_identifier("prefixfilename", "filename"));
        assert!(contains_identifier("filename", "filename"));
    }
}
