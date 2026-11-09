// Tree-sitter queries reserved for the Java path-traversal taint migration
// (SAST v2, Fase 2).
//
// Structural audit rules live as `.scm` files in `src/analyzer/rules/` and are
// registered in `analyzer::rules::STRUCTURAL_RULES`. Regex-based secret
// detection lives in `sanitizer.rs`.

// ---------------------------------------------------------------------------
// Java — Path Traversal (Taint Flow)
// ---------------------------------------------------------------------------

/// Java — Source: parámetros con anotaciones HTTP (Spring, JAX-RS)
#[allow(dead_code)]
pub const JAVA_TAINT_PARAM_ANNOTATION_QUERY: &str = r#"
  (formal_parameter
    (modifiers
      (annotation
        name: (identifier) @ann_name))
    name: (identifier) @param_name)
  @tainted_param
"#;

/// Java — Source: llamadas a métodos de request HTTP / Servlet / Android que retornan input de usuario
#[allow(dead_code)]
pub const JAVA_TAINT_REQUEST_SOURCE_QUERY: &str = r#"
  (method_invocation
    name: (identifier) @method_name)
  @source_call
"#;

/// Java — Sinks: constructores de File I/O clásicos (read + write combinados)
#[allow(dead_code)]
pub const JAVA_FILE_SINK_CONSTRUCTOR_QUERY: &str = r#"
  (object_creation_expression
    type: (type_identifier) @type_name
    arguments: (argument_list) @sink_args)
  @file_constructor_sink
"#;

/// Java — Sinks: métodos Java NIO (Paths/Files)
#[allow(dead_code)]
pub const JAVA_NIO_SINK_QUERY: &str = r#"
  (method_invocation
    name: (identifier) @method_name
    arguments: (argument_list) @sink_args)
  @nio_sink
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Query;

    /// Verifica que las queries reservadas son S-expressions válidas.
    #[test]
    fn java_taint_param_annotation_query_is_valid() {
        let lang = tree_sitter_java::language();
        assert!(Query::new(&lang, JAVA_TAINT_PARAM_ANNOTATION_QUERY).is_ok());
    }

    #[test]
    fn java_file_sink_constructor_query_is_valid() {
        let lang = tree_sitter_java::language();
        assert!(Query::new(&lang, JAVA_FILE_SINK_CONSTRUCTOR_QUERY).is_ok());
    }

    #[test]
    fn java_nio_sink_query_is_valid() {
        let lang = tree_sitter_java::language();
        assert!(Query::new(&lang, JAVA_NIO_SINK_QUERY).is_ok());
    }

    #[test]
    fn java_taint_request_source_query_is_valid() {
        let lang = tree_sitter_java::language();
        assert!(Query::new(&lang, JAVA_TAINT_REQUEST_SOURCE_QUERY).is_ok());
    }
}
