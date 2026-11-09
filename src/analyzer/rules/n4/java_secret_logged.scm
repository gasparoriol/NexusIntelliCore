; Java — secret-named variable passed to a logger or stdout.
(method_invocation
  object: (_) @_o (#match? @_o "(?i)((^|\\.)(log|logger)|^System\\.(out|err))$")
  name: (identifier) @_m (#match? @_m "^(trace|debug|info|warn|error|fatal|print|println|printf|format)$")
  arguments: (argument_list [
    (identifier) @_a
    (field_access field: (identifier) @_a)
    (binary_expression [(identifier) @_a (binary_expression (identifier) @_a)])])
  (#match? @_a "(?i)^\\w*(password|passwd|secret|token|apikey|api_key|credential)s?$")) @secret_logged
