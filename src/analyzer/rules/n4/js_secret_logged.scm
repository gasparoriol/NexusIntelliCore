; JS/TS — secret-named variable passed to console or a logger.
(call_expression
  function: (member_expression
    object: [(identifier) (member_expression)] @_o (#match? @_o "(^|\\.)(console|logger|log|winston|LOG|LOGGER)$")
    property: (property_identifier) @_m (#match? @_m "^(log|info|warn|error|debug|trace)$"))
  arguments: (arguments [
    (identifier) @_a
    (member_expression property: (property_identifier) @_a)
    (binary_expression (identifier) @_a)
    (template_string (template_substitution [(identifier) @_a (member_expression property: (property_identifier) @_a)]))])
  (#match? @_a "(?i)^\\w*(password|passwd|secret|token|apikey|api_key|credential)s?$")) @secret_logged
