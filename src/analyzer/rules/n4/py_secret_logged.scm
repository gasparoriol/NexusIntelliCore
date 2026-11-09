; Python — secret-named variable passed to print/logging.
(call
  function: [
    (identifier) @_f
    (attribute object: (_) @_o (#match? @_o "(^|\\.)(logging|logger|log|LOGGER|LOG|_logger|_log)$") attribute: (identifier) @_f)]
  (#match? @_f "^(print|debug|info|warning|warn|error|critical|exception|log)$")
  arguments: (argument_list [
    (identifier) @_a
    (attribute attribute: (identifier) @_a)
    (binary_operator (identifier) @_a)
    (string (interpolation expression: [(identifier) @_a (attribute attribute: (identifier) @_a)]))])
  (#match? @_a "(?i)^\\w*(password|passwd|secret|token|apikey|api_key|credential)s?$")) @secret_logged
