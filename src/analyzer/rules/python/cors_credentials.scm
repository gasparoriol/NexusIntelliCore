; Python — flask-cors with credentials and any origin (default or "*").
(call
  function: (identifier) @_f (#eq? @_f "CORS")
  arguments: (argument_list) @_a
  (#match? @_a "supports_credentials\\s*=\\s*True")
  (#not-match? @_a "origins")) @cors
(call
  function: (identifier) @_f (#eq? @_f "CORS")
  arguments: (argument_list) @_a
  (#match? @_a "supports_credentials\\s*=\\s*True")
  (#match? @_a "origins\\s*=\\s*[\"']\\*[\"']")) @cors
