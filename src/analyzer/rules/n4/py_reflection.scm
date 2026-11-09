; Python — attribute or module chosen by a non-literal name.
(call
  function: (identifier) @_f (#eq? @_f "getattr")
  arguments: (argument_list . (_) . (_) @_a (#not-match? @_a "^[\"']"))) @reflection
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#match? @_f "^(__import__|import_module)$")
  arguments: (argument_list . (_) @_a (#not-match? @_a "^[\"']"))) @reflection
