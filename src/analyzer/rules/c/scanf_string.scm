; C — scanf family reading "%s" without a field width.
(call_expression
  function: (identifier) @_f (#match? @_f "^(scanf|vscanf)$")
  arguments: (argument_list . (string_literal) @_fmt (#match? @_fmt "%s"))) @scanf
(call_expression
  function: (identifier) @_f (#match? @_f "^(fscanf|sscanf|vfscanf|vsscanf)$")
  arguments: (argument_list . (_) . (string_literal) @_fmt (#match? @_fmt "%s"))) @scanf
