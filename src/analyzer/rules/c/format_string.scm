; C — format string taken from a variable instead of a literal.
(call_expression
  function: (identifier) @_f (#eq? @_f "printf")
  arguments: (argument_list . [(identifier) (field_expression) (subscript_expression) (pointer_expression)])) @format
(call_expression
  function: (identifier) @_f (#match? @_f "^(fprintf|dprintf|sprintf|syslog)$")
  arguments: (argument_list . (_) . [(identifier) (field_expression) (subscript_expression) (pointer_expression)])) @format
(call_expression
  function: (identifier) @_f (#eq? @_f "snprintf")
  arguments: (argument_list . (_) . (_) . [(identifier) (field_expression) (subscript_expression) (pointer_expression)])) @format
