; Parsing into a primitive (`x.parse::<i64>()`) neutralises every injection class.
(call_expression
  function: (generic_function
    function: (field_expression field: (field_identifier) @_m (#eq? @_m "parse"))
    type_arguments: (type_arguments (primitive_type)))) @sanitizer
(call_expression
  function: (scoped_identifier
    path: (identifier) @_p (#eq? @_p "Uuid")
    name: (identifier) @_n (#match? @_n "^(parse_str|try_parse)$"))) @sanitizer

; Command: shell escaping.
(call_expression
  function: (scoped_identifier
    path: (_) @_p (#match? @_p "shell_escape")
    name: (identifier) @_n (#eq? @_n "escape"))) @sanitizer.cmd
