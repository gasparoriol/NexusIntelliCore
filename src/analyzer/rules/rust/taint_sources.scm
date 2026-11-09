; axum / actix-web extractors in handler parameters (`Query(q): Query<T>`).
(parameter
  pattern: (_) @source.param
  type: (generic_type
    type: [(type_identifier) @_t (scoped_type_identifier name: (type_identifier) @_t)])
  (#match? @_t "^(Query|Path|Json|Form|Multipart)$"))

; Command-line arguments.
(call_expression
  function: (scoped_identifier
    path: (_) @_p (#match? @_p "(^|::)env$")
    name: (identifier) @_n (#match? @_n "^(args|args_os)$"))) @source

; `stdin().read_line(&mut buf)` taints `buf`.
(call_expression
  function: (field_expression
    value: (_) @_r (#match? @_r "stdin")
    field: (field_identifier) @_m (#match? @_m "^(read_line|read_to_string)$"))
  arguments: (arguments (reference_expression value: (identifier) @source.param)))
