; Go — SQL built with + or fmt.Sprintf passed to database/sql.
(call_expression
  function: (selector_expression field: (field_identifier) @_f
    (#match? @_f "^(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Prepare)$"))
  arguments: (argument_list [
    (binary_expression)
    (call_expression function: (selector_expression operand: (identifier) @_p (#eq? @_p "fmt") field: (field_identifier) @_s (#eq? @_s "Sprintf")))] @_q
    (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b"))) @sql_dynamic
