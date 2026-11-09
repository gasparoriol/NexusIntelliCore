; Rust — SQL built with format! for sqlx / diesel / rusqlite.
(call_expression
  function: [
    (identifier) @_f
    (scoped_identifier name: (identifier) @_f)
    (field_expression field: (field_identifier) @_f)]
  (#match? @_f "^(query|query_as|sql_query|execute|prepare|query_row)$")
  arguments: (arguments . [
    (macro_invocation macro: (identifier) @_m (#eq? @_m "format"))
    (reference_expression value: (macro_invocation macro: (identifier) @_m (#eq? @_m "format")))] @_q
    (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b"))) @sql_dynamic
