; C# — SQL built with + or interpolation for ADO.NET / EF raw SQL.
(object_creation_expression
  type: (identifier) @_t (#match? @_t "^(SqlCommand|NpgsqlCommand|MySqlCommand|SqliteCommand|OleDbCommand)$")
  arguments: (argument_list . (argument [(binary_expression) (interpolated_string_expression)] @_q
    (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b")))) @sql_dynamic
(invocation_expression
  function: (member_access_expression name: (identifier) @_m (#match? @_m "^(FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync)$"))
  arguments: (argument_list . (argument [(binary_expression) (interpolated_string_expression)] @_q
    (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b")))) @sql_dynamic
