; Java — SQL built inline by concatenation / formatting at the call site.
(method_invocation
  name: (identifier) @_m
  (#match? @_m "^(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|query|update|queryForObject|queryForList|addBatch)$")
  arguments: (argument_list . [(binary_expression) (method_invocation)] @_q (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b"))) @sql_dynamic
