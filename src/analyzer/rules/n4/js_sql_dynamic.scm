; JS/TS — SQL built with + or template literals at the call site.
(call_expression
  function: (member_expression property: (property_identifier) @_m (#match? @_m "^(query|execute|raw)$"))
  arguments: (arguments . [(binary_expression) (template_string (template_substitution))] @_q
    (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b"))) @sql_dynamic
