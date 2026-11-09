; Python — SQL built with +, %, f-strings or str.format at the call site.
(call
  function: (attribute attribute: (identifier) @_m (#match? @_m "^(execute|executemany|raw)$"))
  arguments: (argument_list . [
    (binary_operator)
    (string (interpolation))
    (call function: (attribute attribute: (identifier) @_f (#eq? @_f "format")))] @_q
    (#match? @_q "(?i)\\b(select|insert|update|delete|merge)\\b.*\\b(from|into|set|where|values)\\b"))) @sql_dynamic
