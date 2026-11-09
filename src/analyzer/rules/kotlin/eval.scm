; Kotlin — `eval(…)` and `exec(…)` calls.
(call_expression
  (simple_identifier) @fn_name
  (#match? @fn_name "^(eval|exec)$"))
(call_expression
  (navigation_expression
    (simple_identifier) @fn_name)
  (#match? @fn_name "^(eval|exec)$"))
