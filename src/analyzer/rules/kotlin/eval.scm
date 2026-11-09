; Kotlin — `eval(...)` / `exec(...)` calls, bare or on a receiver (`engine.eval(...)`).
(call_expression
  (simple_identifier) @fn_name
  (#match? @fn_name "^(eval|exec)$"))
(call_expression
  (navigation_expression
    (navigation_suffix (simple_identifier) @fn_name))
  (#match? @fn_name "^(eval|exec)$"))
