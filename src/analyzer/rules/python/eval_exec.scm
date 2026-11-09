; Python — `eval(…)` and `exec(…)` calls.
(call
  function: (identifier) @fn_name
  (#match? @fn_name "^(eval|exec)$"))
@dangerous_call
