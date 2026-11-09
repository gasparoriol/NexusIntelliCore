; Rust — `.unwrap()` / `.expect(…)` calls that can panic (DoS precursor).
(call_expression
  function: (field_expression
    field: (field_identifier) @name
    (#match? @name "^(unwrap|expect)$"))) @panic_call
