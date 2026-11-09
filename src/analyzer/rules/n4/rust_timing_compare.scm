; Rust — secret compared with == (use constant_time_eq / subtle).
((binary_expression
  left: (_) @_l (#not-match? @_l "^(None|true|false|\\d+|\"[^\"]*\")$")
  operator: "=="
  right: (_) @_r (#not-match? @_r "^(None|true|false|\\d+|\"[^\"]*\")$")) @timing_compare
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b"))
