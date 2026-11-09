; C# — secret compared with == (use CryptographicOperations.FixedTimeEquals).
((binary_expression
  left: (_) @_l (#not-match? @_l "^(null|true|false|\\d+|\"[^\"]*\")$")
  operator: "=="
  right: (_) @_r (#not-match? @_r "^(null|true|false|\\d+|\"[^\"]*\")$")) @timing_compare
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b"))
