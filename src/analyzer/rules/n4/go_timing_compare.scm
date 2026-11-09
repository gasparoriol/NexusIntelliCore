; Go — secret compared with == (use subtle.ConstantTimeCompare / hmac.Equal).
((binary_expression
  left: (_) @_l (#not-match? @_l "^(nil|true|false|\\d+|\"[^\"]*\")$")
  operator: "=="
  right: (_) @_r (#not-match? @_r "^(nil|true|false|\\d+|\"[^\"]*\")$")) @timing_compare
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b"))
