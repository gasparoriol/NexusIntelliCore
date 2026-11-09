; JS/TS — secret compared with == / === (not constant time).
((binary_expression
  left: (_) @_l (#not-match? @_l "^(null|undefined|true|false|\\d+|\"[^\"]*\"|'[^']*'|`[^`$]*`)$")
  operator: ["==" "==="]
  right: (_) @_r (#not-match? @_r "^(null|undefined|true|false|\\d+|\"[^\"]*\"|'[^']*'|`[^`$]*`)$")) @timing_compare
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b"))
