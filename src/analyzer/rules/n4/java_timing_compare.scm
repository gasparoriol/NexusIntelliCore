; Java — secret compared with equals() (not constant time).
((method_invocation
  object: (_) @_o (#not-match? @_o "^\"")
  name: (identifier) @_m (#match? @_m "^(equals|contentEquals)$")
  arguments: (argument_list . (_) @_a (#not-match? @_a "^(null|\"[^\"]*\")$") .)) @timing_compare
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b"))
