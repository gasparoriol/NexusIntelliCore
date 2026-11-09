; Python — secret compared with == (not constant time).
((comparison_operator) @timing_compare
  (#match? @timing_compare "==")
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b")
  (#not-match? @timing_compare "==\\s*(None|True|False|\\d+|\"[^\"]*\"|'[^']*')\\s*$")
  (#not-match? @timing_compare "^(None|\\d+|\"[^\"]*\"|'[^']*')\\s*=="))
