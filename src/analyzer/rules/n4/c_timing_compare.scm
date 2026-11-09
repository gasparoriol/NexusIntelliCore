; C — secret compared with strcmp/memcmp (use CRYPTO_memcmp).
((call_expression
  function: (identifier) @_f (#match? @_f "^(strcmp|strncmp|memcmp)$")
  arguments: (argument_list . (identifier) . (identifier))) @timing_compare
  (#match? @timing_compare "(?i)(token|hmac|signature|digest|secret|passw(or)?d|otp|api_?key)\\b"))
