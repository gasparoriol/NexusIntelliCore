; Go — http.Cookie with Secure/HttpOnly explicitly false.
(composite_literal
  type: (_) @_t (#match? @_t "Cookie$")
  body: (literal_value
    (keyed_element) @cookie (#match? @cookie "^(Secure|HttpOnly)\\s*:\\s*false$")))
