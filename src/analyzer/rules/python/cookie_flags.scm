; Python — cookies explicitly marked non-Secure or non-HttpOnly.
(call
  function: (attribute attribute: (identifier) @_m (#eq? @_m "set_cookie"))
  arguments: (argument_list
    (keyword_argument name: (identifier) @_k (#match? @_k "^(secure|httponly)$") value: (false)))) @cookie
(assignment
  left: (identifier) @_l (#match? @_l "^(SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY)$")
  right: (false)) @cookie
