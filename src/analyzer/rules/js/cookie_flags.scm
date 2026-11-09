; JS/TS — res.cookie / express-session cookies marked non-secure or non-httpOnly.
(call_expression
  function: (member_expression property: (property_identifier) @_m (#eq? @_m "cookie"))
  arguments: (arguments (object
    (pair key: (property_identifier) @_k (#match? @_k "^(secure|httpOnly)$") value: (false))))) @cookie
(pair
  key: (property_identifier) @_c (#eq? @_c "cookie")
  value: (object
    (pair key: (property_identifier) @_k (#match? @_k "^(secure|httpOnly)$") value: (false)))) @cookie
