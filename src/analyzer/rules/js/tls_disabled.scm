; JS/TS — TLS certificate validation disabled.
(pair
  key: [(property_identifier) (string)] @_k (#match? @_k "^['\"]?rejectUnauthorized['\"]?$")
  value: (false)) @tls_off
(pair
  key: (property_identifier) @_k (#eq? @_k "checkServerIdentity")
  value: [(arrow_function) (function_expression)]) @tls_off
(assignment_expression
  left: (member_expression property: (property_identifier) @_p (#eq? @_p "NODE_TLS_REJECT_UNAUTHORIZED"))
  right: (string) @_v (#match? @_v "^['\"]0['\"]$")) @tls_off
