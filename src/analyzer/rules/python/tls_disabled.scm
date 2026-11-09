; Python — certificate validation disabled.
(keyword_argument
  name: (identifier) @_k (#eq? @_k "verify")
  value: (false)) @tls_off
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "ssl")
    attribute: (identifier) @_m (#eq? @_m "_create_unverified_context"))) @tls_off
(assignment
  left: (attribute attribute: (identifier) @_a (#match? @_a "^(verify_mode|check_hostname)$"))
  right: (_) @_v (#match? @_v "^((ssl\\.)?CERT_NONE|False)$")) @tls_off
