; Rust — reqwest / native-tls / openssl verification disabled.
(call_expression
  function: (field_expression
    field: (field_identifier) @_m (#match? @_m "^(danger_accept_invalid_certs|danger_accept_invalid_hostnames)$"))
  arguments: (arguments (boolean_literal) @_b (#eq? @_b "true"))) @tls_off
(scoped_identifier
  path: (identifier) @_p (#eq? @_p "SslVerifyMode")
  name: (identifier) @_n (#eq? @_n "NONE")) @tls_off
