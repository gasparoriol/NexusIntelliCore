; C — OpenSSL / libcurl peer verification disabled.
(call_expression
  function: (identifier) @_f (#match? @_f "^(SSL_CTX_set_verify|SSL_set_verify)$")
  arguments: (argument_list . (_) . (identifier) @_m (#eq? @_m "SSL_VERIFY_NONE"))) @tls_off
(call_expression
  function: (identifier) @_f (#eq? @_f "curl_easy_setopt")
  arguments: (argument_list
    . (_)
    . (identifier) @_o (#match? @_o "^CURLOPT_SSL_VERIFY(PEER|HOST)$")
    . (number_literal) @_v (#match? @_v "^0[lL]?$"))) @tls_off
