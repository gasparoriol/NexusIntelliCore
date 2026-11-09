; Java — trust managers / hostname verifiers that accept everything.
(method_declaration
  name: (identifier) @_n (#eq? @_n "checkServerTrusted")
  body: (block) @_b (#match? @_b "^\\{\\s*\\}$")) @tls_off
(method_declaration
  name: (identifier) @_n (#eq? @_n "verify")
  parameters: (formal_parameters) @_p (#match? @_p "SSLSession")
  body: (block . (return_statement (true)) .)) @tls_off
(method_invocation
  name: (identifier) @_m (#match? @_m "^(setHostnameVerifier|setDefaultHostnameVerifier|setSSLHostnameVerifier)$")
  arguments: (argument_list (_) @_a (#match? @_a "(->\\s*true|NoopHostnameVerifier|AllowAllHostnameVerifier|ALLOW_ALL)"))) @tls_off
(object_creation_expression
  type: (type_identifier) @_t (#match? @_t "^(NoopHostnameVerifier|AllowAllHostnameVerifier|TrustAllStrategy)$")) @tls_off
