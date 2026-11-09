; C# — certificate validation callbacks that always succeed.
(assignment_expression
  left: (_) @_l (#match? @_l "ServerCertificate(Custom)?ValidationCallback$")
  right: (lambda_expression body: (boolean_literal) @_b (#eq? @_b "true"))) @tls_off
(member_access_expression
  name: (identifier) @_n (#eq? @_n "DangerousAcceptAnyServerCertificateValidator")) @tls_off
