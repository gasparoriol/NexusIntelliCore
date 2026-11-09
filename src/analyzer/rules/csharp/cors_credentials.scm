; C# — CORS policy allowing any origin together with credentials.
(invocation_expression
  function: (member_access_expression
    expression: (_) @_e (#match? @_e "(AllowAnyOrigin\\(\\)|SetIsOriginAllowed\\(\\s*\\w*\\s*=>\\s*true\\s*\\))")
    name: (identifier) @_n (#eq? @_n "AllowCredentials"))) @cors
(invocation_expression
  function: (member_access_expression
    expression: (_) @_e (#match? @_e "AllowCredentials\\(\\)")
    name: (identifier) @_n (#eq? @_n "AllowAnyOrigin"))) @cors
