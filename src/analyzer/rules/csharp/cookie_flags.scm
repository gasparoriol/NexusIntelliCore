; C# — cookie options explicitly non-Secure / non-HttpOnly.
(assignment_expression
  left: (_) @_l (#match? @_l "(^|\\.)(Secure|HttpOnly)$")
  right: (boolean_literal) @_v (#eq? @_v "false")) @cookie
(member_access_expression
  expression: (identifier) @_e (#eq? @_e "CookieSecurePolicy")
  name: (identifier) @_n (#eq? @_n "None")) @cookie
