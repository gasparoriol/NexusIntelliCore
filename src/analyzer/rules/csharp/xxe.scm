; C# — DTD processing / external resolution enabled.
(assignment_expression
  left: (_) @_l (#match? @_l "(^|\\.)DtdProcessing$")
  right: (_) @_r (#match? @_r "DtdProcessing\\.Parse$")) @xxe
(assignment_expression
  left: (_) @_l (#match? @_l "(^|\\.)XmlResolver$")
  right: (object_creation_expression type: (identifier) @_t (#eq? @_t "XmlUrlResolver"))) @xxe
(assignment_expression
  left: (_) @_l (#match? @_l "(^|\\.)ProhibitDtd$")
  right: (boolean_literal) @_v (#eq? @_v "false")) @xxe
