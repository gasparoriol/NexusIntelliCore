; Go — error checked and then ignored.
(if_statement
  condition: (binary_expression) @_c (#match? @_c "^err\\s*!=\\s*nil$")
  consequence: (block) @_b (#match? @_b "^\\{\\s*\\}$")) @empty_catch
