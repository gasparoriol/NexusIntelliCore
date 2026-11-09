; Go — os.Stat check followed by opening/writing the path.
(if_statement
  initializer: (_) @_i (#match? @_i "os\\.(Stat|Lstat)\\(")
  consequence: (block) @_b (#match? @_b "os\\.(Open|OpenFile|Create|Remove|WriteFile|ReadFile)\\(")) @toctou
