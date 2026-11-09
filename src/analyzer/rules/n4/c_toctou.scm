; C — access()/stat() followed by open/fopen/unlink of the path.
(if_statement
  condition: (_) @_c (#match? @_c "\\b(access|stat|lstat)\\s*\\(")
  consequence: (_) @_b (#match? @_b "\\b(fopen|open|unlink|remove|rename|chmod|chown)\\s*\\(")) @toctou
