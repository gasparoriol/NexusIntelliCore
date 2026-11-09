; Numeric / UUID conversion neutralises every injection class.
(call_expression
  (navigation_expression
    (_)
    (navigation_suffix (simple_identifier) @_m
      (#match? @_m "^(toInt|toLong|toIntOrNull|toLongOrNull|toDouble|parseInt|parseLong|fromString)$")))) @sanitizer
