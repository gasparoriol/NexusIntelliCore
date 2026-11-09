; JS/TS — module loaded from a non-literal specifier.
(call_expression
  function: [(identifier) @_f (#eq? @_f "require") (import)]
  arguments: (arguments . (_) @_a (#not-match? @_a "^([\"'][^\"']*[\"']|`[^`$]*`)$"))) @reflection
