; Python — blacklist filtering of "../" or "<script" instead of allowlisting.
(call
  function: (attribute attribute: (identifier) @_m (#eq? @_m "replace"))
  arguments: (argument_list . (string) @_p (#match? @_p "(?i)(\\.[\\\\]*\\.[\\\\]*[/\\\\]|<\\s*script|javascript:)"))) @weak_validation
(call
  function: (attribute object: (identifier) @_o (#eq? @_o "re") attribute: (identifier) @_m (#eq? @_m "sub"))
  arguments: (argument_list . (string) @_p (#match? @_p "(?i)(\\.[\\\\]*\\.[\\\\]*[/\\\\]|<\\s*script|javascript:)"))) @weak_validation
((comparison_operator (string) @_p (#match? @_p "^[\"']\\.\\.[/\\\\]*[\"']$")) @weak_validation
  (#match? @weak_validation " in "))
