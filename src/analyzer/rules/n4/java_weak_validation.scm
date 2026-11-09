; Java — blacklist filtering of "../" or "<script" instead of allowlisting.
(method_invocation
  name: (identifier) @_m (#match? @_m "^(replace|replaceAll|replaceFirst)$")
  arguments: (argument_list . (string_literal) @_p (#match? @_p "(?i)(\\.[\\\\]*\\.[\\\\]*[/\\\\]|<\\s*script|javascript:)"))) @weak_validation
(method_invocation
  name: (identifier) @_m (#match? @_m "^(contains|indexOf)$")
  arguments: (argument_list . (string_literal) @_p (#match? @_p "^[\"']\\.\\.[/\\\\]*[\"']$"))) @weak_validation
