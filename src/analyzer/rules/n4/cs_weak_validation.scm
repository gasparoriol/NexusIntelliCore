; C# — blacklist filtering of "../" or "<script" instead of allowlisting.
(invocation_expression
  function: (member_access_expression name: (identifier) @_m (#eq? @_m "Replace"))
  arguments: (argument_list . (argument (string_literal) @_s (#match? @_s "(?i)(\\.[\\\\]*\\.[\\\\]*[/\\\\]|<\\s*script|javascript:)")))) @weak_validation
