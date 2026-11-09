; JS/TS — blacklist filtering of "../" or "<script" instead of allowlisting.
(call_expression
  function: (member_expression property: (property_identifier) @_m (#match? @_m "^(replace|replaceAll)$"))
  arguments: (arguments . [(string) (regex)] @_p (#match? @_p "(?i)(\\.[\\\\]*\\.[\\\\]*[/\\\\]|<\\s*script|javascript:)"))) @weak_validation
(call_expression
  function: (member_expression property: (property_identifier) @_m (#match? @_m "^(includes|indexOf)$"))
  arguments: (arguments . (string) @_p (#match? @_p "^[\"']\\.\\.[/\\\\]*[\"']$"))) @weak_validation
