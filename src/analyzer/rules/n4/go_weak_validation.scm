; Go — blacklist filtering of "../" instead of filepath.Clean + prefix check.
(call_expression
  function: (selector_expression
    operand: (identifier) @_p (#eq? @_p "strings")
    field: (field_identifier) @_f (#match? @_f "^(Replace|ReplaceAll)$"))
  arguments: (argument_list . (_) . (interpreted_string_literal) @_s (#match? @_s "(?i)(\\.[\\\\]*\\.[\\\\]*[/\\\\]|<\\s*script|javascript:)"))) @weak_validation
