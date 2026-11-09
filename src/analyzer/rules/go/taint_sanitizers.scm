; Numeric / UUID parsing neutralises every injection class.
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(strconv|uuid)$")
    field: (field_identifier) @_f (#match? @_f "^(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool|Parse|MustParse)$"))) @sanitizer

; Path: keep only the file name component.
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(filepath|path)$")
    field: (field_identifier) @_f (#eq? @_f "Base"))) @sanitizer.path

; Path: confinement guard `strings.HasPrefix(p, base+string(os.PathSeparator))`.
(call_expression
  function: (selector_expression
    operand: (identifier) @_s (#eq? @_s "strings")
    field: (field_identifier) @_f (#eq? @_f "HasPrefix"))
  arguments: (argument_list . (_) @guard.path . (_) @_b (#match? @_b "Separator|\"/\"")))

; Redirect / SSRF / log: escaping.
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "url")
    field: (field_identifier) @_f (#match? @_f "^(PathEscape|QueryEscape)$"))) @sanitizer.redirect
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "url")
    field: (field_identifier) @_f (#match? @_f "^(PathEscape|QueryEscape)$"))) @sanitizer.ssrf
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "strconv")
    field: (field_identifier) @_f (#eq? @_f "Quote"))) @sanitizer.log
(call_expression
  function: (selector_expression
    operand: (identifier) @_s (#eq? @_s "strings")
    field: (field_identifier) @_f (#match? @_f "^(Replace|ReplaceAll)$"))
  arguments: (argument_list . (_) . (interpreted_string_literal) @_lit (#match? @_lit "\\\\[rn]"))) @sanitizer.log
