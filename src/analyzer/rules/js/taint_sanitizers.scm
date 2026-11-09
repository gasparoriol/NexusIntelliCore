; Numeric conversion neutralises every injection class.
(call_expression
  function: (identifier) @_f (#match? @_f "^(parseInt|parseFloat|Number|Boolean)$")) @sanitizer

; Redirect / SSRF / log: URL-encoding a component removes scheme, host and CR/LF.
(call_expression
  function: (identifier) @_f (#eq? @_f "encodeURIComponent")) @sanitizer.redirect
(call_expression
  function: (identifier) @_f (#eq? @_f "encodeURIComponent")) @sanitizer.ssrf
(call_expression
  function: (identifier) @_f (#eq? @_f "encodeURIComponent")) @sanitizer.log

; Path: keep only the file name component.
(call_expression
  function: (member_expression
    object: (identifier) @_o (#eq? @_o "path")
    property: (property_identifier) @_m (#eq? @_m "basename"))) @sanitizer.path

; Path: confinement guard `p.startsWith(base + path.sep)` in a condition.
(call_expression
  function: (member_expression
    object: (_) @guard.path
    property: (property_identifier) @_m (#eq? @_m "startsWith"))
  arguments: (arguments (_) @_a (#match? @_a "sep|[\"'`]/[\"'`]")))

; SQL: driver escaping helpers (`connection.escape`, `pg.escapeLiteral`…).
(call_expression
  function: (member_expression
    property: (property_identifier) @_m (#match? @_m "^(escape|escapeId|literal|escapeLiteral|escapeIdentifier)$"))) @sanitizer.sql

; Command: shell quoting helpers.
(call_expression
  function: (identifier) @_f (#match? @_f "^(shellescape|shellEscape|escapeShellArg|quote)$")) @sanitizer.cmd

; Log: CR/LF stripping.
(call_expression
  function: (member_expression
    property: (property_identifier) @_m (#match? @_m "^(replace|replaceAll)$"))
  arguments: (arguments . (_) @_lit (#match? @_lit "\\\\[rn]"))) @sanitizer.log
