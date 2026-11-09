; Numeric / UUID parsing neutralises every injection class.
(method_invocation
  object: (identifier) @_o (#match? @_o "^(Integer|Long|Short|Byte|Double|Float|Boolean|UUID)$")
  name: (identifier) @_m (#match? @_m "^(parseInt|parseLong|parseShort|parseByte|parseDouble|parseFloat|parseBoolean|valueOf|fromString)$")) @sanitizer

; Path: keep only the file name component.
(method_invocation
  object: (identifier) @_o (#eq? @_o "FilenameUtils")
  name: (identifier) @_m (#match? @_m "^(getName|getBaseName)$")) @sanitizer.path
(method_invocation
  name: (identifier) @_m (#eq? @_m "getFileName")) @sanitizer.path

; Path: confinement guard `p.startsWith(BASE + File.separator)` in a condition.
; A bare `startsWith(BASE)` is NOT accepted: "/data2" passes a "/data" check.
(method_invocation
  object: (_) @guard.path
  name: (identifier) @_m (#eq? @_m "startsWith")
  arguments: (argument_list (_) @_a (#match? @_a "separator|\"/\"|'/'")))

; SQL: ESAPI encoder.
(method_invocation
  name: (identifier) @_m (#eq? @_m "encodeForSQL")) @sanitizer.sql

; Log: CR/LF stripping or escaping.
(method_invocation
  name: (identifier) @_m (#match? @_m "^(replace|replaceAll)$")
  arguments: (argument_list . (_) @_lit (#match? @_lit "\\\\[rn]"))) @sanitizer.log
(method_invocation
  name: (identifier) @_m (#match? @_m "^(escapeJava|encodeForHTML)$")) @sanitizer.log
