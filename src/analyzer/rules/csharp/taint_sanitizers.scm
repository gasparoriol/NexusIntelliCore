; Numeric / GUID parsing neutralises every injection class.
(invocation_expression
  function: (member_access_expression
    expression: [(predefined_type) (identifier)] @_t
    (#match? @_t "^(int|long|short|uint|ulong|decimal|double|float|Guid|Int32|Int64|Convert)$")
    name: (identifier) @_n (#match? @_n "^(Parse|ToInt32|ToInt64|ToDecimal|ToDouble)$"))) @sanitizer

; Path: keep only the file name component.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#eq? @_o "Path")
    name: (identifier) @_n (#eq? @_n "GetFileName"))) @sanitizer.path

; Path: confinement guard `full.StartsWith(baseDir + Path.DirectorySeparatorChar)`.
(invocation_expression
  function: (member_access_expression
    expression: (_) @guard.path
    name: (identifier) @_n (#eq? @_n "StartsWith"))
  arguments: (argument_list (argument) @_a (#match? @_a "Separator|\"/\"")))

; Redirect: Url.IsLocalUrl(x) in a condition.
(invocation_expression
  function: (member_access_expression name: (identifier) @_n (#eq? @_n "IsLocalUrl"))
  arguments: (argument_list . (argument) @guard.redirect))

; Redirect / SSRF / log: an encoded URL component cannot change scheme, host
; or path, nor inject CR/LF.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#match? @_o "^(HttpUtility|WebUtility|Uri)$")
    name: (identifier) @_n (#match? @_n "^(UrlEncode|EscapeDataString)$"))) @sanitizer.redirect
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#match? @_o "^(HttpUtility|WebUtility|Uri)$")
    name: (identifier) @_n (#match? @_n "^(UrlEncode|EscapeDataString)$"))) @sanitizer.ssrf
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#match? @_o "^(HttpUtility|WebUtility|Uri)$")
    name: (identifier) @_n (#match? @_n "^(UrlEncode|EscapeDataString)$"))) @sanitizer.log
(invocation_expression
  function: (member_access_expression name: (identifier) @_n (#eq? @_n "Replace"))
  arguments: (argument_list . (argument) @_lit (#match? @_lit "\\\\[rn]"))) @sanitizer.log
