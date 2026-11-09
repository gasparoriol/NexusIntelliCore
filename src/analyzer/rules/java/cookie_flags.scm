; Java — cookies explicitly marked non-Secure or non-HttpOnly.
(method_invocation
  name: (identifier) @_m (#match? @_m "^(setSecure|setHttpOnly|secure|httpOnly)$")
  arguments: (argument_list (false))) @cookie
