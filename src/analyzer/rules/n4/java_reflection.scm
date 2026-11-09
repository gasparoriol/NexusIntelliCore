; Java — class loaded from a non-literal name.
(method_invocation
  object: (_) @_o (#match? @_o "(^Class|[Ll]oader(\\(\\))?)$")
  name: (identifier) @_m (#match? @_m "^(forName|loadClass)$")
  arguments: (argument_list . (_) @_a (#not-match? @_a "^\""))) @reflection
