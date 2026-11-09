; C# — type or assembly loaded from a non-literal name.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_e (#match? @_e "^(Type|Assembly)$")
    name: (identifier) @_n (#match? @_n "^(GetType|Load|LoadFrom)$"))
  arguments: (argument_list . (argument) @_a (#not-match? @_a "^\""))) @reflection
