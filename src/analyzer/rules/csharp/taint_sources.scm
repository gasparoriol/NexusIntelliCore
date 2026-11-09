; ASP.NET Core model-binding attributes on action parameters.
(parameter
  (attribute_list (attribute name: (identifier) @_a))
  name: (identifier) @source.param
  (#match? @_a "^(FromQuery|FromBody|FromRoute|FromForm|FromHeader)$"))

; HttpContext.Request accessors.
(member_access_expression
  expression: (_) @_o (#match? @_o "(^|\\.)Request$")
  name: (identifier) @_n (#match? @_n "^(Query|Form|Headers|Cookies|QueryString|Body|Path|RouteValues|Params)$")) @source

; Console input.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#eq? @_o "Console")
    name: (identifier) @_n (#eq? @_n "ReadLine"))) @source
