; Spring MVC annotated handler parameters: the annotation precedes the parameter.
(function_value_parameters
  (parameter_modifiers
    (annotation [
      (user_type (type_identifier) @_a)
      (constructor_invocation (user_type (type_identifier) @_a))]))
  .
  (parameter (simple_identifier) @source.param)
  (#match? @_a "^(RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue)$"))

; Servlet request accessors.
(call_expression
  (navigation_expression
    (_)
    (navigation_suffix (simple_identifier) @_m
      (#match? @_m "^(getParameter|getHeader|getQueryString|getPathInfo|getRequestURI)$")))) @source
