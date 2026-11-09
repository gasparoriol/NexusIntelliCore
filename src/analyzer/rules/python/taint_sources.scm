; Flask / Django / Starlette request data (`request.args`, `self.request.GET`…).
(attribute
  object: (_) @_o (#match? @_o "(^|\\.)request$")
  attribute: (identifier) @_a
  (#match? @_a "^(args|form|values|json|data|cookies|headers|files|get_json|get_data|GET|POST|body|META|COOKIES|FILES|query_params|path_params|query_string|url|full_path|path)$")) @source

; Route handler parameters (Flask / FastAPI decorators).
(decorated_definition
  (decorator (call function: (attribute attribute: (identifier) @_d)))
  definition: (function_definition
    parameters: (parameters [
      (identifier) @source.param
      (typed_parameter (identifier) @source.param)
      (default_parameter name: (identifier) @source.param)
      (typed_default_parameter name: (identifier) @source.param)]))
  (#match? @_d "^(route|get|post|put|delete|patch|api_route)$"))

; Command line and interactive input.
(call function: (identifier) @_f (#eq? @_f "input")) @source
(attribute
  object: (identifier) @_o (#eq? @_o "sys")
  attribute: (identifier) @_a (#eq? @_a "argv")) @source
