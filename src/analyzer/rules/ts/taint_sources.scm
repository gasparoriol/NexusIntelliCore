; NestJS parameter decorators (TypeScript only).
(required_parameter
  decorator: (decorator (call_expression function: (identifier) @_d))
  pattern: (identifier) @source.param
  (#match? @_d "^(Query|Param|Body|Headers|Req|Cookies)$"))
