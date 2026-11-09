; Java — CORS any-origin combined with credentials.
(annotation
  name: (identifier) @_a (#eq? @_a "CrossOrigin")
  arguments: (annotation_argument_list) @_args
  (#match? @_args "\"\\*\"")
  (#match? @_args "allowCredentials\\s*=\\s*\"true\"")) @cors
(method_invocation
  object: (_) @_o (#match? @_o "allowedOrigin(s|Patterns)\\(\\s*\"\\*\"\\s*\\)")
  name: (identifier) @_m (#eq? @_m "allowCredentials")
  arguments: (argument_list (true))) @cors
