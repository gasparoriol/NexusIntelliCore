; JS/TS — cors()/enableCors() reflecting any origin with credentials.
(call_expression
  function: [(identifier) @_f (member_expression property: (property_identifier) @_f)]
  (#match? @_f "^(cors|enableCors)$")
  arguments: (arguments (object) @_o
    (#match? @_o "credentials\\s*:\\s*true")
    (#match? @_o "origin\\s*:\\s*(true|['\"]\\*['\"])"))) @cors
