; Rust — listener bound to every interface.
(call_expression
  arguments: (arguments [(string_literal) @_s (tuple_expression (string_literal) @_s)]
    (#match? @_s "^[\"'](https?://)?(0\\.0\\.0\\.0|\\[::\\])(:\\d+)?/?[\"']$"))) @bind_all
