; Rust — cookie builders with secure / http_only disabled.
(call_expression
  function: (field_expression field: (field_identifier) @_m (#match? @_m "^(secure|http_only)$"))
  arguments: (arguments (boolean_literal) @_b (#eq? @_b "false"))) @cookie
