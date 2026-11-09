; Go — tls.Config{InsecureSkipVerify: true}.
((keyed_element) @tls_off (#match? @tls_off "^InsecureSkipVerify\\s*:\\s*true$"))
(assignment_statement
  left: (expression_list (selector_expression field: (field_identifier) @_f (#eq? @_f "InsecureSkipVerify")))
  right: (expression_list (true))) @tls_off
