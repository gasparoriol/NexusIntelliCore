; Taint engine syntax for Kotlin (the grammar has no field names; children are
; matched by position).
[(function_declaration) (lambda_literal) (anonymous_function)] @function

(property_declaration (variable_declaration (simple_identifier) @assign.lhs) . (_) @assign.rhs)
(assignment (directly_assignable_expression (simple_identifier) @assign.lhs) . (_) @assign.rhs)
(for_statement (variable_declaration (simple_identifier) @assign.lhs) . (_) @assign.rhs)

; StringBuilder / collection mutation taints the receiver.
(call_expression
  (navigation_expression
    (simple_identifier) @prop.to
    (navigation_suffix (simple_identifier) @_m (#match? @_m "^(append|add|put|insert)$")))
  (call_suffix (value_arguments (value_argument (_) @prop.from))))
