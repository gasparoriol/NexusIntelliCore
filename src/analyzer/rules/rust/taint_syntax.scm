; Taint engine syntax for Rust: scopes, bindings and mutating propagators.
[(function_item) (closure_expression)] @function

(let_declaration pattern: (_) @assign.lhs value: (_) @assign.rhs)
(let_condition pattern: (_) @assign.lhs value: (_) @assign.rhs)
(assignment_expression left: (_) @assign.lhs right: (_) @assign.rhs)
(compound_assignment_expr left: (_) @update.lhs right: (_) @update.rhs)
(for_expression pattern: (_) @assign.lhs value: (_) @assign.rhs)

; `sql.push_str(&x)` taints the receiver.
(call_expression
  function: (field_expression
    value: (identifier) @prop.to
    field: (field_identifier) @_m (#match? @_m "^(push_str|push|extend|extend_from_slice|insert|write_str|write_all)$"))
  arguments: (arguments (_) @prop.from))
