; Taint engine syntax for Python: scopes, assignments and mutating propagators.
[(function_definition) (lambda)] @function

(assignment left: (_) @assign.lhs right: (_) @assign.rhs)
(augmented_assignment left: (_) @update.lhs right: (_) @update.rhs)
(for_statement left: (_) @assign.lhs right: (_) @assign.rhs)
(named_expression name: (_) @assign.lhs value: (_) @assign.rhs)

; `parts.append(x)` taints the receiver.
(call
  function: (attribute
    object: (identifier) @prop.to
    attribute: (identifier) @_m (#match? @_m "^(append|extend|insert|update|add|write)$"))
  arguments: (argument_list (_) @prop.from))
