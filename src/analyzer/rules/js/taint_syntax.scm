; Taint engine syntax for JS/TS: scopes, assignments and mutating propagators.
[(function_declaration) (function_expression) (arrow_function) (method_definition) (generator_function_declaration)] @function

(variable_declarator name: (_) @assign.lhs value: (_) @assign.rhs)
(assignment_expression left: (_) @assign.lhs right: (_) @assign.rhs)
(augmented_assignment_expression left: (_) @update.lhs right: (_) @update.rhs)
(for_in_statement left: (_) @assign.lhs right: (_) @assign.rhs)

; `parts.push(x)` taints the receiver.
(call_expression
  function: (member_expression
    object: (identifier) @prop.to
    property: (property_identifier) @_m (#match? @_m "^(push|unshift|append|set|add|write)$"))
  arguments: (arguments (_) @prop.from))
