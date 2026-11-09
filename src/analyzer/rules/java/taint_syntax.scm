; Taint engine syntax for Java: scopes, assignments and mutating propagators.
[(method_declaration) (constructor_declaration) (lambda_expression)] @function

(variable_declarator name: (_) @assign.lhs value: (_) @assign.rhs)
(assignment_expression left: (_) @assign.lhs operator: "=" right: (_) @assign.rhs)
(assignment_expression left: (_) @update.lhs operator: "+=" right: (_) @update.rhs)
(enhanced_for_statement name: (_) @assign.lhs value: (_) @assign.rhs)

; `sb.append(x)`, `list.add(x)` taint the receiver.
(method_invocation
  object: (identifier) @prop.to
  name: (identifier) @_m (#match? @_m "^(append|insert|add|addAll|put|putAll|write|print|println|format)$")
  arguments: (argument_list (_) @prop.from))
