; Taint engine syntax for C#: scopes, assignments and mutating propagators.
[(method_declaration) (constructor_declaration) (local_function_statement) (lambda_expression) (anonymous_method_expression)] @function

(variable_declarator name: (identifier) @assign.lhs (_) @assign.rhs)
(assignment_expression left: (_) @assign.lhs operator: "=" right: (_) @assign.rhs)
(assignment_expression left: (_) @update.lhs operator: "+=" right: (_) @update.rhs)
(foreach_statement left: (_) @assign.lhs right: (_) @assign.rhs)

; StringBuilder / collection mutation taints the receiver.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @prop.to
    name: (identifier) @_m (#match? @_m "^(Append|AppendLine|AppendFormat|Insert|Add|AddRange|Write|WriteLine)$"))
  arguments: (argument_list (argument (_) @prop.from)))
