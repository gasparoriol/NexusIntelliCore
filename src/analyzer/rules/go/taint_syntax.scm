; Taint engine syntax for Go: scopes, assignments and mutating propagators.
[(function_declaration) (method_declaration) (func_literal)] @function

(short_var_declaration
  left: (expression_list . (_) @assign.lhs)
  right: (expression_list . (_) @assign.rhs))
(assignment_statement
  left: (expression_list . (_) @assign.lhs)
  operator: "="
  right: (expression_list . (_) @assign.rhs))
(assignment_statement
  left: (expression_list . (_) @update.lhs)
  operator: "+="
  right: (expression_list . (_) @update.rhs))
(var_spec name: (identifier) @assign.lhs value: (expression_list . (_) @assign.rhs))
(range_clause left: (expression_list (_) @assign.lhs) right: (_) @assign.rhs)

; strings.Builder / bytes.Buffer writes taint the receiver.
(call_expression
  function: (selector_expression
    operand: (identifier) @prop.to
    field: (field_identifier) @_m (#match? @_m "^(WriteString|Write|WriteByte|WriteRune|Add|Set)$"))
  arguments: (argument_list (_) @prop.from))
