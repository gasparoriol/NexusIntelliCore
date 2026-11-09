; Go — method or field selected by a non-literal name via reflect.
(call_expression
  function: (selector_expression field: (field_identifier) @_f (#match? @_f "^(MethodByName|FieldByName)$"))
  arguments: (argument_list . (_) @_a (#not-match? @_a "^\""))) @reflection
