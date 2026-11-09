; JS/TS — node-serialize style unserialize (evaluates functions).
(call_expression
  function: [(identifier) @_f (member_expression property: (property_identifier) @_f)]
  (#match? @_f "^(unserialize|deepDeserialize)$")) @deser
