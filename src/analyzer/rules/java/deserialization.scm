; Java — native / XML / polymorphic deserialization of untrusted data.
(object_creation_expression
  type: (type_identifier) @_t (#match? @_t "^(ObjectInputStream|XMLDecoder)$")) @deser
(method_invocation
  name: (identifier) @_m (#match? @_m "^(fromXML|enableDefaultTyping|activateDefaultTyping)$")) @deser
