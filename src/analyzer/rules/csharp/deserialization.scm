; C# — dangerous formatters and Json.NET type name handling.
(object_creation_expression
  type: (identifier) @_t (#match? @_t "^(BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter)$")) @deser
(member_access_expression
  expression: (identifier) @_e (#eq? @_e "TypeNameHandling")
  name: (identifier) @_n (#match? @_n "^(All|Auto|Objects|Arrays)$")) @deser
