; C# — MD5 / SHA-1.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_t (#match? @_t "^(MD5|SHA1)$")
    name: (identifier) @_m (#match? @_m "^(Create|HashData|HashDataAsync)$"))) @weak_hash
(object_creation_expression
  type: (identifier) @_t (#match? @_t "^(MD5CryptoServiceProvider|MD5Cng|SHA1Managed|SHA1CryptoServiceProvider|SHA1Cng)$")) @weak_hash
