; Go — crypto/md5, crypto/sha1, x/crypto/md4.
(call_expression
  function: (selector_expression
    operand: (identifier) @_p (#match? @_p "^(md5|sha1|md4)$")
    field: (field_identifier) @_f (#match? @_f "^(New|Sum)$"))) @weak_hash
