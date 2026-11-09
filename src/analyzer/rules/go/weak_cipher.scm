; Go — DES / 3DES / RC4 / Blowfish.
(call_expression
  function: (selector_expression
    operand: (identifier) @_p (#match? @_p "^(des|rc4|blowfish)$")
    field: (field_identifier) @_f (#match? @_f "^(NewCipher|NewTripleDESCipher)$"))) @weak_cipher
