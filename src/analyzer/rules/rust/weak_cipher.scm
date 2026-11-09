; Rust — DES / 3DES / RC4 / Blowfish ciphers and ECB mode.
(call_expression
  function: (_) @_f
  (#match? @_f "(^|::)(Des|TdesEde2|TdesEde3|Rc4|Blowfish|ecb::Encryptor|ecb::Decryptor)(::<[^>]*>)?::(new|new_from_slice|new_from_slices)$")) @weak_cipher
