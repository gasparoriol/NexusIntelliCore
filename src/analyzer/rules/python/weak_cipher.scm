; Python — PyCryptodome / cryptography weak ciphers and ECB mode.
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(DES|DES3|ARC2|ARC4|Blowfish|CAST|XOR)$")
    attribute: (identifier) @_m (#eq? @_m "new"))) @weak_cipher
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "AES")
    attribute: (identifier) @_m (#eq? @_m "new"))
  arguments: (argument_list (_) @_mode (#match? @_mode "MODE_ECB$"))) @weak_cipher
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "modes")
    attribute: (identifier) @_m (#eq? @_m "ECB"))) @weak_cipher
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "algorithms")
    attribute: (identifier) @_m (#match? @_m "^(TripleDES|ARC4|Blowfish|IDEA|CAST5|SEED)$"))) @weak_cipher
