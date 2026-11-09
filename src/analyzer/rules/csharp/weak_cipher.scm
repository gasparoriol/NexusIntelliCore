; C# — DES / 3DES / RC2 and ECB mode.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_t (#match? @_t "^(DES|TripleDES|RC2)$")
    name: (identifier) @_m (#eq? @_m "Create"))) @weak_cipher
(object_creation_expression
  type: (identifier) @_t (#match? @_t "^(DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)$")) @weak_cipher
(member_access_expression
  expression: (identifier) @_e (#eq? @_e "CipherMode")
  name: (identifier) @_n (#eq? @_n "ECB")) @weak_cipher
