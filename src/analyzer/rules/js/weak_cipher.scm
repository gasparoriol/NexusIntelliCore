; JS/TS — weak Node ciphers, ECB mode, deprecated createCipher, CryptoJS DES/RC4/ECB.
(call_expression
  function: (member_expression property: (property_identifier) @_m (#match? @_m "^(createCipheriv|createDecipheriv)$"))
  arguments: (arguments . (string) @_alg (#match? @_alg "(?i)^['\"]((des|rc2|rc4|bf|blowfish|cast)[a-z0-9-]*|[a-z0-9-]*-ecb)['\"]$"))) @weak_cipher
(call_expression
  function: (member_expression property: (property_identifier) @_m (#match? @_m "^(createCipher|createDecipher)$"))) @weak_cipher
(member_expression
  object: (identifier) @_o (#eq? @_o "CryptoJS")
  property: (property_identifier) @_p (#match? @_p "^(DES|TripleDES|RC4|RC4Drop)$")) @weak_cipher
(member_expression
  object: (_) @_o (#match? @_o "(^|\\.)mode$")
  property: (property_identifier) @_p (#eq? @_p "ECB")) @weak_cipher
