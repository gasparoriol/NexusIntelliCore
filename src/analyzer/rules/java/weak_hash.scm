; Java — MD5 / SHA-1 / MD2 digests.
(method_invocation
  object: (identifier) @_o (#eq? @_o "MessageDigest")
  name: (identifier) @_m (#eq? @_m "getInstance")
  arguments: (argument_list . (string_literal) @_alg (#match? @_alg "(?i)^\"(md2|md4|md5|sha-?1|sha)\"$"))) @weak_hash
; Apache Commons Codec / Guava helpers.
(method_invocation
  object: (identifier) @_o (#match? @_o "^(DigestUtils|Hashing)$")
  name: (identifier) @_m (#match? @_m "^(md2|md2Hex|md5|md5Hex|sha|shaHex|sha1|sha1Hex)$")) @weak_hash
