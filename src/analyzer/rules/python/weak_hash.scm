; Python — MD5 / SHA-1 (unless explicitly marked non-security).
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "hashlib")
    attribute: (identifier) @_m (#match? @_m "^(md5|sha1|md4)$"))
  arguments: (argument_list) @_a (#not-match? @_a "usedforsecurity\\s*=\\s*False")) @weak_hash
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "hashlib")
    attribute: (identifier) @_m (#eq? @_m "new"))
  arguments: (argument_list . (string) @_alg (#match? @_alg "(?i)^[\"'](md5|md4|sha1)[\"']$"))) @weak_hash
; PyCryptodome hash modules.
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(MD2|MD4|MD5|SHA|SHA1)$")
    attribute: (identifier) @_m (#eq? @_m "new"))) @weak_hash
