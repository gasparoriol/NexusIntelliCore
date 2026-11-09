; JS/TS — Node crypto / CryptoJS MD5 and SHA-1.
(call_expression
  function: (member_expression property: (property_identifier) @_m (#eq? @_m "createHash"))
  arguments: (arguments . (string) @_alg (#match? @_alg "(?i)^['\"](md5|md4|sha1|ripemd160)['\"]$"))) @weak_hash
(call_expression
  function: (member_expression
    object: (identifier) @_o (#eq? @_o "CryptoJS")
    property: (property_identifier) @_m (#match? @_m "^(MD5|SHA1|RIPEMD160)$"))) @weak_hash
