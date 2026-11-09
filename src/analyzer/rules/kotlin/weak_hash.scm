; Kotlin — MD5 / SHA-1 digests.
(call_expression
  (navigation_expression
    (simple_identifier) @_o (#eq? @_o "MessageDigest")
    (navigation_suffix (simple_identifier) @_m (#eq? @_m "getInstance")))
  (call_suffix (value_arguments . (value_argument (string_literal) @_alg
    (#match? @_alg "(?i)^\"(md2|md4|md5|sha-?1|sha)\"$"))))) @weak_hash
