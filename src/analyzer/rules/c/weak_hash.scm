; C — OpenSSL MD5 / MD4 / SHA-1.
(call_expression
  function: (identifier) @_f
  (#match? @_f "^(MD2|MD4|MD5|SHA1|MD4_Init|MD5_Init|SHA1_Init|EVP_md4|EVP_md5|EVP_sha1|EVP_md5_sha1)$")) @weak_hash
