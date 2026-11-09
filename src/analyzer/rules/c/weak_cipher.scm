; C — OpenSSL DES / RC2 / RC4 / Blowfish and AES-ECB.
(call_expression
  function: (identifier) @_f
  (#match? @_f "^(EVP_des_[a-z0-9_]+|EVP_rc4[a-z0-9_]*|EVP_rc2_[a-z0-9_]+|EVP_bf_[a-z0-9_]+|EVP_aes_(128|192|256)_ecb|DES_[a-z_]+|RC4|RC4_set_key|BF_set_key|AES_ecb_encrypt)$")) @weak_cipher
