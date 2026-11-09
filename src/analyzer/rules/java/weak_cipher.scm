; Java — DES/3DES/RC2/RC4/Blowfish, ECB mode, or bare "AES" (defaults to ECB).
(method_invocation
  object: (identifier) @_o (#eq? @_o "Cipher")
  name: (identifier) @_m (#eq? @_m "getInstance")
  arguments: (argument_list . (string_literal) @_alg
    (#match? @_alg "(?i)^\"((des|desede|tripledes|rc2|rc4|arcfour|blowfish)(/[^\"]*)?|aes|[^\"]*/ecb/[^\"]*)\"$"))) @weak_cipher
