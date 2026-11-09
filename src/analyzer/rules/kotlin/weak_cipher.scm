; Kotlin — weak ciphers, ECB mode, or bare "AES".
(call_expression
  (navigation_expression
    (simple_identifier) @_o (#eq? @_o "Cipher")
    (navigation_suffix (simple_identifier) @_m (#eq? @_m "getInstance")))
  (call_suffix (value_arguments . (value_argument (string_literal) @_alg
    (#match? @_alg "(?i)^\"((des|desede|tripledes|rc2|rc4|arcfour|blowfish)(/[^\"]*)?|aes|[^\"]*/ecb/[^\"]*)\"$"))))) @weak_cipher
