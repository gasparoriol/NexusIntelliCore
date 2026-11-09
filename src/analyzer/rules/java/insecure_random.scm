; Java — non-cryptographic PRNGs (reported only in a security-sensitive context).
(object_creation_expression
  type: (type_identifier) @_t (#eq? @_t "Random")) @weak_random
(method_invocation
  object: (identifier) @_o (#match? @_o "^(Math|ThreadLocalRandom|RandomStringUtils|RandomUtils)$")
  name: (identifier) @_m (#match? @_m "^(random|current|randomAlphanumeric|randomAlphabetic|randomNumeric|randomAscii|nextInt|nextLong)$")) @weak_random
