; Go — math/rand (reported only in a security-sensitive context).
; Function names absent from crypto/rand, so both packages named `rand` are told apart.
(call_expression
  function: (selector_expression
    operand: (identifier) @_p (#eq? @_p "rand")
    field: (field_identifier) @_f
    (#match? @_f "^(Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float32|Float64|Perm|Shuffle|IntN|Int32N|Int64N|Uint32N|Uint64N|N)$"))) @weak_random
