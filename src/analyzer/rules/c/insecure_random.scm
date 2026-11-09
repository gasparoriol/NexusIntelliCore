; C — libc PRNGs (reported only in a security-sensitive context).
(call_expression
  function: (identifier) @_f (#match? @_f "^(rand|random|drand48|lrand48|mrand48)$")) @weak_random
