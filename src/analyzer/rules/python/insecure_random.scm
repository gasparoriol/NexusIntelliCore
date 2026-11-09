; Python — `random` module (reported only in a security-sensitive context).
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "random")
    attribute: (identifier) @_m (#match? @_m "^(random|randint|randrange|choice|choices|sample|getrandbits|uniform|shuffle)$"))) @weak_random
