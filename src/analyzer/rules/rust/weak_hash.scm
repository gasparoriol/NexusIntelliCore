; Rust — md5 / sha1 / md4 crates.
(call_expression
  function: (_) @_f
  (#match? @_f "(^|::)(md5::compute|(Md5|Sha1|Md4)::(new|default|digest|new_with_prefix))$")) @weak_hash
