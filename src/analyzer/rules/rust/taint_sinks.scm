; ── SQL injection (sqlx, diesel, rusqlite, postgres) ──────────────────────
; `sqlx::query!` macros are checked at compile time and are not sinks.
(call_expression
  function: [
    (identifier) @_f
    (scoped_identifier name: (identifier) @_f)
    (generic_function function: [(identifier) @_f (scoped_identifier name: (identifier) @_f)])]
  (#match? @_f "^(query|query_as|query_scalar|query_with|sql_query)$")
  arguments: (arguments . (_) @sink.sql))
(call_expression
  function: (field_expression
    field: (field_identifier) @_m (#match? @_m "^(query|query_row|query_map|query_one|query_opt|prepare|prepare_cached|simple_query)$"))
  arguments: (arguments . (_) @sink.sql))
(call_expression
  function: (field_expression
    field: (field_identifier) @_m (#match? @_m "^(execute|execute_batch|batch_execute)$"))
  arguments: (arguments . (_) @sink.sql.write))

; ── OS command injection ───────────────────────────────────────────────────
(call_expression
  function: (scoped_identifier
    path: (_) @_p (#match? @_p "(^|::)Command$")
    name: (identifier) @_n (#eq? @_n "new"))
  arguments: (arguments . (_) @sink.cmd))
; Arguments of an explicit shell: `Command::new("sh").arg("-c").arg(x)`.
(call_expression
  function: (field_expression
    value: (_) @_r (#match? @_r "Command::new\\(\"(sh|bash|zsh|/bin/sh|/bin/bash|cmd|cmd\\.exe|powershell|pwsh)\"\\)")
    field: (field_identifier) @_m (#match? @_m "^(arg|args)$"))
  arguments: (arguments (_) @sink.cmd))

; ── SSRF ───────────────────────────────────────────────────────────────────
(call_expression
  function: (scoped_identifier
    path: (_) @_p (#match? @_p "(^|::)reqwest(::blocking)?$")
    name: (identifier) @_n (#eq? @_n "get"))
  arguments: (arguments . (_) @sink.ssrf))
(call_expression
  function: (field_expression
    value: (_) @_r (#match? @_r "(?i)^(self\\.)?(http_?)?client$")
    field: (field_identifier) @_m (#match? @_m "^(get|post|put|delete|patch|head)$"))
  arguments: (arguments . (_) @sink.ssrf))

; ── Open redirect ──────────────────────────────────────────────────────────
(call_expression
  function: (scoped_identifier
    path: (_) @_p (#match? @_p "(^|::)Redirect$")
    name: (identifier) @_n (#match? @_n "^(to|temporary|permanent|see_other)$"))
  arguments: (arguments . (_) @sink.redirect))
(call_expression
  function: (field_expression
    field: (field_identifier) @_m (#match? @_m "^(insert_header|append_header)$"))
  arguments: (arguments
    (tuple_expression . (_) @_h (#match? @_h "(?i)location") . (_) @sink.redirect)))
