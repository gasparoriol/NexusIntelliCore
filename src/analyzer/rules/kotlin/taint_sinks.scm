; ── SQL injection ──────────────────────────────────────────────────────────
(call_expression
  (navigation_expression
    (_)
    (navigation_suffix (simple_identifier) @_m
      (#match? @_m "^(executeQuery|prepareStatement|createQuery|createNativeQuery|queryForObject|queryForList|query)$")))
  (call_suffix (value_arguments . (value_argument) @sink.sql)))
(call_expression
  (navigation_expression
    (_)
    (navigation_suffix (simple_identifier) @_m (#match? @_m "^(executeUpdate|execute|update|batchUpdate)$")))
  (call_suffix (value_arguments . (value_argument) @sink.sql.write)))

; ── OS command injection ───────────────────────────────────────────────────
(call_expression
  (navigation_expression
    (_)
    (navigation_suffix (simple_identifier) @_m (#eq? @_m "exec")))
  (call_suffix (value_arguments . (value_argument) @sink.cmd)))
(call_expression
  (simple_identifier) @_f (#eq? @_f "ProcessBuilder")
  (call_suffix (value_arguments (value_argument) @sink.cmd)))

; ── Path traversal ─────────────────────────────────────────────────────────
(call_expression
  (simple_identifier) @_f (#match? @_f "^(File|FileInputStream|FileReader)$")
  (call_suffix (value_arguments (value_argument) @sink.path)))
(call_expression
  (simple_identifier) @_f (#match? @_f "^(FileOutputStream|FileWriter)$")
  (call_suffix (value_arguments . (value_argument) @sink.path.write)))

; ── SSRF ───────────────────────────────────────────────────────────────────
(call_expression
  (simple_identifier) @_f (#match? @_f "^(URL|URI)$")
  (call_suffix (value_arguments . (value_argument) @sink.ssrf)))

; ── Open redirect ──────────────────────────────────────────────────────────
(call_expression
  (navigation_expression
    (_)
    (navigation_suffix (simple_identifier) @_m (#eq? @_m "sendRedirect")))
  (call_suffix (value_arguments . (value_argument) @sink.redirect)))

; ── Log injection ──────────────────────────────────────────────────────────
(call_expression
  (navigation_expression
    (simple_identifier) @_o (#match? @_o "(?i)^(log|logger)$")
    (navigation_suffix (simple_identifier) @_m (#match? @_m "^(trace|debug|info|warn|error)$")))
  (call_suffix (value_arguments (value_argument) @sink.log)))
