; ── SQL injection ──────────────────────────────────────────────────────────
(method_invocation
  name: (identifier) @_m
  (#match? @_m "^(executeQuery|prepareStatement|prepareCall|createQuery|createNativeQuery|createSQLQuery|queryForObject|queryForList|queryForMap|queryForRowSet|query)$")
  arguments: (argument_list . (_) @sink.sql))
(method_invocation
  name: (identifier) @_m
  (#match? @_m "^(executeUpdate|executeLargeUpdate|execute|addBatch|update|batchUpdate)$")
  arguments: (argument_list . (_) @sink.sql.write))

; ── OS command injection ───────────────────────────────────────────────────
(method_invocation
  name: (identifier) @_m (#eq? @_m "exec")
  arguments: (argument_list . (_) @sink.cmd))
(object_creation_expression
  type: (type_identifier) @_t (#eq? @_t "ProcessBuilder")
  arguments: (argument_list (_) @sink.cmd))
(method_invocation
  name: (identifier) @_m (#eq? @_m "command")
  arguments: (argument_list (_) @sink.cmd))

; ── Path traversal ─────────────────────────────────────────────────────────
(object_creation_expression
  type: (type_identifier) @_t (#match? @_t "^(File|FileInputStream|FileReader|RandomAccessFile)$")
  arguments: (argument_list (_) @sink.path))
(object_creation_expression
  type: (type_identifier) @_t (#match? @_t "^(FileOutputStream|FileWriter|PrintWriter|PrintStream)$")
  arguments: (argument_list . (_) @sink.path.write))
(method_invocation
  object: (identifier) @_o (#eq? @_o "Files")
  name: (identifier) @_m (#match? @_m "^(readAllBytes|readAllLines|readString|lines|newInputStream|newBufferedReader)$")
  arguments: (argument_list . (_) @sink.path))
(method_invocation
  object: (identifier) @_o (#eq? @_o "Files")
  name: (identifier) @_m (#match? @_m "^(write|writeString|newOutputStream|newBufferedWriter|createFile|createDirectory|createDirectories|delete|deleteIfExists)$")
  arguments: (argument_list . (_) @sink.path.write))
(method_invocation
  object: (identifier) @_o (#eq? @_o "Files")
  name: (identifier) @_m (#match? @_m "^(copy|move)$")
  arguments: (argument_list (_) @sink.path.write .))

; ── SSRF ───────────────────────────────────────────────────────────────────
(object_creation_expression
  type: (type_identifier) @_t (#match? @_t "^(URL|HttpGet|HttpPost|HttpPut|HttpDelete|HttpHead|HttpPatch|HttpOptions)$")
  arguments: (argument_list . (_) @sink.ssrf))
(method_invocation
  object: (identifier) @_o (#eq? @_o "URI")
  name: (identifier) @_m (#eq? @_m "create")
  arguments: (argument_list . (_) @sink.ssrf))
(method_invocation
  name: (identifier) @_m
  (#match? @_m "^(getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|patchForObject|headForHeaders|uri|newBuilder)$")
  arguments: (argument_list . (_) @sink.ssrf))

; ── Open redirect ──────────────────────────────────────────────────────────
(method_invocation
  name: (identifier) @_m (#eq? @_m "sendRedirect")
  arguments: (argument_list . (_) @sink.redirect))
(object_creation_expression
  type: (type_identifier) @_t (#eq? @_t "RedirectView")
  arguments: (argument_list . (_) @sink.redirect))
(method_invocation
  name: (identifier) @_m (#match? @_m "^(setHeader|addHeader)$")
  arguments: (argument_list . (string_literal) @_h (#match? @_h "^\"[Ll]ocation\"$") . (_) @sink.redirect))
(return_statement
  (binary_expression) @sink.redirect (#match? @sink.redirect "^\"redirect:"))

; ── Server-side template injection ─────────────────────────────────────────
(object_creation_expression
  type: (type_identifier) @_t (#eq? @_t "Template")
  arguments: (argument_list (_) @sink.ssti))
(method_invocation
  object: (identifier) @_o (#match? @_o "(?i)^(velocity|velocityengine|ve|engine)$")
  name: (identifier) @_m (#eq? @_m "evaluate")
  arguments: (argument_list (_) @sink.ssti))

; ── Log injection ──────────────────────────────────────────────────────────
(method_invocation
  object: (_) @_o (#match? @_o "(?i)(^|\\.)(log|logger)$")
  name: (identifier) @_m (#match? @_m "^(trace|debug|info|warn|error|fatal|fine|finer|finest|config|severe|warning|log)$")
  arguments: (argument_list (_) @sink.log))
