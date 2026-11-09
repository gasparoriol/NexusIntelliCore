; ── SQL injection ──────────────────────────────────────────────────────────
(call
  function: (attribute attribute: (identifier) @_m (#match? @_m "^(execute|executemany|executescript|raw|mogrify|read_sql|read_sql_query)$"))
  arguments: (argument_list . (_) @sink.sql))
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#eq? @_f "text")
  arguments: (argument_list . (_) @sink.sql))

; ── OS command injection ───────────────────────────────────────────────────
(call
  function: (attribute object: (identifier) @_o attribute: (identifier) @_m)
  (#match? @_o "^(os|commands|subprocess)$")
  (#match? @_m "^(system|popen|getoutput|getstatusoutput)$")
  arguments: (argument_list . (_) @sink.cmd))
(call
  function: (attribute object: (identifier) @_o (#eq? @_o "subprocess"))
  arguments: (argument_list
    . (_) @sink.cmd
    (keyword_argument name: (identifier) @_k (#eq? @_k "shell") value: (true))))

; ── Path traversal ─────────────────────────────────────────────────────────
(call
  function: (identifier) @_f (#match? @_f "^(open|send_file)$")
  arguments: (argument_list . (_) @sink.path))
(call
  function: (identifier) @_f (#eq? @_f "open")
  arguments: (argument_list . (_) @sink.path.write . (string) @_mode (#match? @_mode "[wax+]")))
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(os|shutil)$")
    attribute: (identifier) @_m (#match? @_m "^(remove|unlink|rmdir|removedirs|makedirs|mkdir|rename|replace|rmtree|copy|copyfile|copy2|move)$"))
  arguments: (argument_list (_) @sink.path.write))
(call
  function: (attribute
    object: (_) @sink.path
    attribute: (identifier) @_m (#match? @_m "^(read_text|read_bytes)$")))
(call
  function: (attribute
    object: (_) @sink.path.write
    attribute: (identifier) @_m (#match? @_m "^(write_text|write_bytes)$")))

; ── SSRF ───────────────────────────────────────────────────────────────────
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(requests|httpx)$")
    attribute: (identifier) @_m (#match? @_m "^(get|post|put|delete|head|patch|options|stream)$"))
  arguments: (argument_list . (_) @sink.ssrf))
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(requests|httpx)$")
    attribute: (identifier) @_m (#eq? @_m "request"))
  arguments: (argument_list . (_) . (_) @sink.ssrf))
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#eq? @_f "urlopen")
  arguments: (argument_list . (_) @sink.ssrf))

; ── Open redirect ──────────────────────────────────────────────────────────
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#match? @_f "^(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)$")
  arguments: (argument_list . (_) @sink.redirect))

; ── Server-side template injection ─────────────────────────────────────────
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#match? @_f "^(render_template_string|from_string)$")
  arguments: (argument_list . (_) @sink.ssti))
(call
  function: (identifier) @_f (#eq? @_f "Template")
  arguments: (argument_list . (_) @sink.ssti))
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(jinja2|mako)$")
    attribute: (identifier) @_m (#eq? @_m "Template"))
  arguments: (argument_list . (_) @sink.ssti))

; ── Log injection ──────────────────────────────────────────────────────────
(call
  function: (attribute
    object: (_) @_o (#match? @_o "(^|\\.)(logging|logger|log|LOGGER|LOG|_logger|_log)$")
    attribute: (identifier) @_m (#match? @_m "^(debug|info|warning|warn|error|critical|exception|fatal|log)$"))
  arguments: (argument_list (_) @sink.log))
