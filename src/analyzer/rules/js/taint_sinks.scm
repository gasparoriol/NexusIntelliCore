; ── SQL injection ──────────────────────────────────────────────────────────
(call_expression
  function: (member_expression
    property: (property_identifier) @_m
    (#match? @_m "^(query|execute|raw|whereRaw|havingRaw|orderByRaw|\\$queryRawUnsafe|\\$executeRawUnsafe)$"))
  arguments: (arguments . (_) @sink.sql))

; ── OS command injection ───────────────────────────────────────────────────
(call_expression
  function: (identifier) @_f (#match? @_f "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$")
  arguments: (arguments . (_) @sink.cmd))
(call_expression
  function: (member_expression
    object: (_) @_o (#match? @_o "(child_process|^cp$|childProcess|^shell$)")
    property: (property_identifier) @_m (#match? @_m "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$"))
  arguments: (arguments . (_) @sink.cmd))

; ── Path traversal ─────────────────────────────────────────────────────────
(call_expression
  function: (member_expression
    object: (_) @_o (#match? @_o "^(fs|fsp|fsPromises|fs\\.promises)$")
    property: (property_identifier) @_m (#match? @_m "^(readFile|readFileSync|createReadStream|readdir|readdirSync|access|accessSync|stat|statSync|open|openSync)$"))
  arguments: (arguments . (_) @sink.path))
(call_expression
  function: (member_expression
    object: (_) @_o (#match? @_o "^(fs|fsp|fsPromises|fs\\.promises)$")
    property: (property_identifier) @_m (#match? @_m "^(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|mkdir|mkdirSync|rename|renameSync|copyFile|copyFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync)$"))
  arguments: (arguments . (_) @sink.path.write))
(call_expression
  function: (member_expression
    object: (identifier) @_o (#match? @_o "^(res|response)$")
    property: (property_identifier) @_m (#match? @_m "^(sendFile|download)$"))
  arguments: (arguments . (_) @sink.path))

; ── SSRF ───────────────────────────────────────────────────────────────────
(call_expression
  function: (identifier) @_f (#match? @_f "^(fetch|axios|got|needle|superagent)$")
  arguments: (arguments . (_) @sink.ssrf))
(call_expression
  function: (member_expression
    object: (identifier) @_o (#match? @_o "^(axios|got|http|https|superagent|needle)$")
    property: (property_identifier) @_m (#match? @_m "^(get|post|put|delete|patch|head|request)$"))
  arguments: (arguments . (_) @sink.ssrf))

; ── Open redirect ──────────────────────────────────────────────────────────
(call_expression
  function: (member_expression
    object: (identifier) @_o (#match? @_o "^(res|response|ctx)$")
    property: (property_identifier) @_m (#match? @_m "^(redirect|location)$"))
  arguments: (arguments (_) @sink.redirect))
(assignment_expression
  left: [(identifier) @_l (member_expression property: (property_identifier) @_l)]
  (#match? @_l "^(location|href)$")
  right: (_) @sink.redirect)
(call_expression
  function: (member_expression
    object: (_) @_o (#match? @_o "(^|\\.)location$")
    property: (property_identifier) @_m (#match? @_m "^(assign|replace)$"))
  arguments: (arguments . (_) @sink.redirect))
(call_expression
  function: (member_expression
    object: (identifier) @_o (#eq? @_o "window")
    property: (property_identifier) @_m (#eq? @_m "open"))
  arguments: (arguments . (_) @sink.redirect))

; ── Server-side template injection ─────────────────────────────────────────
(call_expression
  function: (member_expression
    object: (identifier) @_o (#match? @_o "^(ejs|pug|jade|Handlebars|handlebars|nunjucks|_|lodash|doT|dot|Mustache|mustache|Hogan|swig|twig)$")
    property: (property_identifier) @_m (#match? @_m "^(render|compile|renderString|template|compileTemplate|precompile)$"))
  arguments: (arguments . (_) @sink.ssti))

; ── Log injection ──────────────────────────────────────────────────────────
(call_expression
  function: (member_expression
    object: [(identifier) (member_expression)] @_o (#match? @_o "(^|\\.)(logger|log|winston|bunyan|pino|LOG|LOGGER)$")
    property: (property_identifier) @_m (#match? @_m "^(info|warn|error|debug|trace|fatal|log|verbose|silly)$"))
  arguments: (arguments (_) @sink.log))
