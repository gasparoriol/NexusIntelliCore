; ── SQL injection (ADO.NET, EF Core, Dapper) ───────────────────────────────
(object_creation_expression
  type: (identifier) @_t (#match? @_t "^(SqlCommand|NpgsqlCommand|MySqlCommand|SqliteCommand|OleDbCommand|OracleCommand)$")
  arguments: (argument_list . (argument) @sink.sql))
(assignment_expression
  left: (member_access_expression name: (identifier) @_n (#eq? @_n "CommandText"))
  right: (_) @sink.sql)
(invocation_expression
  function: (member_access_expression name: (identifier) @_n
    (#match? @_n "^(FromSqlRaw|SqlQueryRaw|Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QueryFirstOrDefaultAsync|QuerySingle|QuerySingleOrDefault|ExecuteScalar|ExecuteScalarAsync)$"))
  arguments: (argument_list . (argument) @sink.sql))
(invocation_expression
  function: (member_access_expression name: (identifier) @_n
    (#match? @_n "^(ExecuteSqlRaw|ExecuteSqlRawAsync|Execute|ExecuteAsync)$"))
  arguments: (argument_list . (argument) @sink.sql.write))

; ── OS command injection ───────────────────────────────────────────────────
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#eq? @_o "Process")
    name: (identifier) @_n (#eq? @_n "Start"))
  arguments: (argument_list (argument) @sink.cmd))
(object_creation_expression
  type: (identifier) @_t (#eq? @_t "ProcessStartInfo")
  arguments: (argument_list (argument) @sink.cmd))
(assignment_expression
  left: (_) @_l (#match? @_l "(^|\\.)(FileName|Arguments)$")
  right: (_) @sink.cmd)

; ── Path traversal ─────────────────────────────────────────────────────────
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#match? @_o "^(File|Directory)$")
    name: (identifier) @_n (#match? @_n "^(ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|OpenRead|OpenText|Open|GetFiles|EnumerateFiles)$"))
  arguments: (argument_list . (argument) @sink.path))
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#match? @_o "^(File|Directory)$")
    name: (identifier) @_n (#match? @_n "^(WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|Delete|Create|CreateText|OpenWrite|Copy|Move|CreateDirectory)$"))
  arguments: (argument_list (argument) @sink.path.write))
(object_creation_expression
  type: (identifier) @_t (#match? @_t "^(FileStream|StreamReader|FileInfo)$")
  arguments: (argument_list . (argument) @sink.path))
(object_creation_expression
  type: (identifier) @_t (#eq? @_t "StreamWriter")
  arguments: (argument_list . (argument) @sink.path.write))
(invocation_expression
  function: (identifier) @_f (#match? @_f "^(PhysicalFile|File)$")
  arguments: (argument_list . (argument) @sink.path))

; ── SSRF ───────────────────────────────────────────────────────────────────
(invocation_expression
  function: (member_access_expression
    expression: (_) @_o (#match? @_o "(?i)client$")
    name: (identifier) @_n (#match? @_n "^(GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|PutAsync|DeleteAsync|PatchAsync)$"))
  arguments: (argument_list . (argument) @sink.ssrf))
(object_creation_expression
  type: (identifier) @_t (#eq? @_t "HttpRequestMessage")
  arguments: (argument_list . (argument) . (argument) @sink.ssrf))
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @_o (#match? @_o "^(WebRequest|HttpWebRequest)$")
    name: (identifier) @_n (#eq? @_n "Create"))
  arguments: (argument_list . (argument) @sink.ssrf))

; ── Open redirect ──────────────────────────────────────────────────────────
(invocation_expression
  function: [(identifier) @_f (member_access_expression name: (identifier) @_f)]
  (#match? @_f "^(Redirect|RedirectPermanent|RedirectPreserveMethod|RedirectPermanentPreserveMethod)$")
  arguments: (argument_list . (argument) @sink.redirect))

; ── Server-side template injection ─────────────────────────────────────────
(invocation_expression
  function: (member_access_expression
    expression: (_) @_o (#match? @_o "(Razor|Template|Handlebars|razorEngine)$")
    name: (identifier) @_n (#match? @_n "^(RunCompile|Compile|Parse|CompileRenderStringAsync)$"))
  arguments: (argument_list . (argument) @sink.ssti))

; ── Log injection ──────────────────────────────────────────────────────────
(invocation_expression
  function: (member_access_expression
    expression: (_) @_o (#match? @_o "(?i)(^|\\.)_?(logger|log)$")
    name: (identifier) @_n (#match? @_n "^(Log|LogInformation|LogWarning|LogError|LogDebug|LogTrace|LogCritical|Information|Warning|Error|Debug|Verbose|Fatal|Info|Warn|Trace)$"))
  arguments: (argument_list (argument) @sink.log))
