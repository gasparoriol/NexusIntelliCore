; ── SQL injection (database/sql, sqlx, gorm) ───────────────────────────────
(call_expression
  function: (selector_expression field: (field_identifier) @_f (#match? @_f "^(Query|QueryRow|Prepare|Raw|Where|Queryx|QueryRowx)$"))
  arguments: (argument_list . (_) @sink.sql))
(call_expression
  function: (selector_expression field: (field_identifier) @_f (#match? @_f "^(QueryContext|QueryRowContext|PrepareContext|QueryxContext|Select|Get)$"))
  arguments: (argument_list . (_) . (_) @sink.sql))
(call_expression
  function: (selector_expression field: (field_identifier) @_f (#eq? @_f "Exec"))
  arguments: (argument_list . (_) @sink.sql.write))
(call_expression
  function: (selector_expression field: (field_identifier) @_f (#eq? @_f "ExecContext"))
  arguments: (argument_list . (_) . (_) @sink.sql.write))

; ── OS command injection ───────────────────────────────────────────────────
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(exec|syscall)$")
    field: (field_identifier) @_f (#match? @_f "^(Command|Exec)$"))
  arguments: (argument_list . (_) @sink.cmd))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "exec")
    field: (field_identifier) @_f (#eq? @_f "CommandContext"))
  arguments: (argument_list . (_) . (_) @sink.cmd))
; Arguments of an explicit shell: exec.Command("sh", "-c", x)
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "exec")
    field: (field_identifier) @_f (#match? @_f "^(Command|CommandContext)$"))
  arguments: (argument_list
    (interpreted_string_literal) @_sh (#match? @_sh "^\"(sh|bash|zsh|/bin/sh|/bin/bash|cmd|cmd\\.exe|powershell|pwsh)\"$")
    (_) @sink.cmd))

; ── Path traversal ─────────────────────────────────────────────────────────
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(os|ioutil)$")
    field: (field_identifier) @_f (#match? @_f "^(Open|ReadFile|ReadDir|Stat|Lstat)$"))
  arguments: (argument_list . (_) @sink.path))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(os|ioutil)$")
    field: (field_identifier) @_f (#match? @_f "^(OpenFile|Create|WriteFile|Remove|RemoveAll|Mkdir|MkdirAll|Rename|Chmod)$"))
  arguments: (argument_list . (_) @sink.path.write))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "http")
    field: (field_identifier) @_f (#eq? @_f "ServeFile"))
  arguments: (argument_list . (_) . (_) . (_) @sink.path))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(c|ctx)$")
    field: (field_identifier) @_f (#match? @_f "^(File|FileAttachment|SendFile)$"))
  arguments: (argument_list . (_) @sink.path))

; ── SSRF ───────────────────────────────────────────────────────────────────
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "(?i)^(http|client|httpclient)$")
    field: (field_identifier) @_f (#match? @_f "^(Get|Head|Post|PostForm)$"))
  arguments: (argument_list . (_) @sink.ssrf))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "http")
    field: (field_identifier) @_f (#eq? @_f "NewRequest"))
  arguments: (argument_list . (_) . (_) @sink.ssrf))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "http")
    field: (field_identifier) @_f (#eq? @_f "NewRequestWithContext"))
  arguments: (argument_list . (_) . (_) . (_) @sink.ssrf))

; ── Open redirect ──────────────────────────────────────────────────────────
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "http")
    field: (field_identifier) @_f (#eq? @_f "Redirect"))
  arguments: (argument_list . (_) . (_) . (_) @sink.redirect))
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(c|ctx)$")
    field: (field_identifier) @_f (#eq? @_f "Redirect"))
  arguments: (argument_list . (_) . (_) @sink.redirect))

; ── Server-side template injection ─────────────────────────────────────────
(call_expression
  function: (selector_expression
    operand: (_) @_r (#match? @_r "template\\.")
    field: (field_identifier) @_f (#eq? @_f "Parse"))
  arguments: (argument_list . (_) @sink.ssti))

; ── Log injection ──────────────────────────────────────────────────────────
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(log|logger|slog|logrus)$")
    field: (field_identifier) @_f
    (#match? @_f "^(Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf|Info|Infof|Warn|Warnf|Error|Errorf|Debug|Debugf)$"))
  arguments: (argument_list (_) @sink.log))
