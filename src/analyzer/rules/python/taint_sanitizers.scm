; Numeric / UUID conversion neutralises every injection class.
(call function: (identifier) @_f (#match? @_f "^(int|float|bool|len|UUID)$")) @sanitizer
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "uuid")
    attribute: (identifier) @_m (#eq? @_m "UUID"))) @sanitizer

; Command: shell quoting.
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(shlex|pipes)$")
    attribute: (identifier) @_m (#eq? @_m "quote"))) @sanitizer.cmd

; Path: keep only the file name component.
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#match? @_f "^(basename|secure_filename)$")) @sanitizer.path

; Path: confinement guard `p.startswith(base + os.sep)` in a condition.
(call
  function: (attribute
    object: (_) @guard.path
    attribute: (identifier) @_m (#eq? @_m "startswith"))
  arguments: (argument_list (_) @_a (#match? @_a "sep|[\"']/[\"']")))

; SQL: driver escaping helpers.
(call
  function: (attribute attribute: (identifier) @_m (#match? @_m "^(escape_string|quote_identifier|literal)$"))) @sanitizer.sql

; Redirect: `url_for` builds an internal URL.
(call
  function: [(identifier) @_f (attribute attribute: (identifier) @_f)]
  (#eq? @_f "url_for")) @sanitizer.redirect

; Log: CR/LF stripping.
(call
  function: (attribute attribute: (identifier) @_m (#eq? @_m "replace"))
  arguments: (argument_list . (string) @_lit (#match? @_lit "\\\\[rn]"))) @sanitizer.log
