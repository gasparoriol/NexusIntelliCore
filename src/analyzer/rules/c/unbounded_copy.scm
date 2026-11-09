; C — copies without a destination bound.
(call_expression
  function: (identifier) @_f
  (#match? @_f "^(strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat|lstrcpy|lstrcat)$")) @unbounded_copy
