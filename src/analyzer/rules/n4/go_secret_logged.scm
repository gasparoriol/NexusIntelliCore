; Go — secret-named variable passed to log / fmt / a structured logger.
(call_expression
  function: (selector_expression
    operand: (identifier) @_p (#match? @_p "^(log|fmt|logger|logrus|zap|slog)$")
    field: (field_identifier) @_f (#match? @_f "^(Print|Println|Printf|Fatal|Fatalf|Fatalln|Panic|Panicf|Info|Infof|Infow|Warn|Warnf|Error|Errorf|Debug|Debugf)$"))
  arguments: (argument_list [(identifier) @_a (selector_expression field: (field_identifier) @_a)])
  (#match? @_a "(?i)^\\w*(password|passwd|secret|token|apikey|api_key|credential)s?$")) @secret_logged
