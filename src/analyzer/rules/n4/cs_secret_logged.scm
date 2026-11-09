; C# — secret-named variable passed to Console or ILogger.
(invocation_expression
  function: (member_access_expression
    expression: (_) @_e (#match? @_e "(?i)(^|\\.)_?(console|logger|log)$")
    name: (identifier) @_n (#match? @_n "^(Write|WriteLine|Log|LogInformation|LogWarning|LogError|LogDebug|LogTrace|LogCritical|Information|Warning|Error|Debug)$"))
  arguments: (argument_list (argument [
    (identifier) @_a
    (member_access_expression name: (identifier) @_a)
    (binary_expression (identifier) @_a)]))
  (#match? @_a "(?i)^\\w*(password|passwd|secret|token|apikey|api_key|credential)s?$")) @secret_logged
