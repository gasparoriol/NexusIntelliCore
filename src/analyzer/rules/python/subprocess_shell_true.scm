; Python — `subprocess.*(…, shell=True)` calls.
(call
  function: (attribute
    object: (identifier) @module
    attribute: (identifier) @fn_name)
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kw_name
      value: (_) @kw_value
      (#eq? @kw_name "shell")
      (#match? @kw_value "^(True|true)$")))
  (#eq? @module "subprocess"))
@subprocess_shell_true
