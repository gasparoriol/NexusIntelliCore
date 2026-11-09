; Python — server bound to every interface.
(call
  arguments: (argument_list [
    (string) @_s
    (keyword_argument value: (string) @_s)
    (tuple (string) @_s)])
  (#match? @_s "^[\"'](https?://)?(0\\.0\\.0\\.0|\\[::\\])(:\\d+)?/?[\"']$")) @bind_all
