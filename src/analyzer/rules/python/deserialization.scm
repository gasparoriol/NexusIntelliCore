; Python — pickle-like and unsafe YAML loaders.
(call
  function: (attribute
    object: (identifier) @_o (#match? @_o "^(pickle|cPickle|_pickle|dill|marshal|shelve|jsonpickle)$")
    attribute: (identifier) @_m (#match? @_m "^(load|loads|open|decode|Unpickler)$"))) @deser
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "yaml")
    attribute: (identifier) @_m (#match? @_m "^(unsafe_load|unsafe_load_all|full_load|full_load_all)$"))) @deser
(call
  function: (attribute
    object: (identifier) @_o (#eq? @_o "yaml")
    attribute: (identifier) @_m (#match? @_m "^(load|load_all)$"))
  arguments: (argument_list) @_a (#not-match? @_a "(Safe|Base)Loader")) @deser
