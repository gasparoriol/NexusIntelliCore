; Python — existence/permission check followed by use of the same path.
(if_statement
  condition: (_) @_c (#match? @_c "os\\.path\\.(exists|isfile|isdir)|os\\.access")
  consequence: (block) @_b (#match? @_b "\\bopen\\(|os\\.(remove|unlink|rename|chmod)")) @toctou
