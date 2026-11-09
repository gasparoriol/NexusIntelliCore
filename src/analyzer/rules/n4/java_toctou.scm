; Java — File.exists()/canRead() followed by opening the file.
(if_statement
  condition: (_) @_c (#match? @_c "\\.(exists|canRead|canWrite|isFile)\\(\\)|Files\\.exists\\(")
  consequence: (_) @_b (#match? @_b "new File(Input|Output)Stream|new File(Reader|Writer)|Files\\.(read|write|newInput|newOutput|delete)|\\.delete\\(\\)")) @toctou
