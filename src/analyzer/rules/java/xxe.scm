; Java — XML parser factories (reported unless the method hardens them).
(method_invocation
  object: (identifier) @_o (#match? @_o "^(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)$")
  name: (identifier) @_m (#match? @_m "^(newInstance|newFactory|newDefaultInstance|createXMLReader)$")) @xxe
(object_creation_expression
  type: (type_identifier) @_t (#match? @_t "^(SAXReader|SAXBuilder)$")) @xxe
