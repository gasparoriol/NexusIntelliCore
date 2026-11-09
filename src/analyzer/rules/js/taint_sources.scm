; Express / Koa request data (`req.query`, `ctx.request.body`…).
(member_expression
  object: [(identifier) (member_expression)] @_o (#match? @_o "^(req|request|ctx|ctx\\.request)$")
  property: (property_identifier) @_p
  (#match? @_p "^(query|body|params|headers|cookies|signedCookies|url|originalUrl|path|files|file)$")) @source
(call_expression
  function: (member_expression
    object: (identifier) @_o (#match? @_o "^(req|request)$")
    property: (property_identifier) @_p (#match? @_p "^(get|header|param)$"))) @source

; Command line.
(member_expression
  object: (identifier) @_o (#eq? @_o "process")
  property: (property_identifier) @_p (#eq? @_p "argv")) @source

; Browser URL (DOM open redirect).
(member_expression
  object: [(identifier) (member_expression)] @_o (#match? @_o "(^|\\.)location$")
  property: (property_identifier) @_p (#match? @_p "^(search|hash|href)$")) @source
