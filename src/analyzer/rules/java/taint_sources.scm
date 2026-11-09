; Spring MVC / JAX-RS annotated handler parameters.
(formal_parameter
  (modifiers [(annotation name: (identifier) @_a) (marker_annotation name: (identifier) @_a)])
  name: (identifier) @source.param
  (#match? @_a "^(RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue|MatrixVariable|RequestPart|QueryParam|PathParam|FormParam|HeaderParam|CookieParam)$"))

; Servlet / Android request accessors.
(method_invocation
  name: (identifier) @_m
  (#match? @_m "^(getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getPathInfo|getRequestURI|getRequestURL|getCookies|getInputStream|getReader|getOriginalFilename|getSubmittedFileName|getStringExtra|getLastPathSegment)$")) @source

; Archive entry names (Zip Slip) only matter for path traversal.
(method_invocation
  object: (identifier) @_o (#match? @_o "(?i)entry$")
  name: (identifier) @_m (#eq? @_m "getName")) @source.path
