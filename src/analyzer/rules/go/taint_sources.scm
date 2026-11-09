; net/http, gin, echo, fiber request accessors.
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(r|req|request|c|ctx)$")
    field: (field_identifier) @_f
    (#match? @_f "^(FormValue|PostFormValue|Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|GetHeader|QueryParam|QueryParams|FormFile|Cookie|GetRawData)$"))) @source
; r.URL.Query().Get("x"), r.Header.Get("x")
(call_expression
  function: (selector_expression
    operand: (_) @_o (#match? @_o "^(r|req|request)\\.(URL\\.Query\\(\\)|Header|Form|PostForm)$")
    field: (field_identifier) @_f (#match? @_f "^(Get|Values)$"))) @source
; r.URL.Path, r.URL.RawQuery
(selector_expression
  operand: (selector_expression
    operand: (identifier) @_o (#match? @_o "^(r|req|request)$")
    field: (field_identifier) @_u (#eq? @_u "URL"))
  field: (field_identifier) @_f (#match? @_f "^(Path|RawQuery|RawPath|Fragment)$")) @source
; r.Body, r.Form, r.RequestURI
(selector_expression
  operand: (identifier) @_o (#match? @_o "^(r|req|request)$")
  field: (field_identifier) @_f (#match? @_f "^(Body|Form|PostForm|RequestURI)$")) @source
; gorilla/mux route variables and command-line arguments.
(call_expression
  function: (selector_expression
    operand: (identifier) @_o (#eq? @_o "mux")
    field: (field_identifier) @_f (#eq? @_f "Vars"))) @source
(selector_expression
  operand: (identifier) @_o (#eq? @_o "os")
  field: (field_identifier) @_f (#eq? @_f "Args")) @source
; Binding into a struct: c.ShouldBindJSON(&req), json.NewDecoder(r.Body).Decode(&req)
(call_expression
  function: (selector_expression
    field: (field_identifier) @_f
    (#match? @_f "^(ShouldBind|ShouldBindJSON|ShouldBindQuery|ShouldBindUri|Bind|BindJSON|BindQuery)$"))
  arguments: (argument_list (unary_expression operand: (identifier) @source.param)))
(call_expression
  function: (selector_expression
    operand: (_) @_d (#match? @_d "Body")
    field: (field_identifier) @_f (#eq? @_f "Decode"))
  arguments: (argument_list (unary_expression operand: (identifier) @source.param)))
