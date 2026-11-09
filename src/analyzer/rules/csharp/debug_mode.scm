; C# — developer error pages (reported unless guarded by IsDevelopment()).
(invocation_expression
  function: (member_access_expression
    name: (identifier) @_n (#match? @_n "^(UseDeveloperExceptionPage|UseDatabaseErrorPage)$"))) @debug_on
