; Go — gin-contrib/cors or rs/cors: any origin with credentials.
((literal_value) @cors
  (#match? @cors "AllowCredentials\\s*:\\s*true")
  (#match? @cors "(Allow(ed)?Origins\\s*:\\s*\\[\\]string\\{\\s*\"\\*\"|AllowAllOrigins\\s*:\\s*true)"))
