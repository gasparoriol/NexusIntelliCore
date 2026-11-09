; Security-related TODO/FIXME/HACK left in code (Java, Rust).
([(line_comment) (block_comment)] @suspicious_comment (#match? @suspicious_comment "(?i)\\b(todo|fixme|hack|xxx)\\b.{0,80}\\b(auth\\w*|secur\\w*|validat\\w*|saniti[sz]\\w*|escap\\w*|csrf|xss|inject\\w*|password|token|permission\\w*|vulnerab\\w*|insecure|unsafe|crypt\\w*)"))
