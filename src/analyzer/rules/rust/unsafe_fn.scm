; Rust — `unsafe fn` definitions (function-level unsafety declaration).
; `unsafe` is a child of `function_modifiers`, not of `function_item`.
(function_item
  (function_modifiers "unsafe")
  name: (identifier) @fn_name) @unsafe_fn
