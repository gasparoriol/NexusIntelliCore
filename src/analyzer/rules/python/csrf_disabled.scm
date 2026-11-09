; Python — Django / Flask-WTF CSRF protection disabled.
(decorator (identifier) @_d (#eq? @_d "csrf_exempt")) @csrf_off
(decorator (attribute attribute: (identifier) @_d (#eq? @_d "exempt"))) @csrf_off
(assignment
  left: (_) @_l (#match? @_l "WTF_CSRF_ENABLED")
  right: (false)) @csrf_off
