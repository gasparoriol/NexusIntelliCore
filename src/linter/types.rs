use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LintResult {
    pub diagnostics: Vec<LintDiagnostic>,
    pub sources: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LintDiagnostic {
    pub line: u32,
    pub column: u32,
    pub severity: Severity,
    pub message: String,
    pub rule_id: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
        }
    }
}
