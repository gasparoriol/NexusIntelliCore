#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct SecurityConfig {
    // Token required for authenticate cliients
    pub auth_token: Option<String>,

    // Allowed tools (if it's None, all tools are allowed)
    pub allowed_tools: Option<Vec<String>>,

    // If detailed auditory is required in an specific file
    pub audit_log_path: Option<std::path::PathBuf>,

    // Additional redaction regex patterns applied by Privacy Gateway.
    #[allow(dead_code)]
    pub custom_redaction_patterns: Option<Vec<String>>,

    // Placeholder used when @mcp-strip hides function implementations.
    pub custom_strip_placeholder: Option<String>,
}

impl SecurityConfig {
    fn load_from_env() -> Self {
        let auth_token = std::env::var("MCP_AUTH_TOKEN").ok();
        let allowed_tools = std::env::var("MCP_ALLOWED_TOOLS")
            .ok()
            .map(|s| s.split(',').map(|t| t.trim().to_string()).collect());
        let audit_log_path = std::env::var("MCP_AUDIT_LOG_PATH")
            .ok()
            .map(std::path::PathBuf::from);
        let custom_redaction_patterns = std::env::var("MCP_CUSTOM_REDACTION_PATTERNS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty());
        let custom_strip_placeholder = std::env::var("MCP_CUSTOM_STRIP_PLACEHOLDER")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        SecurityConfig {
            auth_token,
            allowed_tools,
            audit_log_path,
            custom_redaction_patterns,
            custom_strip_placeholder,
        }
    }

    /// Load security configuration from JSON file or environment variables.
    /// Returns a Result to allow callers to handle missing/invalid config gracefully.
    fn load_from_json() -> Result<Self, String> {
        let config_path = std::env::var("MCP_SECURITY_CONFIG_PATH")
            .map_err(|_| "MCP_SECURITY_CONFIG_PATH not set".to_string())?;

        let file = std::fs::File::open(&config_path)
            .map_err(|e| format!("Cannot open security config file at '{config_path}': {e}"))?;

        let config: Self = serde_json::from_reader(&file)
            .map_err(|e| format!("Invalid JSON in security config at '{config_path}': {e}"))?;

        Ok(config)
    }

    pub fn load() -> Self {
        // First try to load from JSON config file, then fallback to environment variables
        match Self::load_from_json() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("[WARN] SecurityConfig: {e}");
                Self::load_from_env()
            }
        }
    }
}

/// Compare two strings in constant time to prevent timing attacks.
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    let mut result = 0;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[allow(clippy::needless_pass_by_value)] // json! literals are ergonomic to pass by value
pub fn log_audit_event(event_type: &str, details: serde_json::Value) {
    // Try to get ServerState, but do not panic if not yet initialized
    let Ok(state) = std::panic::catch_unwind(crate::state::ServerState::get) else {
        return;
    };

    if let Some(ref path) = state.security_config().audit_log_path {
        let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => 0,
        };
        let log_entry = serde_json::json!({
            "timestamp": timestamp,
            "event": event_type,
            "details": details
        });
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            if let Ok(line) = serde_json::to_string(&log_entry) {
                let _ = writeln!(file, "{line}");
            }
        }
    }
}

/// Serialises tests that mutate `MCP_SECURITY_CONFIG_PATH` (or any other
/// security-related env var) so that concurrent tests cannot observe each
/// other's temporary env-var state.  Used by both `security::tests` and
/// `tools::tests::ensure_state_init`.
#[cfg(test)]
pub(crate) static SECURITY_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig {
            auth_token: None,
            allowed_tools: None,
            audit_log_path: None,
            custom_redaction_patterns: None,
            custom_strip_placeholder: None,
        };
        assert!(config.auth_token.is_none());
        assert!(config.allowed_tools.is_none());
        assert!(config.audit_log_path.is_none());
        assert!(config.custom_redaction_patterns.is_none());
        assert!(config.custom_strip_placeholder.is_none());
    }

    #[test]
    fn test_load_from_env() {
        let _guard = super::SECURITY_ENV_TEST_LOCK.lock().unwrap();

        // Run env changes sequentially within one test to avoid thread races.
        // Save original vars to restore them
        let orig_token = std::env::var("MCP_AUTH_TOKEN").ok();
        let orig_tools = std::env::var("MCP_ALLOWED_TOOLS").ok();
        let orig_path = std::env::var("MCP_AUDIT_LOG_PATH").ok();
        let orig_custom_patterns = std::env::var("MCP_CUSTOM_REDACTION_PATTERNS").ok();
        let orig_custom_placeholder = std::env::var("MCP_CUSTOM_STRIP_PLACEHOLDER").ok();
        let orig_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();

        // Ensure clean state for config path
        std::env::remove_var("MCP_SECURITY_CONFIG_PATH");

        // 1. Test empty env loading
        std::env::remove_var("MCP_AUTH_TOKEN");
        std::env::remove_var("MCP_ALLOWED_TOOLS");
        std::env::remove_var("MCP_AUDIT_LOG_PATH");
        std::env::remove_var("MCP_CUSTOM_REDACTION_PATTERNS");
        std::env::remove_var("MCP_CUSTOM_STRIP_PLACEHOLDER");

        let config_empty = SecurityConfig::load();
        assert!(config_empty.auth_token.is_none());
        assert!(config_empty.allowed_tools.is_none());
        assert!(config_empty.audit_log_path.is_none());
        assert!(config_empty.custom_redaction_patterns.is_none());
        assert!(config_empty.custom_strip_placeholder.is_none());

        // 2. Test values env loading
        std::env::set_var("MCP_AUTH_TOKEN", "test_token_123");
        std::env::set_var("MCP_ALLOWED_TOOLS", "tool1, tool2");
        std::env::set_var("MCP_AUDIT_LOG_PATH", "/tmp/audit.log");
        std::env::set_var(
            "MCP_CUSTOM_REDACTION_PATTERNS",
            "ACME-[0-9]{4},corp-secret-[A-Za-z0-9]+",
        );
        std::env::set_var(
            "MCP_CUSTOM_STRIP_PLACEHOLDER",
            "Implementation hidden by policy",
        );

        let config_vals = SecurityConfig::load();
        assert_eq!(config_vals.auth_token, Some("test_token_123".to_string()));
        assert_eq!(
            config_vals.allowed_tools,
            Some(vec!["tool1".to_string(), "tool2".to_string()])
        );
        assert_eq!(
            config_vals.audit_log_path,
            Some(std::path::PathBuf::from("/tmp/audit.log"))
        );
        assert_eq!(
            config_vals.custom_redaction_patterns,
            Some(vec![
                "ACME-[0-9]{4}".to_string(),
                "corp-secret-[A-Za-z0-9]+".to_string()
            ])
        );
        assert_eq!(
            config_vals.custom_strip_placeholder,
            Some("Implementation hidden by policy".to_string())
        );

        // Restore original env
        if let Some(v) = orig_token {
            std::env::set_var("MCP_AUTH_TOKEN", v);
        } else {
            std::env::remove_var("MCP_AUTH_TOKEN");
        }
        if let Some(v) = orig_tools {
            std::env::set_var("MCP_ALLOWED_TOOLS", v);
        } else {
            std::env::remove_var("MCP_ALLOWED_TOOLS");
        }
        if let Some(v) = orig_path {
            std::env::set_var("MCP_AUDIT_LOG_PATH", v);
        } else {
            std::env::remove_var("MCP_AUDIT_LOG_PATH");
        }
        if let Some(v) = orig_custom_patterns {
            std::env::set_var("MCP_CUSTOM_REDACTION_PATTERNS", v);
        } else {
            std::env::remove_var("MCP_CUSTOM_REDACTION_PATTERNS");
        }
        if let Some(v) = orig_custom_placeholder {
            std::env::set_var("MCP_CUSTOM_STRIP_PLACEHOLDER", v);
        } else {
            std::env::remove_var("MCP_CUSTOM_STRIP_PLACEHOLDER");
        }
        if let Some(v) = orig_config {
            std::env::set_var("MCP_SECURITY_CONFIG_PATH", v);
        } else {
            std::env::remove_var("MCP_SECURITY_CONFIG_PATH");
        }
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello_world"));
        assert!(!constant_time_compare("hello_world", "hello"));
        assert!(constant_time_compare("", ""));
    }

    #[test]
    fn test_load_from_corrupted_json_falls_back_to_env() {
        let _guard = super::SECURITY_ENV_TEST_LOCK.lock().unwrap();

        // Write corrupted JSON to a temp file
        let temp_dir = std::env::temp_dir();
        let config_file = temp_dir.join("corrupted_mcp_config.json");
        std::fs::write(&config_file, "{invalid_json}").unwrap();

        let orig_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();
        let orig_token = std::env::var("MCP_AUTH_TOKEN").ok();

        std::env::set_var(
            "MCP_SECURITY_CONFIG_PATH",
            config_file.to_string_lossy().to_string(),
        );
        // Set a fallback env var to verify it loads from env when JSON fails
        std::env::set_var("MCP_AUTH_TOKEN", "fallback_token_from_env");
        std::env::remove_var("MCP_ALLOWED_TOOLS");
        std::env::remove_var("MCP_AUDIT_LOG_PATH");
        std::env::remove_var("MCP_CUSTOM_REDACTION_PATTERNS");
        std::env::remove_var("MCP_CUSTOM_STRIP_PLACEHOLDER");

        // Should NOT panic; should fallback to env vars gracefully
        let config = SecurityConfig::load();
        assert_eq!(
            config.auth_token,
            Some("fallback_token_from_env".to_string())
        );

        // Cleanup
        let _ = std::fs::remove_file(&config_file);
        if let Some(v) = orig_config {
            std::env::set_var("MCP_SECURITY_CONFIG_PATH", v);
        } else {
            std::env::remove_var("MCP_SECURITY_CONFIG_PATH");
        }
        if let Some(v) = orig_token {
            std::env::set_var("MCP_AUTH_TOKEN", v);
        } else {
            std::env::remove_var("MCP_AUTH_TOKEN");
        }
    }
}
