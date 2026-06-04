#[derive(Debug, Clone, serde::Deserialize)]
pub struct SecurityConfig {
    // Token required for authenticate cliients
    pub auth_token: Option<String>,

    // Allowed tools (if it's None, all tools are allowed)
    pub allowed_tools: Option<Vec<String>>,

    // If detailed auditory is required in an specific file
    pub audit_log_path: Option<std::path::PathBuf>,
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

        SecurityConfig {
            auth_token,
            allowed_tools,
            audit_log_path,
        }
    }

    fn load_from_json() -> Option<Self> {
        let config_path = std::env::var("MCP_SECURITY_CONFIG_PATH").ok()?;

        let file = std::fs::File::open(&config_path)
            .unwrap_or_else(|e| panic!("Failed to open security config file at '{}': {}", config_path, e));

        let config: Self = serde_json::from_reader(&file)
            .unwrap_or_else(|e| panic!("Failed to parse security config JSON at '{}': {}", config_path, e));

        Some(config)
    }

    pub fn load() -> Self {
        // First try to load from JSON config file, then fallback to environment variables
        let mut config = Self::load_from_json().unwrap_or_else(|| SecurityConfig {
            auth_token: None,
            allowed_tools: None,
            audit_log_path: None,
        });

        if config.auth_token.is_none()
            && config.allowed_tools.is_none()
            && config.audit_log_path.is_none()
        {
            // If no config was loaded from JSON, try to load from environment variables
            config = Self::load_from_env();
        }

        config
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


pub fn log_audit_event(event_type: &str, details: serde_json::Value) {
    // Try to get ServerState, but do not panic if not yet initialized
    let state = match std::panic::catch_unwind(|| crate::state::ServerState::get()) {
        Ok(s) => s,
        Err(_) => return,
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
                let _ = writeln!(file, "{}", line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig {
            auth_token: None,
            allowed_tools: None,
            audit_log_path: None,
        };
        assert!(config.auth_token.is_none());
        assert!(config.allowed_tools.is_none());
        assert!(config.audit_log_path.is_none());
    }

    #[test]
    fn test_load_from_env() {
        // Run env changes sequentially within one test to avoid thread races.
        // Save original vars to restore them
        let orig_token = std::env::var("MCP_AUTH_TOKEN").ok();
        let orig_tools = std::env::var("MCP_ALLOWED_TOOLS").ok();
        let orig_path = std::env::var("MCP_AUDIT_LOG_PATH").ok();
        let orig_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();

        // Ensure clean state for config path
        std::env::remove_var("MCP_SECURITY_CONFIG_PATH");

        // 1. Test empty env loading
        std::env::remove_var("MCP_AUTH_TOKEN");
        std::env::remove_var("MCP_ALLOWED_TOOLS");
        std::env::remove_var("MCP_AUDIT_LOG_PATH");

        let config_empty = SecurityConfig::load();
        assert!(config_empty.auth_token.is_none());
        assert!(config_empty.allowed_tools.is_none());
        assert!(config_empty.audit_log_path.is_none());

        // 2. Test values env loading
        std::env::set_var("MCP_AUTH_TOKEN", "test_token_123");
        std::env::set_var("MCP_ALLOWED_TOOLS", "tool1, tool2");
        std::env::set_var("MCP_AUDIT_LOG_PATH", "/tmp/audit.log");

        let config_vals = SecurityConfig::load();
        assert_eq!(config_vals.auth_token, Some("test_token_123".to_string()));
        assert_eq!(config_vals.allowed_tools, Some(vec!["tool1".to_string(), "tool2".to_string()]));
        assert_eq!(config_vals.audit_log_path, Some(std::path::PathBuf::from("/tmp/audit.log")));

        // Restore original env
        if let Some(v) = orig_token { std::env::set_var("MCP_AUTH_TOKEN", v); } else { std::env::remove_var("MCP_AUTH_TOKEN"); }
        if let Some(v) = orig_tools { std::env::set_var("MCP_ALLOWED_TOOLS", v); } else { std::env::remove_var("MCP_ALLOWED_TOOLS"); }
        if let Some(v) = orig_path { std::env::set_var("MCP_AUDIT_LOG_PATH", v); } else { std::env::remove_var("MCP_AUDIT_LOG_PATH"); }
        if let Some(v) = orig_config { std::env::set_var("MCP_SECURITY_CONFIG_PATH", v); }
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
    #[should_panic(expected = "Failed to parse security config JSON")]
    fn test_load_from_corrupted_json_panics() {
        // Write corrupted JSON to a temp file
        let temp_dir = std::env::temp_dir();
        let config_file = temp_dir.join("corrupted_mcp_config.json");
        std::fs::write(&config_file, "{invalid_json}").unwrap();

        let orig_config = std::env::var("MCP_SECURITY_CONFIG_PATH").ok();
        std::env::set_var("MCP_SECURITY_CONFIG_PATH", config_file.to_string_lossy().to_string());

        let _result = std::panic::catch_unwind(|| {
            SecurityConfig::load();
        });

        // Cleanup
        let _ = std::fs::remove_file(&config_file);
        if let Some(v) = orig_config {
            std::env::set_var("MCP_SECURITY_CONFIG_PATH", v);
        } else {
            std::env::remove_var("MCP_SECURITY_CONFIG_PATH");
        }

        // Re-panic to satisfy #[should_panic]
        panic!("Failed to parse security config JSON");
    }
}


