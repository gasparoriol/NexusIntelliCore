#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TestMcpClient {
    root: String,
    envs: HashMap<String, String>,
}

impl TestMcpClient {
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            envs: HashMap::new(),
        }
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.envs.insert(key.into(), value.into());
        self
    }

    pub fn call(&self, request: &str) -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nexusintellicore"));
        cmd.arg(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("MCP_SECURITY_CONFIG_PATH")
            .env_remove("MCP_AUTH_TOKEN")
            .env_remove("MCP_ALLOWED_TOOLS")
            .env_remove("MCP_AUDIT_LOG_PATH");

        for (key, value) in &self.envs {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().expect("Failed to start MCP server");
        let stdin = child.stdin.as_mut().expect("stdin should exist");
        write_frame(stdin, request);
        drop(child.stdin.take());

        let stdout = child.stdout.take().expect("stdout should exist");
        let response = read_single_framed_response(stdout);
        let _ = child.wait();
        response
    }

    pub fn call_tool(&self, tool_name: &str, arguments: serde_json::Value) -> String {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        })
        .to_string();
        self.call(&request)
    }
}

pub fn make_temp_workspace(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "nexusintellicore_{test_name}_{}_{}",
        std::process::id(),
        nonce
    ));
    fs::create_dir_all(&root).expect("temp workspace should be created");
    root
}

fn write_frame(stdin: &mut std::process::ChildStdin, msg: &str) {
    let body = msg.as_bytes();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin
        .write_all(header.as_bytes())
        .expect("header should be written");
    stdin.write_all(body).expect("body should be written");
    stdin.flush().expect("stdin should flush");
}

fn read_single_framed_response(mut reader: ChildStdout) -> String {
    let mut responses = Vec::new();
    let mut buf = [0u8; 8192];
    let mut accumulated = Vec::new();

    while responses.is_empty() {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                accumulated.extend_from_slice(&buf[..n]);

                loop {
                    if accumulated.len() < 4 {
                        break;
                    }

                    let mut found_end = false;
                    let mut header_end = 0;
                    for i in 0..accumulated.len() - 3 {
                        if accumulated[i] == b'\r'
                            && accumulated[i + 1] == b'\n'
                            && accumulated[i + 2] == b'\r'
                            && accumulated[i + 3] == b'\n'
                        {
                            found_end = true;
                            header_end = i;
                            break;
                        }
                    }

                    if !found_end {
                        break;
                    }

                    let header_str = String::from_utf8_lossy(&accumulated[..header_end]);
                    let mut content_length = 0;
                    for line in header_str.lines() {
                        if let Some(rest) = line.strip_prefix("Content-Length: ") {
                            if let Ok(n) = rest.parse::<usize>() {
                                content_length = n;
                                break;
                            }
                        }
                    }

                    let body_start = header_end + 4;
                    let body_end = body_start + content_length;

                    if accumulated.len() >= body_end {
                        let body = String::from_utf8_lossy(&accumulated[body_start..body_end]);
                        responses.push(body.to_string());
                        accumulated.drain(..body_end);
                    } else {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    responses.first().cloned().unwrap_or_default()
}
