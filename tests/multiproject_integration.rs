use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn write_frame(stdin: &mut std::process::ChildStdin, msg: &str) {
    let body = msg.as_bytes();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin.write_all(header.as_bytes()).unwrap();
    stdin.write_all(body).unwrap();
    stdin.flush().unwrap();
}

fn read_frame(stdout: &mut std::process::ChildStdout) -> String {
    let mut buf = [0u8; 8192];
    let mut accumulated = Vec::new();
    loop {
        let n = stdout.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        accumulated.extend_from_slice(&buf[..n]);
        if let Some(pos) = accumulated.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = String::from_utf8_lossy(&accumulated[..pos]);
            let mut content_length = 0;
            for line in header_str.lines() {
                if let Some(rest) = line.strip_prefix("Content-Length: ") {
                    content_length = rest.parse::<usize>().unwrap_or(0);
                }
            }
            let body_start = pos + 4;
            if accumulated.len() >= body_start + content_length {
                return String::from_utf8_lossy(
                    &accumulated[body_start..body_start + content_length],
                )
                .to_string();
            }
        }
    }
    String::new()
}

#[test]
fn multiproject_cli_startup_and_dynamic_registration() {
    let dir_a = tempdir().expect("tempdir A");
    let dir_b = tempdir().expect("tempdir B");

    let file_a = dir_a.path().join("main_a.rs");
    let file_b = dir_b.path().join("main_b.py");

    fs::write(&file_a, "fn main_a() { println!(\"Hello A\"); }").expect("write file_a");
    fs::write(&file_b, "def main_b(): print('Hello B')").expect("write file_b");

    let root_a = dir_a.path().to_string_lossy().to_string();
    let root_b = dir_b.path().to_string_lossy().to_string();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nexusintellicore"));
    cmd.arg(&root_a)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().expect("Failed to start MCP server");
    let stdin = child.stdin.as_mut().expect("stdin");
    let stdout = child.stdout.as_mut().expect("stdout");

    // 1. Dynamically register project B
    let reg_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "register_project",
            "arguments": {
                "path": root_b,
                "project_id": "project_b"
            }
        }
    })
    .to_string();
    write_frame(stdin, &reg_req);
    let reg_resp = read_frame(stdout);
    assert!(reg_resp.contains("Successfully registered project 'project_b'"));

    // 2. Call list_projects
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "list_projects",
            "arguments": {}
        }
    })
    .to_string();
    write_frame(stdin, &list_req);
    let list_resp = read_frame(stdout);
    assert!(list_resp.contains("project_b"));

    // 3. Query file outline for Project A file
    let outline_a_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_file_outline",
            "arguments": {
                "file_path": file_a.to_string_lossy()
            }
        }
    })
    .to_string();
    write_frame(stdin, &outline_a_req);
    let outline_a_resp = read_frame(stdout);
    assert!(outline_a_resp.contains("main_a"));

    // 4. Query file outline for Project B file (automatic project resolution by path)
    let outline_b_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_file_outline",
            "arguments": {
                "file_path": file_b.to_string_lossy()
            }
        }
    })
    .to_string();
    write_frame(stdin, &outline_b_req);
    let outline_b_resp = read_frame(stdout);
    assert!(outline_b_resp.contains("main_b"));

    // 5. Unregister project B
    let unreg_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "unregister_project",
            "arguments": {
                "project_id": "project_b"
            }
        }
    })
    .to_string();
    write_frame(stdin, &unreg_req);
    let unreg_resp = read_frame(stdout);
    assert!(unreg_resp.contains("Successfully unregistered project: project_b"));

    let _ = child.kill();
    let _ = child.wait();
}
