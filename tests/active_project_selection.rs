use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use tempfile::{tempdir, TempDir};

struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    next_id: u64,
}

impl Server {
    fn start(roots: &[&Path]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nexusintellicore"))
            .args(roots)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("MCP_SECURITY_CONFIG_PATH")
            .env_remove("MCP_AUTH_TOKEN")
            .env_remove("MCP_ALLOWED_TOOLS")
            .env_remove("MCP_AUDIT_LOG_PATH")
            .spawn()
            .expect("server should start");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let body =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        write!(self.stdin, "Content-Length: {}\r\n\r\n{body}", body.len())
            .expect("request should be written");
        self.stdin.flush().expect("stdin should flush");
        read_frame(&mut self.stdout)
    }

    fn initialize(&mut self, params: Value) {
        let resp = self.request("initialize", params);
        assert!(resp.get("error").is_none(), "initialize failed: {resp}");
    }

    /// Returns the `result` object of a tools/call response.
    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let resp = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        resp.get("result")
            .cloned()
            .expect("tool call should return a result")
    }

    fn project_ids(&mut self) -> Vec<String> {
        let listed = parse_text(&self.tool("list_projects", json!({})));
        listed["projects"]
            .as_array()
            .expect("projects array")
            .iter()
            .map(|p| p["id"].as_str().expect("id").to_owned())
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_frame(stdout: &mut ChildStdout) -> Value {
    let mut acc = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&acc[..pos]).into_owned();
            let len: usize = header
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.trim().parse().ok())
                .expect("Content-Length header");
            let start = pos + 4;
            if acc.len() >= start + len {
                return serde_json::from_slice(&acc[start..start + len]).expect("valid JSON frame");
            }
        }
        let n = stdout.read(&mut buf).expect("read from server");
        assert!(n > 0, "server closed stdout unexpectedly");
        acc.extend_from_slice(&buf[..n]);
    }
}

fn text(result: &Value) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn parse_text(result: &Value) -> Value {
    serde_json::from_str(&text(result)).expect("tool text should be JSON")
}

fn is_error(result: &Value) -> bool {
    result["isError"].as_bool() == Some(true)
}

struct Fixture {
    dir_a: TempDir,
    dir_b: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir_a = tempdir().expect("tempdir A");
        let dir_b = tempdir().expect("tempdir B");
        fs::write(dir_a.path().join("only_in_a.rs"), "fn a() {}\n").expect("write a");
        fs::write(dir_b.path().join("only_in_b.rs"), "fn b() {}\n").expect("write b");
        Self { dir_a, dir_b }
    }

    fn start(&self) -> Server {
        Server::start(&[self.dir_a.path(), self.dir_b.path()])
    }

    fn id_of(&self, server: &mut Server, dir: &Path) -> String {
        let canonical = fs::canonicalize(dir).expect("canonical dir");
        let listed = parse_text(&server.tool("list_projects", json!({})));
        listed["projects"]
            .as_array()
            .expect("projects array")
            .iter()
            .find(|p| Path::new(p["root"].as_str().unwrap_or_default()) == canonical)
            .and_then(|p| p["id"].as_str())
            .expect("project should be registered")
            .to_owned()
    }
}

fn file_uri(dir: &Path) -> String {
    format!("file://{}", dir.display())
}

#[test]
fn initialize_root_uri_selects_the_matching_project() {
    let fx = Fixture::new();
    let mut server = fx.start();
    server.initialize(json!({ "rootUri": file_uri(fx.dir_b.path()) }));

    let id_b = fx.id_of(&mut server, fx.dir_b.path());
    let result = server.tool("get_project_structure", json!({}));
    let structure = text(&result);
    assert!(structure.contains("only_in_b.rs"), "{structure}");
    assert!(!structure.contains("only_in_a.rs"), "{structure}");
    assert_eq!(result["project"]["id"], id_b);
}

#[test]
fn initialize_workspace_folders_select_the_matching_project() {
    let fx = Fixture::new();
    let mut server = fx.start();
    server.initialize(json!({
        "workspaceFolders": [
            { "uri": "file:///definitely/not/registered", "name": "x" },
            { "uri": file_uri(fx.dir_b.path()), "name": "b" }
        ]
    }));

    let result = server.tool("get_project_structure", json!({}));
    assert!(text(&result).contains("only_in_b.rs"));
}

#[test]
fn explicit_project_id_overrides_the_active_project() {
    let fx = Fixture::new();
    let mut server = fx.start();
    server.initialize(json!({ "rootUri": file_uri(fx.dir_b.path()) }));

    let id_a = fx.id_of(&mut server, fx.dir_a.path());
    let result = server.tool("get_project_structure", json!({ "project_id": id_a }));
    let structure = text(&result);
    assert!(structure.contains("only_in_a.rs"), "{structure}");
    assert_eq!(result["project"]["id"], id_a);

    let by_path = server.tool(
        "get_project_structure",
        json!({ "root_path": fx.dir_a.path() }),
    );
    assert!(text(&by_path).contains("only_in_a.rs"));
}

#[test]
fn unknown_project_id_lists_valid_ids() {
    let fx = Fixture::new();
    let mut server = fx.start();
    let ids = server.project_ids();

    let result = server.tool("get_project_structure", json!({ "project_id": "nope" }));
    assert!(is_error(&result));
    let message = text(&result);
    for id in ids {
        assert!(message.contains(&id), "{message} should list {id}");
    }
}

#[test]
fn set_active_project_switches_stats_and_structure() {
    let fx = Fixture::new();
    let mut server = fx.start();
    let id_b = fx.id_of(&mut server, fx.dir_b.path());

    let switched = parse_text(&server.tool("set_active_project", json!({ "project_id": id_b })));
    assert_eq!(switched["active_project_id"], id_b);
    assert_eq!(
        Path::new(switched["root"].as_str().expect("root")),
        fs::canonicalize(fx.dir_b.path()).expect("canonical")
    );
    assert!(switched["files_indexed"].as_u64().unwrap_or(0) >= 1);

    let stats = text(&server.tool("get_server_stats", json!({})));
    assert!(
        stats.contains(&format!("\"active_project_id\": \"{id_b}\"")),
        "{stats}"
    );
    assert!(text(&server.tool("get_project_structure", json!({}))).contains("only_in_b.rs"));
}

#[test]
fn set_active_project_rejects_unknown_ids() {
    let fx = Fixture::new();
    let mut server = fx.start();
    let result = server.tool("set_active_project", json!({ "project_id": "ghost" }));
    assert!(is_error(&result));
}

#[test]
fn sessions_do_not_share_the_active_project() {
    let fx = Fixture::new();
    let mut server_a = fx.start();
    let mut server_b = fx.start();
    server_a.initialize(json!({ "rootUri": file_uri(fx.dir_a.path()) }));
    server_b.initialize(json!({ "rootUri": file_uri(fx.dir_b.path()) }));

    assert!(text(&server_a.tool("get_project_structure", json!({}))).contains("only_in_a.rs"));
    assert!(text(&server_b.tool("get_project_structure", json!({}))).contains("only_in_b.rs"));
}

#[test]
fn register_project_with_set_active_marks_a_single_active_project() {
    let fx = Fixture::new();
    let extra = tempdir().expect("extra dir");
    fs::write(extra.path().join("only_in_extra.rs"), "fn e() {}\n").expect("write extra");
    let mut server = fx.start();

    let registered = server.tool(
        "register_project",
        json!({ "path": extra.path(), "project_id": "extra", "set_active": true }),
    );
    assert!(!is_error(&registered), "{registered}");
    assert!(text(&registered).contains("Successfully registered project 'extra'"));

    let listed = parse_text(&server.tool("list_projects", json!({})));
    let projects = listed["projects"].as_array().expect("projects");
    let active: Vec<&str> = projects
        .iter()
        .filter(|p| p["active"] == true)
        .filter_map(|p| p["id"].as_str())
        .collect();
    assert_eq!(active, ["extra"]);
    assert!(text(&server.tool("get_project_structure", json!({}))).contains("only_in_extra.rs"));
}

#[test]
fn project_references_outside_registered_roots_are_rejected() {
    let fx = Fixture::new();
    let mut server = fx.start();

    let parent = fx.dir_a.path().parent().expect("parent dir");
    for reference in [
        parent.to_string_lossy().into_owned(),
        fx.dir_a.path().join("..").to_string_lossy().into_owned(),
        "/".to_owned(),
    ] {
        let by_root = server.tool("get_project_structure", json!({ "root_path": reference }));
        assert!(is_error(&by_root), "{reference} must be rejected");
        let by_id = server.tool("set_active_project", json!({ "project_id": reference }));
        assert!(is_error(&by_id), "{reference} must be rejected");
    }
}

#[test]
fn file_outside_the_explicit_project_is_denied() {
    let fx = Fixture::new();
    let mut server = fx.start();
    let id_a = fx.id_of(&mut server, fx.dir_a.path());

    let result = server.tool(
        "get_file_outline",
        json!({
            "file_path": fx.dir_b.path().join("only_in_b.rs"),
            "project_id": id_a
        }),
    );
    assert!(is_error(&result), "{result}");
    assert!(text(&result).contains("Access denied"));
}

#[test]
fn calls_without_project_id_keep_the_previous_behaviour() {
    let fx = Fixture::new();
    let mut server = fx.start();

    // No handshake selection: the first root (args[0]) is the default project.
    let structure = server.tool("get_project_structure", json!({}));
    assert!(text(&structure).contains("only_in_a.rs"));

    // File-scoped tools still resolve the owning project from the path.
    let outline = server.tool(
        "get_file_outline",
        json!({ "file_path": fx.dir_b.path().join("only_in_b.rs") }),
    );
    assert!(!is_error(&outline));
    assert!(text(&outline).contains('b'));
    assert_eq!(
        Path::new(outline["project"]["root"].as_str().expect("project root")),
        fs::canonicalize(fx.dir_b.path()).expect("canonical")
    );
}
