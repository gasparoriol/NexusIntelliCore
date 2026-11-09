mod common;

use common::{make_temp_workspace, TestMcpClient};
use serde_json::json;
use std::fs;

#[test]
fn test_stress_large_workspace_and_concurrent_queries() {
    let root = make_temp_workspace("stress_test");

    // 1. Create a synthetic workspace with 500+ source files across multiple modules
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    for i in 0..100 {
        let mod_dir = src_dir.join(format!("module_{i}"));
        fs::create_dir_all(&mod_dir).unwrap();
        for j in 0..5 {
            let file_path = mod_dir.join(format!("item_{j}.rs"));
            let content = format!(
                "pub struct ModStruct{i}_{j} {{\n    pub id: u64,\n}}\n\npub fn calculate_{i}_{j}() -> u64 {{\n    {i} * {j}\n}}\n"
            );
            fs::write(file_path, content).unwrap();
        }
    }

    // 2. Perform MCP tool calls under stress
    let client = TestMcpClient::new(root.to_str().unwrap());

    // Call get_project_structure
    let struct_resp = client.call_tool("get_project_structure", json!({}));
    assert!(
        struct_resp.contains("result"),
        "Expected valid JSON-RPC response from get_project_structure"
    );

    // Call get_file_outline on multiple generated files
    for i in 0..10 {
        let abs_path = root.join(format!("src/module_{i}/item_0.rs"));
        let outline_resp = client.call_tool(
            "get_file_outline",
            json!({ "file_path": abs_path.to_str().unwrap() }),
        );
        assert!(
            outline_resp.contains("result"),
            "Expected valid response for {abs_path:?}: {outline_resp}"
        );
        assert!(
            outline_resp.contains(&format!("ModStruct{i}_0")),
            "Expected symbol ModStruct{i}_0 in outline response"
        );
    }

    // Cleanup
    let _ = fs::remove_dir_all(root);
}

/// SAST v2 §6.6: the audit engine (structural + taint) over 500 files stays
/// within ≤ 350 ms total and p95 ≤ 20 ms per file in release (≤ 2.5 s debug).
/// Query compilation is a one-time cost and is warmed up first.
#[test]
fn test_audit_engine_latency_budget_500_files() {
    use std::path::Path;
    use std::time::{Duration, Instant};
    use NexusIntelliCore::analyzer::{audit_file_ast, detect_grammar};

    let body = |i: usize| -> [(&'static str, String); 4] {
        [
            ("A.java", format!(
                "class C{i} {{\n    String find(@RequestParam String id, Statement st) throws Exception {{\n        String q = \"SELECT * FROM t WHERE id = \" + id;\n        StringBuilder sb = new StringBuilder(q);\n        sb.append(\" LIMIT {i}\");\n        log.info(\"q=\" + q);\n        st.executeQuery(sb.toString());\n        return Integer.toString({i});\n    }}\n}}\n"
            )),
            ("a.py", format!(
                "from flask import request\nimport os\n\ndef handler_{i}(cur):\n    name = request.args.get('n')\n    q = f\"SELECT * FROM t WHERE n = '{{name}}'\"\n    cur.execute(q)\n    os.system('echo ' + name)\n    return open('/srv/' + name).read()\n"
            )),
            ("a.js", format!(
                "app.get('/r{i}', async (req, res) => {{\n  const {{ id }} = req.query;\n  const sql = `SELECT * FROM t WHERE id = ${{id}}`;\n  await db.query(sql);\n  logger.info('id ' + id);\n  res.redirect(req.query.next);\n}});\n"
            )),
            ("a.rs", format!(
                "async fn h{i}(Query(q): Query<F>, pool: PgPool) {{\n    let sql = format!(\"SELECT * FROM t WHERE id = '{{}}'\", q.id);\n    sqlx::query(&sql).fetch_all(&pool).await.ok();\n    Command::new(&q.bin).spawn().ok();\n}}\n"
            )),
        ]
    };
    let files: Vec<(&str, String)> = (0..125).flat_map(body).collect();
    assert_eq!(files.len(), 500);

    for (name, src) in files.iter().take(4) {
        let grammar = detect_grammar(Path::new(name)).expect("grammar");
        assert!(
            !audit_file_ast(src, grammar).is_empty(),
            "warm-up {name} must find flows"
        );
    }

    let mut per_file: Vec<Duration> = Vec::with_capacity(files.len());
    let start = Instant::now();
    for (name, src) in &files {
        let grammar = detect_grammar(Path::new(name)).expect("grammar");
        let t = Instant::now();
        let _ = audit_file_ast(src, grammar);
        per_file.push(t.elapsed());
    }
    let total = start.elapsed();
    per_file.sort();
    let p95 = per_file[per_file.len() * 95 / 100];

    let (total_budget, p95_budget) = if cfg!(debug_assertions) {
        (Duration::from_millis(2500), Duration::from_millis(100))
    } else {
        (Duration::from_millis(350), Duration::from_millis(20))
    };
    eprintln!(
        "audit engine: total={total:?} p95={p95:?} (budget {total_budget:?} / {p95_budget:?})"
    );
    assert!(
        total <= total_budget,
        "500-file audit took {total:?} > {total_budget:?}"
    );
    assert!(p95 <= p95_budget, "per-file p95 {p95:?} > {p95_budget:?}");
}
