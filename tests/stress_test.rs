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
    assert!(struct_resp.contains("result"), "Expected valid JSON-RPC response from get_project_structure");

    // Call get_file_outline on multiple generated files
    for i in 0..10 {
        let abs_path = root.join(format!("src/module_{i}/item_0.rs"));
        let outline_resp = client.call_tool("get_file_outline", json!({ "file_path": abs_path.to_str().unwrap() }));
        assert!(outline_resp.contains("result"), "Expected valid response for {abs_path:?}: {outline_resp}");
        assert!(outline_resp.contains(&format!("ModStruct{i}_0")), "Expected symbol ModStruct{i}_0 in outline response");
    }

    // Cleanup
    let _ = fs::remove_dir_all(root);
}
