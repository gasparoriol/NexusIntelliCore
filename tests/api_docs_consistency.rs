/// C1 — Registry-to-docs consistency test (mitigación 07, fase 3).
///
/// Verifica que la tabla de herramientas en docs/API.md coincide con
/// el registro ejecutable. Un tool nuevo sin documentar o un nombre
/// documentado que no exista en el registro rompe el test.
///
/// The canonical set of registered tool names — must equal `all_registered_tools_are_covered_by_sentinel_gate` in src/tools/mod.rs.
const REGISTRY_NAMES: &[&str] = &[
    "analyze_angular_component",
    "audit_security_measures",
    "generate_project_docs",
    "get_dependencies_graph",
    "get_file_outline",
    "get_module_summary",
    "get_project_structure",
    "get_server_stats",
    "inspect_symbol",
    "lint_file",
    "query_ast",
    "read_config_file",
    "refresh_index",
    "search_design_patterns",
];

#[test]
fn api_docs_tool_table_matches_registry() {
    let root = env!("CARGO_MANIFEST_DIR");
    let api_md = std::fs::read_to_string(format!("{root}/docs/API.md"))
        .expect("docs/API.md must be readable");

    // Verify structural markers are present.
    assert!(
        api_md.contains("## Current MCP Contract"),
        "docs/API.md must contain '## Current MCP Contract' section"
    );
    assert!(
        api_md.contains("## Historical API Material"),
        "docs/API.md must contain '## Historical API Material' marker"
    );

    // Only search within the Current MCP Contract section.
    let contract_start = api_md
        .find("## Current MCP Contract")
        .expect("section marker must exist");
    let contract_end = api_md[contract_start..]
        .find("## Historical API Material")
        .map_or(api_md.len(), |i| contract_start + i);
    let contract_section = &api_md[contract_start..contract_end];

    // Every registered tool must appear in the normative section.
    for &tool in REGISTRY_NAMES {
        assert!(
            contract_section.contains(tool),
            "Tool '{}' is in the registry but missing from '## Current MCP Contract' in docs/API.md",
            tool
        );
    }

    // Stale internal method paths must not leak into the normative section.
    for stale in &[
        "tools/project",
        "tools/analyze_file",
        "tools/audit",
        "tools/deps_graph",
    ] {
        assert!(
            !contract_section.contains(stale),
            "Stale method '{}' found inside '## Current MCP Contract' — move it to the Historical section",
            stale
        );
    }
}
