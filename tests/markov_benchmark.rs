use NexusIntelliCore::analyzer::MarkovAstPredictor;
use std::time::Instant;
use tree_sitter::Parser;

/// Genera un código fuente sintetizado de gran tamaño con estructuras AST complejas
fn generate_large_source_code(files: usize) -> String {
    let mut code = String::new();
    for i in 0..files {
        code.push_str(&format!(
            r#"
pub struct ServiceContext_{i} {{
    pub id: u64,
    pub name: String,
    pub active: bool,
}}

impl ServiceContext_{i} {{
    pub fn new(id: u64, name: &str) -> Self {{
        Self {{
            id,
            name: name.to_string(),
            active: true,
        }}
    }}

    pub fn process_data(&self, value: u64) -> Result<u64, String> {{
        if value == 0 {{
            return Err("Zero value".to_string());
        }}
        let mut sum = 0;
        for k in 0..value {{
            if k % 2 == 0 {{
                sum += k * 2;
            }} else {{
                sum += k;
            }}
        }}
        Ok(sum + self.id)
    }}

    pub fn validate(&self) -> bool {{
        if !self.active {{
            return false;
        }}
        self.name.len() > 3
    }}
}}
"#
        ));
    }
    code
}

#[test]
fn test_markov_performance_benchmark() {
    let source = generate_large_source_code(150); // Genera ~6.000 líneas de código Rust
    let ts_lang = tree_sitter_rust::language();

    let mut parser = Parser::new();
    parser.set_language(&ts_lang).unwrap();

    let tree = parser.parse(&source, None).expect("Fallo al parsear");
    let root = tree.root_node();

    // 1. Entrenamiento del Predictor de Markov
    let mut predictor = MarkovAstPredictor::new();
    let start_train = Instant::now();
    predictor.observe_tree(root);
    let train_duration = start_train.elapsed();

    println!("\n=======================================================");
    println!("   BENCHMARK DE RENDIMIENTO: MARKOV PREDICTOR VS BASELINE");
    println!("=======================================================");
    println!("Total de Nodos en AST: {}", root.descendant_count());
    println!("Observaciones Markov de 2º orden acumuladas: {}", predictor.total_observations());
    println!("Tiempo de entrenamiento del Predictor: {:?}", train_duration);

    // Objetivo de búsqueda: identificar llamadas a funciones/métodos (ej. `call_expression`)
    // Obtener kind_id de `call_expression` y `field_expression` en la gramática
    let call_expr_kind = ts_lang.id_for_node_kind("call_expression", true);
    let field_expr_kind = ts_lang.id_for_node_kind("field_expression", true);
    let target_kinds = vec![call_expr_kind, field_expr_kind];

    // Iteraciones para benchmark de latencia
    let iterations = 50;

    // -----------------------------------------------------------------------
    // ESCENARIO A: BASELINE (Sin Cadenas de Markov - Recorrido exhaustivo)
    // -----------------------------------------------------------------------
    let start_baseline = Instant::now();
    let mut baseline_nodes_visited = 0usize;
    let mut baseline_matches = 0usize;

    for _ in 0..iterations {
        baseline_nodes_visited = 0;
        baseline_matches = 0;

        let mut stack = vec![(0u16, root)]; // (parent_kind, node)
        while let Some((_parent_kind, node)) = stack.pop() {
            baseline_nodes_visited += 1;
            let kind = node.kind_id();
            if target_kinds.contains(&kind) {
                baseline_matches += 1;
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((kind, child));
            }
        }
    }
    let baseline_duration = start_baseline.elapsed();

    // -----------------------------------------------------------------------
    // ESCENARIO B: CON CADENAS DE MARKOV (Predictive Pruning / Skip-Traversal)
    // -----------------------------------------------------------------------
    let start_markov = Instant::now();
    let mut markov_nodes_visited = 0usize;
    let mut markov_nodes_pruned = 0usize;
    let mut markov_matches = 0usize;

    let pruning_threshold = 0.005; // 0.5% umbral de descarte de subárboles improbables

    for _ in 0..iterations {
        markov_nodes_visited = 0;
        markov_nodes_pruned = 0;
        markov_matches = 0;

        let mut stack = vec![(0u16, root)]; // (parent_kind, node)
        while let Some((parent_kind, node)) = stack.pop() {
            markov_nodes_visited += 1;
            let kind = node.kind_id();
            if target_kinds.contains(&kind) {
                markov_matches += 1;
            }

            // Aplicar evaluación de la Cadena de Markov antes de expandir hijos
            if predictor.should_prune_subtree(parent_kind, kind, &target_kinds, pruning_threshold) {
                markov_nodes_pruned += node.child_count();
                continue; // Skip subtree expansion
            }

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((kind, child));
            }
        }
    }
    let markov_duration = start_markov.elapsed();

    // -----------------------------------------------------------------------
    // RESULTADOS Y COMPARATIVA
    // -----------------------------------------------------------------------
    let baseline_avg_us = baseline_duration.as_micros() as f64 / iterations as f64;
    let markov_avg_us = markov_duration.as_micros() as f64 / iterations as f64;
    let speedup = if markov_avg_us > 0.0 {
        baseline_avg_us / markov_avg_us
    } else {
        1.0
    };
    let recall = if baseline_matches > 0 {
        (markov_matches as f64 / baseline_matches as f64) * 100.0
    } else {
        100.0
    };

    println!("\n-------------------------------------------------------");
    println!("                    RESULTADOS DE RENDIMIENTO");
    println!("-------------------------------------------------------");
    println!("Métrica                             | Baseline (Sin Markov) | Predictivo (Con Markov)");
    println!("------------------------------------+-----------------------+-------------------------");
    println!("Tiempo Promedio por Recorrido       | {:>17.2} µs | {:>19.2} µs", baseline_avg_us, markov_avg_us);
    println!("Nodos Visitados por Pasada          | {:>21} | {:>23}", baseline_nodes_visited, markov_nodes_visited);
    println!("Nodos Descartados (Subtree Pruning) | {:>21} | {:>23}", 0, markov_nodes_pruned);
    println!("Coincidencias Encontradas           | {:>21} | {:>23}", baseline_matches, markov_matches);
    println!("-------------------------------------------------------");
    println!("Aceleración (Speedup Factor)        : {:.2}x", speedup);
    println!("Precisión / Exhaustividad (Recall)  : {:.2}%", recall);
    println!("=======================================================\n");

    assert!(baseline_matches > 0, "Debe haber encontrado coincidencias");
    assert_eq!(baseline_matches, markov_matches, "El modelo predictivo no debe perder coincidencias verdaderas");
}
