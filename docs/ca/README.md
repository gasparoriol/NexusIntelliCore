# NexusIntelliCore

**NexusIntelliCore** és un servidor [Model Context Protocol (MCP)](https://modelcontextprotocol.io) preparat per a producció, escrit en Rust, per a anàlisi semàntica de codi amb controls de privacitat integrats i seguretat d'empresa.

Exposa **17 eines d'intel·ligència de codi** sobre stdio JSON-RPC/MCP i neteja tots els resultats a través d'una Privacy Gateway multicapa abans de retornar-los als clients.

---

## Mètriques de Qualitat i Seguretat Verificades

| Mètrica | Valor |
|---|---|
| Tests automàtics | **362** (100% d'aprovació) |
| Codi insegur | **Zero** — aplicat al nivell del compilador via `#[forbid(unsafe_code)]` |
| Avisos de Clippy | **Zero** — compilació neta sota `-D warnings` |
| Prova d'estrès | 500+ fitxers sintètics, alta concurrència, zero fuites de memòria |
| Tasques CI/CD | **8** tasques automatitzades de seguretat i qualitat |

---

## Què Resol NexusIntelliCore

NexusIntelliCore ajuda les eines habilitades per LLM a entendre repositoris de forma segura i eficient:

- **Gestió multi-projecte en temps d'execució** i resolució automàtica de rutes
- **Descobriment de l'estructura del projecte** amb límits de control d'accés
- **Esquemes a nivell de fitxer** — tipus, importacions, signatures de funcions
- **Inspecció de símbols** amb extracció de codi font dirigida
- **Extracció de gràfics de dependències** amb detecció de dependències circulars
- **Heurístiques de patrons de disseny** i comprovacions de seguretat basades en AST
- **Generació automàtica de documentació** (Markdown, multilingüe: EN, ES, CA)
- **Lectura segura de fitxers de configuració** amb redacció de claus/valors

Totes les sortides de les eines passen per una **Privacy Gateway** centralitzada abans d'arribar al client.

---

## Inici Ràpid

### Requisits previs

- [Rust](https://rustup.rs/) (cadena d'eines estable)
- Gestor de paquets `cargo`

### Compilar

```bash
git clone https://github.com/your-org/NexusIntelliCore.git
cd NexusIntelliCore
cargo build --release
```

Binari de sortida: `target/release/nexusintellicore`

### Executar (Projecte únic)

```bash
./target/release/nexusintellicore /ruta/al/vostre/projecte
```

### Executar (Multi-projecte)

```bash
./target/release/nexusintellicore /ruta/projecte1 /ruta/projecte2
```

### Integració amb VS Code

Afegiu a `.vscode/mcp.json`:

```json
{
  "servers": {
    "nexusintellicore": {
      "transport": "stdio",
      "command": "${workspaceFolder}/target/release/nexusintellicore",
      "cwd": "${workspaceFolder}",
      "args": ["${workspaceFolder}"],
      "env": {
        "MCP_LINT_ENABLED": "true",
        "MCP_LINT_TIMEOUT_SECS": "10",
        "MCP_TOOL_TIMEOUT_SECS": "30",
        "RUST_LOG": "error"
      }
    }
  }
}
```

---

## Eines Disponibles (17)

| Eina | Descripció |
|---|---|
| `get_project_structure` | Arbre de directoris amb marcadors de control d'accés |
| `get_file_outline` | Mapa estructural: signatures, tipus, importacions, doc-comentaris |
| `get_module_summary` | Doc-comentaris de mòdul i resum de l'API pública |
| `inspect_symbol` | Codi font netejat d'una funció, classe o mètode específics |
| `get_dependencies_graph` | Gràfic d'importacions entre mòduls, incloent alertes de cicles |
| `search_design_patterns` | Detecció heurística de patrons de disseny |
| `audit_security_measures` | Escaneig de secrets i detecció de codi insegur basada en AST |
| `analyze_angular_component` | Anàlisi de tríada Angular (Component TS + Plantilla HTML + Estils CSS) |
| `refresh_index` | Reconstruir l'índex de fitxers i buidar les memòries cau d'AST/eines |
| `get_server_stats` | Mètriques operatives del servidor (taxes d'èxit de memòria cau, etc.) |
| `generate_project_docs` | Generar documentació Markdown estructurada automàticament (EN, ES, CA) |
| `lint_file` | Lint híbrid: Nivell 1 Tree-sitter + Nivell 2 extens opcional |
| `query_ast` | Consulta S-expression Tree-sitter ad-hoc contra fitxers font |
| `read_config_file` | Lectura segura de fitxers de configuració amb redacció automàtica |
| `list_projects` | Llistar tots els projectes d'espai de treball actius |
| `register_project` | Registrar dinàmicament un nou arrel de projecte en temps d'execució |
| `unregister_project` | Donar de baixa un arrel de projecte i buidar les seves memòries cau |

---

## Compilació i Publicació

```bash
# Compilar binari estàtic de Linux (MUSL)
cargo make linux-release

# Compilar binari de Windows 64 bits
cargo make windows-release

# Compilar Binari Universal de macOS (Intel + Apple Silicon)
cargo make mac-universal-release

# Executar suite de proves d'estrès i alta concurrència
cargo make stress

# Generar informe de cobertura de codi
cargo make coverage
```

---

## Proves

```bash
# Totes les proves
cargo test

# Proves d'integració
cargo test --test integration
cargo test --test multiproject_integration
cargo test --test privacy_adversarial
```

---

## Documentació

| Document | Descripció |
|---|---|
| [GUIA_USUARI.md](./GUIA_USUARI.md) | Guia d'ús pas a pas per a cada eina MCP |
| [CONFIGURACIO.md](./CONFIGURACIO.md) | Totes les variables d'entorn i opcions de compilació |
| [API.md](./API.md) | Referència completa de l'API MCP (17 eines) |
| [ARQUITECTURA.md](./ARQUITECTURA.md) | Arquitectura interna i anàlisi profunda de mòduls |
| [SEGURETAT.md](./SEGURETAT.md) | Arquitectura de seguretat i Privacy Gateway |

---

## Llicència

Aquest projecte té llicència MIT. Vegeu [`LICENSE.md`](../../LICENSE.md) per a més detalls.
