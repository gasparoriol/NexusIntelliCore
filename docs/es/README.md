# NexusIntelliCore

**NexusIntelliCore** es un servidor [Model Context Protocol (MCP)](https://modelcontextprotocol.io) listo para producción, escrito en Rust, para análisis semántico de código con controles de privacidad integrados y seguridad de nivel empresarial.

Expone **17 herramientas de inteligencia de código** sobre stdio JSON-RPC/MCP y sanitiza todas las salidas a través de una Privacy Gateway multicapa antes de devolverlas a los clientes.

---

## Métricas de Calidad y Seguridad Verificadas

| Métrica | Valor |
|---|---|
| Tests automatizados | **362** (100% de aprobación) |
| Código inseguro | **Cero** — aplicado a nivel del compilador via `#[forbid(unsafe_code)]` |
| Avisos de Clippy | **Cero** — compilación limpia bajo `-D warnings` |
| Prueba de estrés | 500+ archivos sintéticos, alta concurrencia, cero fugas de memoria |
| Tareas CI/CD | **8** tareas automatizadas de seguridad y calidad |

---

## Qué Resuelve NexusIntelliCore

NexusIntelliCore ayuda a las herramientas habilitadas para LLM a entender repositorios de forma segura y eficiente:

- **Gestión multi-proyecto en tiempo de ejecución** y resolución automática de rutas
- **Descubrimiento de la estructura del proyecto** con límites de control de acceso
- **Esquemas a nivel de archivo** — tipos, importaciones, firmas de funciones
- **Inspección de símbolos** con extracción de código fuente dirigida
- **Extracción de gráficos de dependencias** con detección de dependencias circulares
- **Heurísticas de patrones de diseño** y comprobaciones de seguridad basadas en AST
- **Generación automática de documentación** (Markdown, multilingüe: EN, ES, CA)
- **Lectura segura de archivos de configuración** con redacción de claves/valores

Todas las salidas de las herramientas pasan por una **Privacy Gateway** centralizada antes de llegar al cliente.

---

## Inicio Rápido

### Requisitos previos

- [Rust](https://rustup.rs/) (cadena de herramientas estable)
- Gestor de paquetes `cargo`

### Compilar

```bash
git clone https://github.com/your-org/NexusIntelliCore.git
cd NexusIntelliCore
cargo build --release
```

Binario de salida: `target/release/nexusintellicore`

### Ejecutar (Proyecto único)

```bash
./target/release/nexusintellicore /ruta/a/su/proyecto
```

### Ejecutar (Multi-proyecto)

```bash
./target/release/nexusintellicore /ruta/proyecto1 /ruta/proyecto2
```

### Integración con VS Code

Añada a `.vscode/mcp.json`:

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

## Herramientas Disponibles (17)

| Herramienta | Descripción |
|---|---|
| `get_project_structure` | Árbol de directorios con marcadores de control de acceso |
| `get_file_outline` | Mapa estructural: firmas, tipos, importaciones, doc-comentarios |
| `get_module_summary` | Doc-comentarios de módulo y resumen de la API pública |
| `inspect_symbol` | Código fuente sanitizado de una función, clase o método específicos |
| `get_dependencies_graph` | Gráfico de importaciones entre módulos, incluyendo alertas de ciclos |
| `search_design_patterns` | Detección heurística de patrones de diseño en archivos |
| `audit_security_measures` | Escaneo de secretos y detección de código inseguro basada en AST |
| `analyze_angular_component` | Análisis de tríada Angular (Componente TS + Plantilla HTML + Estilos CSS) |
| `refresh_index` | Reconstruir el índice de archivos y vaciar cachés de AST/herramientas |
| `get_server_stats` | Métricas operativas del servidor (tasas de acierto de caché, etc.) |
| `generate_project_docs` | Generar documentación Markdown estructurada automáticamente (EN, ES, CA) |
| `lint_file` | Lint híbrido: Nivel 1 Tree-sitter + Nivel 2 externo opcional |
| `query_ast` | Consulta S-expression Tree-sitter ad-hoc contra archivos fuente |
| `read_config_file` | Lectura segura de archivos de configuración con redacción automática |
| `list_projects` | Listar todos los proyectos de espacio de trabajo activos |
| `register_project` | Registrar dinámicamente una nueva raíz de proyecto en tiempo de ejecución |
| `unregister_project` | Dar de baja una raíz de proyecto y vaciar sus cachés asociadas |

---

## Compilación y Publicación

```bash
# Compilar binario estático de Linux (MUSL)
cargo make linux-release

# Compilar binario de Windows 64 bits
cargo make windows-release

# Compilar Binario Universal de macOS (Intel + Apple Silicon)
cargo make mac-universal-release

# Ejecutar suite de pruebas de estrés y alta concurrencia
cargo make stress

# Generar informe de cobertura de código
cargo make coverage
```

---

## Pruebas

```bash
# Todas las pruebas
cargo test

# Pruebas de integración
cargo test --test integration
cargo test --test multiproject_integration
cargo test --test privacy_adversarial
```

---

## Documentación

| Documento | Descripción |
|---|---|
| [GUIA_USUARIO.md](./GUIA_USUARIO.md) | Guía de uso paso a paso para cada herramienta MCP |
| [CONFIGURACION.md](./CONFIGURACION.md) | Todas las variables de entorno y opciones de compilación |
| [API.md](./API.md) | Referencia completa de la API MCP (17 herramientas) |
| [ARQUITECTURA.md](./ARQUITECTURA.md) | Arquitectura interna y análisis profundo de módulos |
| [SEGURIDAD.md](./SEGURIDAD.md) | Arquitectura de seguridad y Privacy Gateway |

---

## Licencia

Este proyecto tiene licencia MIT. Consulte [`LICENSE.md`](../../LICENSE.md) para más detalles.
