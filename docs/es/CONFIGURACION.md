# NexusIntelliCore — Referencia de Configuración

Este documento cubre todas las variables de entorno, argumentos de inicio y objetivos de compilación disponibles en NexusIntelliCore.

---

## Argumentos de Inicio

El servidor acepta una o más rutas raíz de proyecto como argumentos CLI posicionales:

```bash
# Modo de proyecto único
nexusintellicore /ruta/al/proyecto

# Modo multi-proyecto
nexusintellicore /ruta/proyecto1 /ruta/proyecto2 /ruta/proyecto3
```

Si no se proporciona ninguna ruta, el servidor recurre a `MCP_ROOT_PATH` o se inicia vacío esperando un registro dinámico via `register_project`.

---

## Variables de Entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `MCP_AUTH_TOKEN` | *Ninguno* | Token de autenticación esperado para el handshake MCP `initialize`. Si se establece, todos los clientes deben proporcionar este token. |
| `MCP_ALLOWED_TOOLS` | *Todos* | Lista blanca separada por comas de nombres de herramientas permitidos. |
| `MCP_AUDIT_LOG_PATH` | *Ninguno* | Ruta de archivo para registro NDJSON con cadena de hash criptográfico. |
| `MCP_SECURITY_CONFIG_PATH` | *Ninguno* | Ruta a un archivo de configuración de seguridad JSON. |
| `MCP_TOOL_TIMEOUT_SECS` | `30` | Tiempo de espera en segundos para la ejecución individual de herramientas. |
| `MCP_LINT_ENABLED` | `false` | Activa los linters externos de Nivel 2 (`cargo clippy`, `eslint`, `mypy`, etc.). |
| `MCP_LINT_TIMEOUT_SECS` | `10` | Tiempo de espera en segundos para la ejecución de linters externos. |
| `MCP_ROOT_PATH` | *Ninguno* | Ruta raíz de proyecto de reserva si no se proporciona via argumento CLI. |
| `RUST_LOG` | `error` | Nivel de registro. Valores: `error`, `warn`, `info`, `debug`, `trace`. |

### Ejemplos de Uso

```bash
# Ejecutar con token de autenticación
MCP_AUTH_TOKEN="su-token-secreto" nexusintellicore /ruta/al/proyecto

# Activar lint externo con tiempo de espera largo
MCP_LINT_ENABLED=true MCP_LINT_TIMEOUT_SECS=30 nexusintellicore /ruta/al/proyecto

# Activar registro de auditoría
MCP_AUDIT_LOG_PATH=/var/log/nexusintellicore-audit.ndjson nexusintellicore /ruta/al/proyecto

# Restringir herramientas disponibles
MCP_ALLOWED_TOOLS="get_file_outline,inspect_symbol,audit_security_measures" nexusintellicore /ruta/al/proyecto

# Registro de depuración
RUST_LOG=nexusintellicore=debug nexusintellicore /ruta/al/proyecto
```

---

## Configuración MCP para VS Code

Añada a `.vscode/mcp.json` en su espacio de trabajo:

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

## Objetivos de Compilación (Makefile.toml)

Todos los objetivos usan `cargo-make`. Instale con: `cargo install cargo-make`

| Objetivo | Comando | Descripción |
|---|---|---|
| `linux-release` | `cargo make linux-release` | Compilar binario estático de Linux (MUSL, x86_64) |
| `windows-release` | `cargo make windows-release` | Compilar binario de Windows 64 bits (`.exe`) |
| `mac-universal-release` | `cargo make mac-universal-release` | Compilar Binario Universal de macOS (Intel + Apple Silicon) |
| `stress` | `cargo make stress` | Ejecutar suite de pruebas de estrés y alta concurrencia |
| `coverage` | `cargo make coverage` | Generar informe de cobertura de código (requiere `cargo-tarpaulin`) |

### Verificación de Activos de Publicación

Cada binario de publicación incluye un archivo de suma de comprobación SHA-256:

```bash
# Verificar binario Linux
sha256sum -c nexusintellicore-linux-musl.sha256

# Verificar binario macOS
shasum -a 256 -c nexusintellicore-macos-universal.sha256
```

---

## Herramientas con Caché

| Herramienta | Caché |
|---|:---:|
| `get_project_structure` | No |
| `get_file_outline` | ✅ Sí |
| `get_module_summary` | ✅ Sí |
| `inspect_symbol` | ✅ Sí |
| `get_dependencies_graph` | ✅ Sí |
| `search_design_patterns` | ✅ Sí |
| `audit_security_measures` | ✅ Sí |
| `analyze_angular_component` | ✅ Sí |
| `refresh_index` | No |
| `get_server_stats` | No |
| `generate_project_docs` | ✅ Sí |
| `lint_file` | ✅ Sí |
| `query_ast` | ✅ Sí |
| `read_config_file` | ✅ Sí |
| `list_projects` | No |
| `register_project` | No |
| `unregister_project` | No |

La caché se invalida automáticamente cuando los archivos cambian. Puede forzar un vaciado completo con `refresh_index`.
