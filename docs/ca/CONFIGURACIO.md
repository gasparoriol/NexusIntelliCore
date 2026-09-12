# NexusIntelliCore — Referència de Configuració

Aquest document cobreix totes les variables d'entorn, arguments d'inici i objectius de compilació disponibles a NexusIntelliCore.

---

## Arguments d'Inici

El servidor accepta una o més rutes arrel de projecte com a arguments CLI posicionals:

```bash
# Mode de projecte únic
nexusintellicore /ruta/al/projecte

# Mode multi-projecte
nexusintellicore /ruta/projecte1 /ruta/projecte2 /ruta/projecte3
```

Si no es proporciona cap ruta, el servidor recorre a `MCP_ROOT_PATH` o s'inicia buit esperant un registre dinàmic via `register_project`.

---

## Variables d'Entorn

| Variable | Per defecte | Descripció |
|---|---|---|
| `MCP_AUTH_TOKEN` | *Cap* | Token d'autenticació esperat per al handshake MCP `initialize`. Si s'estableix, tots els clients han de proporcionar aquest token. |
| `MCP_ALLOWED_TOOLS` | *Tots* | Llista blanca separada per comes de noms d'eines permesos. |
| `MCP_AUDIT_LOG_PATH` | *Cap* | Ruta de fitxer per a registre NDJSON amb cadena de hash criptogràfic. |
| `MCP_SECURITY_CONFIG_PATH` | *Cap* | Ruta a un fitxer de configuració de seguretat JSON. |
| `MCP_TOOL_TIMEOUT_SECS` | `30` | Temps d'espera en segons per a l'execució individual d'eines. |
| `MCP_LINT_ENABLED` | `false` | Activa els linters externs de Nivell 2 (`cargo clippy`, `eslint`, `mypy`, etc.). |
| `MCP_LINT_TIMEOUT_SECS` | `10` | Temps d'espera en segons per a l'execució de linters externs. |
| `MCP_ROOT_PATH` | *Cap* | Ruta arrel de projecte de reserva si no es proporciona via argument CLI. |
| `RUST_LOG` | `error` | Nivell de registre. Valors: `error`, `warn`, `info`, `debug`, `trace`. |

### Exemples d'Ús

```bash
# Executar amb token d'autenticació
MCP_AUTH_TOKEN="el-vostre-token-secret" nexusintellicore /ruta/al/projecte

# Activar lint extern amb temps d'espera llarg
MCP_LINT_ENABLED=true MCP_LINT_TIMEOUT_SECS=30 nexusintellicore /ruta/al/projecte

# Activar registre d'auditoria
MCP_AUDIT_LOG_PATH=/var/log/nexusintellicore-audit.ndjson nexusintellicore /ruta/al/projecte

# Restringir eines disponibles
MCP_ALLOWED_TOOLS="get_file_outline,inspect_symbol,audit_security_measures" nexusintellicore /ruta/al/projecte

# Registre de depuració
RUST_LOG=nexusintellicore=debug nexusintellicore /ruta/al/projecte
```

---

## Configuració MCP per a VS Code

Afegiu a `.vscode/mcp.json` al vostre espai de treball:

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

## Objectius de Compilació (Makefile.toml)

Tots els objectius usen `cargo-make`. Instal·leu amb: `cargo install cargo-make`

| Objectiu | Comanda | Descripció |
|---|---|---|
| `linux-release` | `cargo make linux-release` | Compilar binari estàtic de Linux (MUSL, x86_64) |
| `windows-release` | `cargo make windows-release` | Compilar binari de Windows 64 bits (`.exe`) |
| `mac-universal-release` | `cargo make mac-universal-release` | Compilar Binari Universal de macOS (Intel + Apple Silicon) |
| `stress` | `cargo make stress` | Executar suite de proves d'estrès i alta concurrència |
| `coverage` | `cargo make coverage` | Generar informe de cobertura de codi (requereix `cargo-tarpaulin`) |

### Verificació d'Actius de Publicació

Cada binari de publicació inclou un fitxer de suma de comprovació SHA-256:

```bash
# Verificar binari Linux
sha256sum -c nexusintellicore-linux-musl.sha256

# Verificar binari macOS
shasum -a 256 -c nexusintellicore-macos-universal.sha256
```

---

## Eines amb Memòria Cau

| Eina | Memòria Cau |
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

La memòria cau s'invalida automàticament quan els fitxers canvien. Podeu forçar un buidatge complet amb `refresh_index`.
