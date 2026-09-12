# NexusIntelliCore — Referencia Completa de la API MCP

> **Vigente a partir de:** v0.9.0 (2026-09-12). Este documento es la fuente normativa del contrato MCP. Debe coincidir con `src/tools/definitions.rs`.

---

## Protocolo MCP

NexusIntelliCore se comunica via **JSON-RPC 2.0** sobre **MCP stdio framing** (cabeceras `Content-Length`). El modo JSON delimitado por líneas también es compatible.

### Métodos de Protocolo Soportados

| Método | Descripción |
|---|---|
| `initialize` | Handshake MCP (autenticación si `MCP_AUTH_TOKEN` está configurado) |
| `notifications/initialized` | Notificación — no se espera respuesta |
| `tools/list` | Descubrir las herramientas disponibles |
| `tools/call` | Invocar una herramienta |
| `ping` | Comprobación de disponibilidad del servidor |

### Formato de Solicitud

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "nombre_herramienta",
    "arguments": { "param": "valor" }
  }
}
```

### Formato de Respuesta Correcta

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{ "type": "text", "text": "Salida..." }],
    "isError": false
  }
}
```

### Códigos de Error

| Código | Mensaje | Significado |
|---|---|---|
| `-32700` | Parse Error | JSON inválido recibido |
| `-32600` | Invalid Request | Formato de solicitud inválido |
| `-32601` | Method Not Found | Nombre de herramienta o método desconocido |
| `-32602` | Invalid Params | Los parámetros no coinciden con el esquema esperado |
| `-32603` | Internal Error | Error del servidor durante el procesamiento |

---

## Referencia de Herramientas

### 1. `get_project_structure`

Devuelve un árbol de directorios compacto con marcadores de control de acceso.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `project` | string | No | ID o alias de proyecto. Por defecto: primer proyecto registrado. |

**Almacenado en caché:** No

---

### 2. `get_file_outline`

Devuelve el mapa estructural de un archivo: importaciones, tipos, firmas de funciones y doc-comentarios.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta relativa o absoluta al archivo fuente |

**Almacenado en caché:** Sí

---

### 3. `get_module_summary`

Devuelve los doc-comentarios de módulo y un resumen de la API pública.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al archivo fuente |

**Almacenado en caché:** Sí

---

### 4. `inspect_symbol`

Devuelve el código fuente sanitizado de una función, struct, enum o método específicos.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al archivo fuente |
| `symbol_name` | string | ✅ | Nombre del símbolo |
| `match_mode` | string | No | `exact` (por defecto), `prefix` o `contains` |
| `return_all_matches` | bool | No | Devolver todos los símbolos coincidentes. Por defecto: `false` |
| `signature_hint` | string | No | Pista de firma de tipo para desambiguación |

**Almacenado en caché:** Sí

---

### 5. `get_dependencies_graph`

Devuelve el gráfico de importación entre módulos con detección de ciclos de dependencia.

**Parámetros:**

| Nombre | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `mode` | string | `summary` | `summary` o `graph` |
| `scope_path` | string | *raíz* | Limitar a un subdirectorio |
| `depth` | integer | *todos* | Límite de profundidad BFS (1–5) |
| `direction` | string | `outbound` | `outbound`, `inbound` o `both` |
| `include_external` | bool | `false` | Incluir deps de bibliotecas externas |
| `max_nodes` | integer | `100` | Máximo 200 |
| `max_edges_per_node` | integer | `50` | Máximo 100 |
| `sort_by` | string | `fanout` | `fanout` o `fanin` |

**Ciclos de dependencia:** Ninguno detectado en NexusIntelliCore.

**Almacenado en caché:** Sí

---

### 6. `search_design_patterns`

Detecta patrones de diseño usando heurísticas en los archivos.

**Patrones detectados:** Factory, Builder, Observer, Repository, Singleton, Strategy

**Almacenado en caché:** Sí

---

### 7. `audit_security_measures`

Ejecuta escaneo de secretos y detección de código inseguro basada en AST en todo el proyecto.

**Parámetros:** Ninguno

**Qué detecta:**
- `secret-detection`: Claves API codificadas, tokens, credenciales, cadenas de conexión
- `rust-unsafe`: Bloques Rust inseguros
- `sql-injection-heuristic`: Concatenación de cadenas en contextos SQL

> **Importante:** Los _valores_ de los secretos NUNCA se incluyen. El informe solo muestra el _tipo_ y la _ubicación_.

**Almacenado en caché:** Sí

---

### 8. `analyze_angular_component`

Analiza un componente Angular: extrae selector, plantilla, estilos, entradas, salidas y hooks de ciclo de vida.

> Solo disponible cuando se detecta un proyecto Angular.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al archivo `.ts` del componente |

**Almacenado en caché:** Sí

---

### 9. `refresh_index`

Reconstruye el índice de archivos y vacía todas las cachés de AST y herramientas.

**Parámetros:** Ninguno | **Almacenado en caché:** No

---

### 10. `get_server_stats`

Devuelve métricas operativas del servidor: tasas de acierto de caché, contadores de invocación, tiempo de funcionamiento.

**Parámetros:** Ninguno | **Almacenado en caché:** No

---

### 11. `generate_project_docs`

Genera automáticamente documentación Markdown estructurada a partir del AST de la base de código.

**Parámetros:**

| Nombre | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `language` | string | `en` | `en`, `es` o `ca` |
| `file_offset` | integer | `0` | Desplazamiento de paginación (50 archivos por página) |

**Almacenado en caché:** Sí

---

### 12. `lint_file`

Lint híbrido: comprobaciones estructurales Tree-sitter (Nivel 1) + linters externos opcionales (Nivel 2).

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al archivo fuente |

> Nivel 2 requiere `MCP_LINT_ENABLED=true`.

**Almacenado en caché:** Sí

---

### 13. `query_ast`

Ejecuta una consulta Tree-sitter S-expression ad-hoc contra un archivo fuente.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al archivo fuente |
| `query` | string | ✅ | Patrón S-expression Tree-sitter |

**Almacenado en caché:** Sí

---

### 14. `read_config_file`

Lee de forma segura un archivo de configuración con redacción automática de secretos.

**Parámetros:**

| Nombre | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al archivo de configuración |

**Formatos soportados:** `.properties`, `.yaml`, `.yml`, `.toml`, `.env`

Los valores sensibles se reemplazan por `[REDACTED_BY_MCP]`.

**Almacenado en caché:** Sí

---

### 15. `list_projects` | 16. `register_project` | 17. `unregister_project`

Gestión de proyectos en tiempo de ejecución:

```json
{ "name": "list_projects", "arguments": {} }
{ "name": "register_project", "arguments": { "path": "/ruta/absoluta", "project_id": "alias" } }
{ "name": "unregister_project", "arguments": { "project_id": "alias" } }
```

**Almacenado en caché:** No (ninguno de los tres)

---

## Límites Operativos

| Límite | Por defecto | Configuración |
|---|---|---|
| Tiempo de espera de ejecución de herramientas | 30 segundos | `MCP_TOOL_TIMEOUT_SECS` |
| Tiempo de espera de linter externo | 10 segundos | `MCP_LINT_TIMEOUT_SECS` |
| Nodos máximos del gráfico de deps | 200 (límite) | Parámetro `max_nodes` |
| Tamaño de página de `generate_project_docs` | 50 archivos | Parámetro `file_offset` |
