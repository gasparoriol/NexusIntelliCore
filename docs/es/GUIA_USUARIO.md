# NexusIntelliCore — Guía de Usuario

Esta guía le acompaña en la configuración y el uso de cada herramienta MCP expuesta por NexusIntelliCore.

---

## Tabla de Contenidos

1. [Inicio](#1-inicio)
2. [Herramientas de Gestión de Proyectos](#2-herramientas-de-gestión-de-proyectos)
3. [Herramientas de Análisis de Código](#3-herramientas-de-análisis-de-código)
4. [Herramientas de Seguridad](#4-herramientas-de-seguridad)
5. [Herramientas de Documentación](#5-herramientas-de-documentación)
6. [Herramientas del Servidor](#6-herramientas-del-servidor)
7. [Flujos de Trabajo Comunes](#7-flujos-de-trabajo-comunes)

---

## 1. Inicio

Todas las herramientas se comunican via **JSON-RPC 2.0** sobre **MCP stdio framing**. Las herramientas se invocan usando el método `tools/call`.

### Forma Básica de Solicitud

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "<nombre_herramienta>",
    "arguments": { }
  }
}
```

### Listar Herramientas Disponibles

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

---

## 2. Herramientas de Gestión de Proyectos

### `list_projects` — Listar Proyectos

```json
{ "name": "list_projects", "arguments": {} }
```

### `register_project` — Registrar Proyecto

```json
{
  "name": "register_project",
  "arguments": {
    "path": "/ruta/al/nuevo/proyecto",
    "project_id": "mi-proyecto"
  }
}
```

| Parámetro | Obligatorio | Descripción |
|---|---|---|
| `path` | ✅ | Ruta absoluta al directorio raíz del proyecto |
| `project_id` | ❌ | Alias opcional. Por defecto: nombre del directorio. |

### `unregister_project` — Dar de Baja Proyecto

```json
{
  "name": "unregister_project",
  "arguments": { "project_id": "mi-proyecto" }
}
```

### `get_project_structure` — Estructura del Proyecto

```json
{
  "name": "get_project_structure",
  "arguments": { "project": "NexusIntelliCore" }
}
```

---

## 3. Herramientas de Análisis de Código

### `get_file_outline` — Esquema de Archivo

Devuelve el mapa estructural de un archivo fuente: importaciones, tipos, firmas de funciones y doc-comentarios.

```json
{
  "name": "get_file_outline",
  "arguments": { "file_path": "src/server.rs" }
}
```

> **Consejo:** Los archivos de configuración (`.env`, `.yaml`, `.toml`) se redactan automáticamente.

### `get_module_summary` — Resumen de Módulo

```json
{
  "name": "get_module_summary",
  "arguments": { "file_path": "src/privacy_gateway.rs" }
}
```

### `inspect_symbol` — Inspección de Símbolo

Devuelve el código fuente sanitizado de una función, struct o método específicos.

```json
{
  "name": "inspect_symbol",
  "arguments": {
    "file_path": "src/security.rs",
    "symbol_name": "constant_time_compare",
    "match_mode": "exact"
  }
}
```

| Parámetro | Descripción |
|---|---|
| `match_mode` | `exact` (por defecto), `prefix` o `contains` |
| `return_all_matches` | Devolver todos los símbolos coincidentes (`false` por defecto) |
| `signature_hint` | Pista para desambiguación |

### `get_dependencies_graph` — Gráfico de Dependencias

```json
{
  "name": "get_dependencies_graph",
  "arguments": {
    "mode": "summary",
    "scope_path": "src/tools",
    "depth": 2,
    "direction": "outbound",
    "max_nodes": 100
  }
}
```

### `search_design_patterns` — Patrones de Diseño

```json
{
  "name": "search_design_patterns",
  "arguments": { "scope_path": "src" }
}
```

**Patrones detectados:** Factory, Builder, Observer, Repository, Singleton, Strategy

### `lint_file` — Lint de Archivo

```json
{
  "name": "lint_file",
  "arguments": { "file_path": "src/main.rs" }
}
```

- **Nivel 1** (siempre activo): Comprobaciones estructurales Tree-sitter
- **Nivel 2** (opt-in via `MCP_LINT_ENABLED=true`): Linters externos

### `query_ast` — Consulta AST

```json
{
  "name": "query_ast",
  "arguments": {
    "file_path": "src/security.rs",
    "query": "(function_item name: (identifier) @fn_name)"
  }
}
```

### `read_config_file` — Leer Archivo de Configuración

```json
{
  "name": "read_config_file",
  "arguments": { "file_path": "config/app.yaml" }
}
```

Formatos soportados: `.properties`, `.yaml`, `.yml`, `.toml`, `.env`

### `analyze_angular_component` — Componente Angular

```json
{
  "name": "analyze_angular_component",
  "arguments": { "file_path": "src/app/hero/hero.component.ts" }
}
```

> Solo disponible para proyectos Angular.

---

## 4. Herramientas de Seguridad

### `audit_security_measures` — Auditoría de Seguridad

Ejecuta una auditoría de seguridad completa: escaneo de secretos y detección de código inseguro basada en AST.

```json
{
  "name": "audit_security_measures",
  "arguments": {}
}
```

**Detecta:**
- Claves API codificadas (OpenAI, AWS, GitHub, JWT, PEM)
- Cadenas de conexión a bases de datos
- IPs privadas y nombres de host internos
- Bloques Rust inseguros
- Heurísticas de inyección SQL

> **Importante:** Los _valores_ de los secretos NUNCA se incluyen. Solo se reporta el _tipo_ y la _ubicación_.

---

## 5. Herramientas de Documentación

### `generate_project_docs` — Generar Documentación

```json
{
  "name": "generate_project_docs",
  "arguments": {
    "language": "es",
    "file_offset": 0
  }
}
```

| Parámetro | Descripción |
|---|---|
| `language` | `en` (inglés), `es` (español), `ca` (catalán) |
| `file_offset` | Paginación: 50 archivos por página |

> Si la salida indica más páginas, vuelva a llamar con `file_offset: 50`, `file_offset: 100`, etc.

---

## 6. Herramientas del Servidor

### `get_server_stats` — Estadísticas del Servidor

```json
{ "name": "get_server_stats", "arguments": {} }
```

### `refresh_index` — Actualizar Índice

Reconstruye el índice y vacía todas las cachés. Use cuando se añaden o eliminan archivos.

```json
{ "name": "refresh_index", "arguments": {} }
```

---

## 7. Flujos de Trabajo Comunes

### Entender una nueva base de código

```
1. get_project_structure        → Visión general de archivos y directorios
2. get_dependencies_graph       → Dependencias de módulos y puntos calientes
3. search_design_patterns       → Patrones arquitectónicos en uso
4. get_file_outline <archivo>   → Análisis profundo de un módulo específico
5. inspect_symbol <símbolo>     → Inspección de una función o tipo concretos
```

### Revisión de seguridad

```
1. audit_security_measures      → Escaneo completo de secretos y código
2. get_file_outline <archivo>   → Revisión de la estructura de los archivos marcados
3. inspect_symbol <fn>          → Inspección de las funciones marcadas
```

### Generar documentación en todos los idiomas

```
1. generate_project_docs (language: "en")  → Documentación en inglés
2. generate_project_docs (language: "es")  → Documentación en español
3. generate_project_docs (language: "ca")  → Documentación en catalán
```

### Análisis multi-proyecto

```
1. list_projects                             → Ver proyectos registrados
2. register_project (path: "/nueva/ruta")   → Añadir un nuevo proyecto
3. get_project_structure (project: "id")    → Analizar proyecto específico
4. unregister_project (project_id: "id")    → Limpiar cuando haya terminado
```
