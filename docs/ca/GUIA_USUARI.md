# NexusIntelliCore — Guia d'Usuari

Aquesta guia us guia per la configuració i l'ús de cada eina MCP exposada per NexusIntelliCore.

---

## Taula de Continguts

1. [Inici](#1-inici)
2. [Eines de Gestió de Projectes](#2-eines-de-gestió-de-projectes)
3. [Eines d'Anàlisi de Codi](#3-eines-danàlisi-de-codi)
4. [Eines de Seguretat](#4-eines-de-seguretat)
5. [Eines de Documentació](#5-eines-de-documentació)
6. [Eines del Servidor](#6-eines-del-servidor)
7. [Fluxos de Treball Comuns](#7-fluxos-de-treball-comuns)

---

## 1. Inici

Totes les eines es comuniquen via **JSON-RPC 2.0** sobre **MCP stdio framing**. Les eines s'invoquen usant el mètode `tools/call`.

### Forma Bàsica de Sol·licitud

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "<nom_eina>",
    "arguments": { }
  }
}
```

### Llistar Eines Disponibles

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

---

## 2. Eines de Gestió de Projectes

### `list_projects` — Llistar Projectes

```json
{ "name": "list_projects", "arguments": {} }
```

### `register_project` — Registrar Projecte

```json
{
  "name": "register_project",
  "arguments": {
    "path": "/ruta/al/nou/projecte",
    "project_id": "el-meu-projecte"
  }
}
```

| Paràmetre | Obligatori | Descripció |
|---|---|---|
| `path` | ✅ | Ruta absoluta al directori arrel del projecte |
| `project_id` | ❌ | Àlies opcional. Per defecte: nom del directori. |

### `unregister_project` — Donar de Baixa Projecte

```json
{
  "name": "unregister_project",
  "arguments": { "project_id": "el-meu-projecte" }
}
```

### `get_project_structure` — Estructura del Projecte

```json
{
  "name": "get_project_structure",
  "arguments": { "project": "NexusIntelliCore" }
}
```

---

## 3. Eines d'Anàlisi de Codi

### `get_file_outline` — Esquema de Fitxer

Retorna el mapa estructural d'un fitxer font: importacions, tipus, signatures de funcions i doc-comentaris.

```json
{
  "name": "get_file_outline",
  "arguments": { "file_path": "src/server.rs" }
}
```

> **Consell:** Els fitxers de configuració (`.env`, `.yaml`, `.toml`) es redacten automàticament.

### `get_module_summary` — Resum de Mòdul

```json
{
  "name": "get_module_summary",
  "arguments": { "file_path": "src/privacy_gateway.rs" }
}
```

### `inspect_symbol` — Inspecció de Símbol

Retorna el codi font netejat d'una funció, struct o mètode específics.

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

| Paràmetre | Descripció |
|---|---|
| `match_mode` | `exact` (per defecte), `prefix` o `contains` |
| `return_all_matches` | Retornar tots els símbols coincidents (`false` per defecte) |
| `signature_hint` | Pista per a desambiguació |

### `get_dependencies_graph` — Gràfic de Dependències

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

### `search_design_patterns` — Patrons de Disseny

```json
{
  "name": "search_design_patterns",
  "arguments": { "scope_path": "src" }
}
```

**Patrons detectats:** Factory, Builder, Observer, Repository, Singleton, Strategy

### `lint_file` — Lint de Fitxer

```json
{
  "name": "lint_file",
  "arguments": { "file_path": "src/main.rs" }
}
```

- **Nivell 1** (sempre actiu): Comprovacions estructurals Tree-sitter
- **Nivell 2** (opt-in via `MCP_LINT_ENABLED=true`): Linters externs

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

### `read_config_file` — Llegir Fitxer de Configuració

```json
{
  "name": "read_config_file",
  "arguments": { "file_path": "config/app.yaml" }
}
```

Formats suportats: `.properties`, `.yaml`, `.yml`, `.toml`, `.env`

### `analyze_angular_component` — Component Angular

```json
{
  "name": "analyze_angular_component",
  "arguments": { "file_path": "src/app/hero/hero.component.ts" }
}
```

> Disponible únicament per a projectes Angular.

---

## 4. Eines de Seguretat

### `audit_security_measures` — Auditoria de Seguretat

Executa una auditoria de seguretat completa: escaneig de secrets i detecció de codi insegur basada en AST.

```json
{
  "name": "audit_security_measures",
  "arguments": {}
}
```

**Detecta:**
- Claus API codificades (OpenAI, AWS, GitHub, JWT, PEM)
- Cadenes de connexió a bases de dades
- IPs privades i noms d'amfitrió interns
- Blocs Rust insegurs
- Heurístiques d'injecció SQL

> **Important:** Els _valors_ dels secrets NO s'inclouen mai. Només es reporta el _tipus_ i la _ubicació_.

---

## 5. Eines de Documentació

### `generate_project_docs` — Generar Documentació

```json
{
  "name": "generate_project_docs",
  "arguments": {
    "language": "ca",
    "file_offset": 0
  }
}
```

| Paràmetre | Descripció |
|---|---|
| `language` | `en` (anglès), `es` (castellà), `ca` (català) |
| `file_offset` | Paginació: 50 fitxers per pàgina |

> Si la sortida indica més pàgines, torneu a cridar amb `file_offset: 50`, `file_offset: 100`, etc.

---

## 6. Eines del Servidor

### `get_server_stats` — Estadístiques del Servidor

```json
{ "name": "get_server_stats", "arguments": {} }
```

### `refresh_index` — Actualitzar Índex

Reconstrueix l'índex i buida totes les memòries cau. Useu quan s'afegeixen o eliminen fitxers.

```json
{ "name": "refresh_index", "arguments": {} }
```

---

## 7. Fluxos de Treball Comuns

### Entendre una nova base de codi

```
1. get_project_structure        → Visió general de fitxers i directoris
2. get_dependencies_graph       → Dependències de mòduls i punts calents
3. search_design_patterns       → Patrons arquitectònics en ús
4. get_file_outline <fitxer>    → Anàlisi profunda d'un mòdul específic
5. inspect_symbol <símbol>      → Inspecció d'una funció o tipus concrets
```

### Revisió de seguretat

```
1. audit_security_measures      → Escaneig complet de secrets i codi
2. get_file_outline <fitxer>    → Revisió de l'estructura dels fitxers marcats
3. inspect_symbol <fn>          → Inspecció de les funcions marcades
```

### Generar documentació en tots els idiomes

```
1. generate_project_docs (language: "en")  → Documentació en anglès
2. generate_project_docs (language: "es")  → Documentació en castellà
3. generate_project_docs (language: "ca")  → Documentació en català
```

### Anàlisi multi-projecte

```
1. list_projects                            → Veure projectes registrats
2. register_project (path: "/nova/ruta")   → Afegir un nou projecte
3. get_project_structure (project: "id")   → Analitzar projecte específic
4. unregister_project (project_id: "id")   → Netejar quan hagueu acabat
```
