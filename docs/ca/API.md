# NexusIntelliCore — Referència Completa de l'API MCP

> **Vigent a partir de:** v0.9.0 (2026-09-12). Aquest document és la font normativa del contracte MCP. Ha de coincidir amb `src/tools/definitions.rs`.

---

## Protocol MCP

NexusIntelliCore es comunica via **JSON-RPC 2.0** sobre **MCP stdio framing** (capçaleres `Content-Length`). El mode JSON delimitat per línies també és compatible.

### Mètodes de Protocol Suportats

| Mètode | Descripció |
|---|---|
| `initialize` | Handshake MCP (autenticació si `MCP_AUTH_TOKEN` està configurat) |
| `notifications/initialized` | Notificació — no s'espera resposta |
| `tools/list` | Descobrir les eines disponibles |
| `tools/call` | Invocar una eina |
| `ping` | Comprovació de disponibilitat del servidor |

### Format de Sol·licitud

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "nom_eina",
    "arguments": { "param": "valor" }
  }
}
```

### Format de Resposta Correcta

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{ "type": "text", "text": "Sortida..." }],
    "isError": false
  }
}
```

### Codis d'Error

| Codi | Missatge | Significat |
|---|---|---|
| `-32700` | Parse Error | JSON invàlid rebut |
| `-32600` | Invalid Request | Format de sol·licitud invàlid |
| `-32601` | Method Not Found | Nom d'eina o mètode desconegut |
| `-32602` | Invalid Params | Paràmetres no coincideixen amb l'esquema esperat |
| `-32603` | Internal Error | Error del servidor durant el processament |

---

## Referència d'Eines

### 1. `get_project_structure`

Retorna un arbre de directoris compacte amb marcadors de control d'accés.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `project` | string | No | ID o àlies de projecte. Per defecte: primer projecte registrat. |

**Emmagatzemat en memòria cau:** No

---

### 2. `get_file_outline`

Retorna el mapa estructural d'un fitxer: importacions, tipus, signatures de funcions i doc-comentaris.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta relativa o absoluta al fitxer font |

**Emmagatzemat en memòria cau:** Sí

---

### 3. `get_module_summary`

Retorna els doc-comentaris de mòdul i un resum de l'API pública.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al fitxer font |

**Emmagatzemat en memòria cau:** Sí

---

### 4. `inspect_symbol`

Retorna el codi font netejat d'una funció, struct, enum o mètode específics.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al fitxer font |
| `symbol_name` | string | ✅ | Nom del símbol |
| `match_mode` | string | No | `exact` (per defecte), `prefix` o `contains` |
| `return_all_matches` | bool | No | Retornar tots els símbols coincidents. Per defecte: `false` |
| `signature_hint` | string | No | Pista de signatura de tipus per a desambiguació |

**Emmagatzemat en memòria cau:** Sí

---

### 5. `get_dependencies_graph`

Retorna el gràfic d'importació entre mòduls amb detecció de cicles de dependència.

**Paràmetres:**

| Nom | Tipus | Per defecte | Descripció |
|---|---|---|---|
| `mode` | string | `summary` | `summary` o `graph` |
| `scope_path` | string | *arrel* | Limitar a un subdirectori |
| `depth` | integer | *tots* | Límit de profunditat BFS (1–5) |
| `direction` | string | `outbound` | `outbound`, `inbound` o `both` |
| `include_external` | bool | `false` | Incloure deps de biblioteques externes |
| `max_nodes` | integer | `100` | Màxim 200 |
| `max_edges_per_node` | integer | `50` | Màxim 100 |
| `sort_by` | string | `fanout` | `fanout` o `fanin` |

**Cicles de dependència:** Cap detectat en NexusIntelliCore.

**Emmagatzemat en memòria cau:** Sí

---

### 6. `search_design_patterns`

Detecta patrons de disseny usant heurístiques en els fitxers.

**Paràmetres:**

| Nom | Tipus | Descripció |
|---|---|---|
| `scope_path` | string | Limitar a un subdirectori |
| `file_path` | string | Limitar a un fitxer específic |

**Patrons detectats:** Factory, Builder, Observer, Repository, Singleton, Strategy

**Emmagatzemat en memòria cau:** Sí

---

### 7. `audit_security_measures`

Executa escaneig de secrets i detecció de codi insegur basada en AST en tot el projecte.

**Paràmetres:** Cap

**Què detecta:**
- `secret-detection`: Claus API codificades, tokens, credencials, cadenes de connexió
- `rust-unsafe`: Blocs Rust insegurs
- `sql-injection-heuristic`: Concatenació de cadenes en contextos SQL

> **Important:** Els _valors_ dels secrets NEVER s'inclouen. L'informe només mostra el _tipus_ i la _ubicació_.

**Emmagatzemat en memòria cau:** Sí

---

### 8. `analyze_angular_component`

Analitza un component Angular: extreu selector, plantilla, estils, entrades, sortides i cicles de vida.

> Disponible únicament quan es detecta un projecte Angular.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al fitxer `.ts` del component |

**Emmagatzemat en memòria cau:** Sí

---

### 9. `refresh_index`

Reconstrueix l'índex de fitxers i buida totes les memòries cau d'AST i eines.

**Paràmetres:** Cap | **Emmagatzemat en memòria cau:** No

---

### 10. `get_server_stats`

Retorna mètriques operatives del servidor: taxes d'èxit de memòria cau, comptadors d'invocació, temps de funcionament.

**Paràmetres:** Cap | **Emmagatzemat en memòria cau:** No

---

### 11. `generate_project_docs`

Genera automàticament documentació Markdown estructurada a partir de l'AST de la base de codi.

**Paràmetres:**

| Nom | Tipus | Per defecte | Descripció |
|---|---|---|---|
| `language` | string | `en` | `en`, `es` o `ca` |
| `file_offset` | integer | `0` | Desplaçament de paginació (50 fitxers per pàgina) |

**Emmagatzemat en memòria cau:** Sí

---

### 12. `lint_file`

Lint híbrid: comprovacions estructurals Tree-sitter (Nivell 1) + linters externs opcionals (Nivell 2).

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al fitxer font |

> Nivell 2 requereix `MCP_LINT_ENABLED=true`.

**Emmagatzemat en memòria cau:** Sí

---

### 13. `query_ast`

Executa una consulta Tree-sitter S-expression ad-hoc contra un fitxer font.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al fitxer font |
| `query` | string | ✅ | Patró S-expression Tree-sitter |

**Emmagatzemat en memòria cau:** Sí

---

### 14. `read_config_file`

Llegeix de forma segura un fitxer de configuració amb redacció automàtica de secrets.

**Paràmetres:**

| Nom | Tipus | Obligatori | Descripció |
|---|---|---|---|
| `file_path` | string | ✅ | Ruta al fitxer de configuració |

**Formats suportats:** `.properties`, `.yaml`, `.yml`, `.toml`, `.env`

Els valors sensibles es substitueixen per `[REDACTED_BY_MCP]`.

**Emmagatzemat en memòria cau:** Sí

---

### 15. `list_projects` | 16. `register_project` | 17. `unregister_project`

Gestió de projectes en temps d'execució:

```json
{ "name": "list_projects", "arguments": {} }
{ "name": "register_project", "arguments": { "path": "/ruta/absoluta", "project_id": "alias" } }
{ "name": "unregister_project", "arguments": { "project_id": "alias" } }
```

**Emmagatzemat en memòria cau:** No (cap dels tres)

---

## Límits Operatius

| Límit | Per defecte | Configuració |
|---|---|---|
| Temps d'espera d'execució d'eines | 30 segons | `MCP_TOOL_TIMEOUT_SECS` |
| Temps d'espera de linter extern | 10 segons | `MCP_LINT_TIMEOUT_SECS` |
| Nodes màxims del gràfic de deps | 200 (límit) | Paràmetre `max_nodes` |
| Mida de pàgina de `generate_project_docs` | 50 fitxers | Paràmetre `file_offset` |
