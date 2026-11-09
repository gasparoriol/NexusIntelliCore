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
Les regles són declaratives (`src/analyzer/rules/`): cadascuna té un id `<lang|any>-<cwe-slug>-<variant>`, CWE, categoria OWASP, nivell i severitat base.

- `any-hardcoded-secret` (CWE-798): Claus API codificades, tokens, credencials, cadenes de connexió
- `rust-unsafe-code-block` / `-fn` / `-asm` (CWE-676): blocs `unsafe`, `unsafe fn`, `asm!` en línia
- `rust-uncaught-panic-unwrap` (CWE-248, patró): crides `unwrap()` / `expect()`
- `js-code-injection-eval`, `js-code-injection-new-function`, `py-code-injection-eval`, `kotlin-code-injection-eval` (CWE-94/95)
- `js-xss-inner-html` (CWE-79): assignacions a `innerHTML`
- `py-command-injection-shell-true`, `java-command-injection-exec` (CWE-78)
- **Regles taint** (`<lang>-<vuln>-taint`; `lang` = `java`, `py`, `js` per a JS/TS, `rust`): flux de dades intra-procedural sobre l'AST des d'entrada d'usuari (Spring/JAX-RS/Servlet, Flask/Django/FastAPI, Express/Koa/NestJS, axum/actix, arguments CLI) fins a un sink, respectant sanititzadors i guardes de confinament:
  - `sql-injection` (CWE-89) i `command-injection` (CWE-78): els quatre llenguatges
  - `path-traversal` (CWE-22): Java, Python, JS/TS (Critical en sinks d'escriptura/esborrat)
  - `ssrf` (CWE-918) i `open-redirect` (CWE-601): els quatre llenguatges
  - `ssti` (CWE-1336) i `log-injection` (CWE-117): Java, Python, JS/TS
- `any-sql-injection-heuristic` (CWE-89): Concatenació de cadenes en contextos SQL; només en llenguatges sense regles taint SQL (Go, C#, Kotlin, C)
- **Regles de configuració i API** (`<lang>-<debilitat>`; `lang` afegeix `go`, `cs`, `c`, `kotlin`):
  - `weak-crypto-hash` (CWE-328) / `weak-crypto-cipher` (CWE-327): MD5/SHA-1, DES/3DES/RC2/RC4/Blowfish, ECB — Java, Kotlin, Python, JS/TS, Go, C#, Rust, C
  - `tls-validation-disabled` (CWE-295): `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`, trust managers que accepten tot, `danger_accept_invalid_certs(true)`… — Java, Python, JS/TS, Go, C#, Rust, C
  - `insecure-random-context` (CWE-338): `Math.random`, `java.util.Random`, `random`, `math/rand`, `rand()` només quan el nom d'una variable/funció que l'envolta és sensible (`token`, `password`, `nonce`, `session`…) — Java, Python, JS/TS, Go, C#, C
  - `insecure-deserialization` (CWE-502): `ObjectInputStream`, XStream, `pickle`, `yaml.load` insegur, `BinaryFormatter`, `TypeNameHandling.All`, `unserialize` — Java, Kotlin, Python, JS/TS, C#
  - `csrf-protection-disabled` (CWE-352), `cors-wildcard-credentials` (CWE-942), `insecure-cookie-flag` (CWE-614), `debug-mode-enabled` (CWE-489) i XXE (CWE-611: factories Java sense `disallow-doctype-decl`, lxml `resolve_entities=True`, C# `DtdProcessing.Parse`)
  - C: `c-dangerous-function-gets` (CWE-242), `c-buffer-overflow-unbounded-copy` / `c-buffer-overflow-scanf` (CWE-120), `c-format-string-variable` (CWE-134)

**Supressions:** `// nexus-ignore: <rule-id> <motiu>` a la línia de la troballa o a l'anterior. El motiu és obligatori; les troballes suprimides es llisten a l'informe, mai no s'amaguen.

**Resum JSON (`schema_version` 2):** cada entrada de `production_risk` inclou `rule_id`, `legacy_rule_id` (id de l'esquema 1, p. ex. `rust-unsafe`), `category`, `cwe`, `owasp`, `tier`, `severity`, `confidence`, `file`, `line`, `flow` (`source_line`/`sink_line` en regles taint), `fingerprint`; a més de `suppressed_total`, `suppressed` i `taint_coverage` (`intra-procedural`: no se segueixen fluxos entre funcions ni fitxers).

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
