# NexusIntelliCore — Arquitectura Tècnica

Aquest document descriu l'arquitectura interna de NexusIntelliCore per a col·laboradors i integradors.

---

## Visió General del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│               Servidor MCP NexusIntelliCore                     │
├─────────────────────────────────────────────────────────────────┤
│  Capa de Transport  (transport.rs)                              │
│  MCP stdio framing — capçaleres Content-Length                  │
│  + mode JSON delimitat per línies de compatibilitat             │
├─────────────────────────────────────────────────────────────────┤
│  Capa de Protocol i Auth  (server.rs + security.rs)             │
│  Enrutament JSON-RPC 2.0 · initialize · tools/list              │
│  Hashing de token (S2) · Limitació de velocitat (S3)            │
│  Comparació de temps constant (S1)                              │
├─────────────────────────────────────────────────────────────────┤
│  Controladors d'Eines  (src/tools/)                             │
│  17 eines registrades — detecció Angular dinàmica               │
│  Memòria Cau de Consultes d'Eines (moka::future::Cache)         │
├─────────────────────────────────────────────────────────────────┤
│  Privacy Gateway  (privacy_gateway.rs + sanitizer.rs)           │
│  Redacció de secrets multicapa · anotacions @mcp-strip          │
│  Emmascara d'infraestructura · Eliminació de comentaris sensibles│
├─────────────────────────────────────────────────────────────────┤
│  Motor d'Anàlisi Principal                                      │
│  Analyzer (AST) · Indexer · Watcher · Relations                 │
│  State (memòria cau moka + aïllament RwLock per projecte)       │
├─────────────────────────────────────────────────────────────────┤
│  Analitzadors Tree-sitter (11 idiomes)                          │
│  Rust · Java · TS/JS · Python · C · C# · Go · Kotlin · CSS · HTML│
└─────────────────────────────────────────────────────────────────┘
```

---

## Estructura de Codi Font

```
src/
├── main.rs                  # Punt d'entrada — args CLI, runtime Tokio
├── server.rs                # Bucle del servidor MCP — enrutament JSON-RPC
├── transport.rs             # Framing MCP stdio (Content-Length)
├── protocol.rs              # Tipus JSON-RPC 2.0: JsonRpcRequest, JsonRpcResponse
├── security.rs              # Auth: hashing de token, comparació de temps constant
├── privacy_gateway.rs       # Privacy Gateway central — porta per a tota E/S
├── sanitizer.rs             # Motor de redacció de secrets basat en patrons
├── indexer.rs               # Descobriment de fitxers amb suport glob/gitignore
├── watcher.rs               # Observador del sistema de fitxers — invalidació de memòria cau
├── relations.rs             # Resolució de relacions de components Angular
├── audit_queries.rs         # Definicions de consultes d'auditoria de seguretat basades en AST
├── analyzer/                # Motor d'anàlisi AST (Tree-sitter)
│   ├── mod.rs               # analyze_file() — punt d'entrada principal
│   ├── imports.rs           # Classificació d'importacions
│   ├── functions.rs         # Extracció de funcions
│   └── types.rs             # Extracció de tipus/struct/enum
├── linter/
│   ├── level1.rs            # Linter estructural Tree-sitter
│   └── level2.rs            # Pont de linter extern (cargo clippy, eslint, mypy)
├── state/
│   ├── mod.rs               # ServerState — memòria cau global compartida (moka)
│   └── project.rs           # ProjectContext — estat aïllat per projecte
└── tools/                   # Dispatcher d'eines + tots els controladors
    ├── definitions.rs       # Registre d'esquemes d'eines (contracte API normatiu)
    └── ...                  # Un fitxer/directori per eina
```

---

## Anàlisi Profunda dels Mòduls

### Capa de Transport (`transport.rs`)

- Llegeix capçaleres `Content-Length` de stdin per a un anàlisi de marcs adequat
- Recau en JSON delimitat per línies per a compatibilitat amb clients antics
- `TransportLimits` — font única de veritat per a totes les restriccions de framing
- Utilitza `BufReader<R>` per a E/S amb buffer eficient via `McpTransport`

### Protocol i Autenticació (`server.rs` + `security.rs`)

El handshake MCP `initialize` realitza l'autenticació si `MCP_AUTH_TOKEN` està establert:

1. El client proporciona `MCP_AUTH_TOKEN` als paràmetres d'inicialització
2. El servidor fa hash del token proporcionat usant `compute_token_digest()` (digest SHA-256 de 32 bytes)
3. La comparació utilitza `constant_time_compare_hashes()` — temps fix, sense fuita de longitud **(S1)**
4. El token en brut es descarta de la memòria immediatament després del hash **(S2)**
5. Els intents fallits activen `AUTH_FAILURE_COUNT` amb backoff exponencial (250ms → 2s) **(S3)**

El registre d'auditoria a prova de manipulació **(S4)** escriu NDJSON append-only amb hashes encadenats quan `MCP_AUDIT_LOG_PATH` està establert.

### Privacy Gateway (`privacy_gateway.rs` + `sanitizer.rs`)

Totes les sortides de les eines passen per la Privacy Gateway.

**Pipeline de sanitització:**
```
Sortida bruta de l'eina
  → strip_sensitive_comments()  — eliminar anotacions @mcp-strip
  → detect_all_secrets()        — identificar patrons de secrets
  → sanitize_text()             — substituir secrets per [REDACTED_BY_MCP]
  → emmascara d'infraestructura — redactar noms d'amfitrió i IPs privades
  → sanitize_config_text()      — per a lectures de fitxers de configuració
  → Sortida de la Privacy Gateway
```

**Tipus de secrets detectats:** `OPENAI_KEY`, `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `JWT_TOKEN`, `DB_CONNECTION_URI`, `PEM_PRIVATE_KEY`, `PRIVATE_IP`, `INTERNAL_HOSTNAME`, `GENERIC_SECRET`

### Gestió d'Estat (`state/`)

**Model d'aïllament de dos nivells:**

| Nivell | Tipus | Àmbit |
|---|---|---|
| `ServerState` | Global compartit | Memòria cau AST + memòria cau de consultes d'eines (`moka`) |
| `ProjectContext` | Aïllat per projecte | `FileIndex`, `TsPathAliasConfig`, `LintPool`, `FileWatcher` |

Tots els accessos `RwLock`/`Mutex` usen recuperació d'errors de verí — el servidor no s'enfonsa mai si un fil de treball falla.

### Memòria Cau de Consultes d'Eines (`moka::future::Cache`)

Les eines deterministes emmagatzemen en memòria cau les seves sortides finals:

- **Clau de memòria cau:** `(nom_eina, ruta_fitxer, hash_args)`
- **Invalidació de memòria cau:** L'observador de fitxers activa la invalidació en modificació/creació/eliminació
- **Buidat manual:** L'eina `refresh_index` buida totes les memòries cau

### Observador de Fitxers (`watcher.rs`)

Utilitza `notify::RecommendedWatcher` (FSEvents a macOS, inotify a Linux):
- **Canvi de contingut** → invalida l'entrada de memòria cau AST per a aquell fitxer
- **Creació/Eliminació/Reanomenament** → sol·licita una actualització d'índex amb debouncing

### Motor d'Anàlisi (`analyzer/`)

Punt d'entrada: `analyze_file(path: &Path) -> Result<FileAnalysis>`

**Flux d'anàlisi:**
```
Ruta del fitxer
  → detect_language()   — heurístiques d'extensió + contingut
  → Analitzador Tree-sitter — gramàtica específica de l'idioma
  → Recorregut AST     — extreure importacions, funcions, tipus
  → audit_file_ast()   — executar comprovacions de seguretat contra AST
  → Resultat FileAnalysis
```

**Idiomes suportats:** Rust, Java, TypeScript, JavaScript, Python, C, C#, Go, Kotlin, CSS, HTML

---

## Model de Concurrència

- **Runtime asíncron:** Tokio — tots els controladors d'eines són `async fn`
- **Estat compartit:** `Arc<RwLock<ServerState>>` — múltiples lectures concurrents, escriptures exclusives
- **Aïllament per projecte:** Cada `ProjectContext` té el seu propi `Arc<RwLock<FileIndex>>`
- **Sense estat mutable global** — disseny funcional, dependències explícites via paràmetres

---

## Patrons de Disseny Detectats

| Patró | Ubicació | Evidència |
|---|---|---|
| Factory | `src/analyzer/tests.rs` | 4 mètodes `create_*/make_*/new_*()` |
| Factory | `src/state/mod.rs` | 2 mètodes `create_*/make_*/new_*()` |
| Factory | `src/watcher.rs` | 2 mètodes `create_*/make_*/new_*()` |

---

## Gràfic de Dependències (Punts Calents Principals)

Tots els controladors d'eines depenen de la Privacy Gateway com a punt central de sanitització:

```
src/tools/audit.rs        → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/outline.rs      → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/symbol.rs       → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/angular.rs      → src/privacy_gateway.rs
src/tools/deps_graph/     → src/privacy_gateway.rs
src/tools/lint.rs         → src/privacy_gateway.rs
src/tools/patterns.rs     → src/privacy_gateway.rs
```

**Cap dependència circular detectada.**

---

## Extensió de NexusIntelliCore

### Afegir una Nova Eina

1. Crear `src/tools/novaeina.rs` — implementar el controlador `async fn`
2. Registrar l'esquema de l'eina a `src/tools/definitions.rs`
3. Afegir l'entrada de dispatch a `src/tools/mod.rs`
4. Actualitzar `tests/api_docs_consistency.rs`
5. Afegir proves d'integració

### Afegir un Nou Idioma

1. Afegir la caixa de gramàtica Tree-sitter a `Cargo.toml`
2. Registrar l'analitzador de l'idioma a `src/analyzer/mod.rs`
3. Afegir regles d'extracció específiques de l'idioma
4. Afegir fixtures de proves a `tests/fixtures/`
5. Actualitzar la detecció d'idiomes a `detect_language()`
