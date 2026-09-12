# NexusIntelliCore — Arquitectura Técnica

Este documento describe la arquitectura interna de NexusIntelliCore para colaboradores e integradores.

---

## Visión General del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│               Servidor MCP NexusIntelliCore                     │
├─────────────────────────────────────────────────────────────────┤
│  Capa de Transporte  (transport.rs)                             │
│  MCP stdio framing — cabeceras Content-Length                   │
│  + modo JSON delimitado por líneas de compatibilidad            │
├─────────────────────────────────────────────────────────────────┤
│  Capa de Protocolo y Auth  (server.rs + security.rs)            │
│  Enrutamiento JSON-RPC 2.0 · initialize · tools/list            │
│  Hashing de token (S2) · Limitación de velocidad (S3)           │
│  Comparación de tiempo constante (S1)                           │
├─────────────────────────────────────────────────────────────────┤
│  Controladores de Herramientas  (src/tools/)                    │
│  17 herramientas registradas — detección Angular dinámica       │
│  Caché de Consultas de Herramientas (moka::future::Cache)       │
├─────────────────────────────────────────────────────────────────┤
│  Privacy Gateway  (privacy_gateway.rs + sanitizer.rs)           │
│  Redacción de secretos multicapa · anotaciones @mcp-strip       │
│  Enmascaramiento de infraestructura · Eliminación de comentarios│
├─────────────────────────────────────────────────────────────────┤
│  Motor de Análisis Principal                                    │
│  Analyzer (AST) · Indexer · Watcher · Relations                 │
│  State (caché moka + aislamiento RwLock por proyecto)           │
├─────────────────────────────────────────────────────────────────┤
│  Analizadores Tree-sitter (11 idiomas)                          │
│  Rust · Java · TS/JS · Python · C · C# · Go · Kotlin · CSS · HTML│
└─────────────────────────────────────────────────────────────────┘
```

---

## Estructura del Código Fuente

```
src/
├── main.rs                  # Punto de entrada — args CLI, runtime Tokio
├── server.rs                # Bucle del servidor MCP — enrutamiento JSON-RPC
├── transport.rs             # Framing MCP stdio (Content-Length)
├── protocol.rs              # Tipos JSON-RPC 2.0: JsonRpcRequest, JsonRpcResponse
├── security.rs              # Auth: hashing de token, comparación tiempo constante
├── privacy_gateway.rs       # Privacy Gateway central — puerta para toda E/S
├── sanitizer.rs             # Motor de redacción de secretos basado en patrones
├── indexer.rs               # Descubrimiento de archivos con soporte glob/gitignore
├── watcher.rs               # Observador del sistema de archivos — invalidación de caché
├── relations.rs             # Resolución de relaciones de componentes Angular
├── audit_queries.rs         # Definiciones de consultas de auditoría de seguridad basadas en AST
├── analyzer/                # Motor de análisis AST (Tree-sitter)
│   ├── mod.rs               # analyze_file() — punto de entrada principal
│   ├── imports.rs           # Clasificación de importaciones
│   ├── functions.rs         # Extracción de funciones
│   └── types.rs             # Extracción de tipos/struct/enum
├── linter/
│   ├── level1.rs            # Linter estructural Tree-sitter
│   └── level2.rs            # Puente de linter externo (cargo clippy, eslint, mypy)
├── state/
│   ├── mod.rs               # ServerState — caché global compartida (moka)
│   └── project.rs           # ProjectContext — estado aislado por proyecto
└── tools/                   # Dispatcher de herramientas + todos los controladores
    ├── definitions.rs       # Registro de esquemas de herramientas (contrato API normativo)
    └── ...                  # Un archivo/directorio por herramienta
```

---

## Análisis Profundo de los Módulos

### Capa de Transporte (`transport.rs`)

- Lee cabeceras `Content-Length` de stdin para un análisis de marcos adecuado
- Recurre a JSON delimitado por líneas para compatibilidad con clientes antiguos
- `TransportLimits` — fuente única de verdad para todas las restricciones de framing
- Utiliza `BufReader<R>` para E/S con buffer eficiente via `McpTransport`

### Protocolo y Autenticación (`server.rs` + `security.rs`)

El handshake MCP `initialize` realiza la autenticación si `MCP_AUTH_TOKEN` está establecido:

1. El cliente proporciona `MCP_AUTH_TOKEN` en los parámetros de inicialización
2. El servidor hashea el token proporcionado usando `compute_token_digest()` (digest SHA-256 de 32 bytes)
3. La comparación utiliza `constant_time_compare_hashes()` — tiempo fijo, sin fuga de longitud **(S1)**
4. El token en bruto se descarta de la memoria inmediatamente después del hash **(S2)**
5. Los intentos fallidos activan `AUTH_FAILURE_COUNT` con backoff exponencial (250ms → 2s) **(S3)**

El registro de auditoría a prueba de manipulación **(S4)** escribe NDJSON append-only con hashes encadenados cuando `MCP_AUDIT_LOG_PATH` está establecido.

### Privacy Gateway (`privacy_gateway.rs` + `sanitizer.rs`)

Todas las salidas de las herramientas pasan por la Privacy Gateway.

**Pipeline de sanitización:**
```
Salida bruta de la herramienta
  → strip_sensitive_comments()  — eliminar anotaciones @mcp-strip
  → detect_all_secrets()        — identificar patrones de secretos
  → sanitize_text()             — reemplazar secretos por [REDACTED_BY_MCP]
  → enmascaramiento infraestructura — redactar hostnames e IPs privadas
  → sanitize_config_text()      — para lecturas de archivos de configuración
  → Salida de la Privacy Gateway
```

**Tipos de secretos detectados:** `OPENAI_KEY`, `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `JWT_TOKEN`, `DB_CONNECTION_URI`, `PEM_PRIVATE_KEY`, `PRIVATE_IP`, `INTERNAL_HOSTNAME`, `GENERIC_SECRET`

### Gestión de Estado (`state/`)

**Modelo de aislamiento de dos niveles:**

| Nivel | Tipo | Ámbito |
|---|---|---|
| `ServerState` | Global compartido | Caché AST + caché de consultas de herramientas (`moka`) |
| `ProjectContext` | Aislado por proyecto | `FileIndex`, `TsPathAliasConfig`, `LintPool`, `FileWatcher` |

Todos los accesos `RwLock`/`Mutex` usan recuperación de errores de veneno — el servidor nunca se bloquea si un hilo de trabajo falla.

### Caché de Consultas de Herramientas (`moka::future::Cache`)

Las herramientas deterministas almacenan en caché sus salidas finales:

- **Clave de caché:** `(nombre_herramienta, ruta_archivo, hash_args)`
- **Invalidación de caché:** El observador de archivos activa la invalidación en modificación/creación/eliminación
- **Vaciado manual:** La herramienta `refresh_index` vacía todas las cachés

### Observador de Archivos (`watcher.rs`)

Utiliza `notify::RecommendedWatcher` (FSEvents en macOS, inotify en Linux):
- **Cambio de contenido** → invalida la entrada de caché AST para ese archivo
- **Creación/Eliminación/Renombrado** → solicita una actualización de índice con debouncing

### Motor de Análisis (`analyzer/`)

Punto de entrada: `analyze_file(path: &Path) -> Result<FileAnalysis>`

**Flujo de análisis:**
```
Ruta del archivo
  → detect_language()  — heurísticas de extensión + contenido
  → Analizador Tree-sitter — gramática específica del idioma
  → Recorrido AST     — extraer importaciones, funciones, tipos
  → audit_file_ast()  — ejecutar comprobaciones de seguridad contra AST
  → Resultado FileAnalysis
```

**Idiomas soportados:** Rust, Java, TypeScript, JavaScript, Python, C, C#, Go, Kotlin, CSS, HTML

---

## Modelo de Concurrencia

- **Runtime asíncrono:** Tokio — todos los controladores de herramientas son `async fn`
- **Estado compartido:** `Arc<RwLock<ServerState>>` — múltiples lecturas concurrentes, escrituras exclusivas
- **Aislamiento por proyecto:** Cada `ProjectContext` tiene su propio `Arc<RwLock<FileIndex>>`
- **Sin estado mutable global** — diseño funcional, dependencias explícitas via parámetros

---

## Patrones de Diseño Detectados

| Patrón | Ubicación | Evidencia |
|---|---|---|
| Factory | `src/analyzer/tests.rs` | 4 métodos `create_*/make_*/new_*()` |
| Factory | `src/state/mod.rs` | 2 métodos `create_*/make_*/new_*()` |
| Factory | `src/watcher.rs` | 2 métodos `create_*/make_*/new_*()` |

---

## Gráfico de Dependencias (Puntos Calientes Principales)

Todos los controladores de herramientas dependen de la Privacy Gateway como punto central de sanitización:

```
src/tools/audit.rs        → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/outline.rs      → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/symbol.rs       → src/privacy_gateway.rs, src/sanitizer.rs
src/tools/angular.rs      → src/privacy_gateway.rs
src/tools/deps_graph/     → src/privacy_gateway.rs
src/tools/lint.rs         → src/privacy_gateway.rs
src/tools/patterns.rs     → src/privacy_gateway.rs
```

**Sin dependencias circulares detectadas.**

---

## Extensión de NexusIntelliCore

### Añadir una Nueva Herramienta

1. Crear `src/tools/nuevaherramienta.rs` — implementar el controlador `async fn`
2. Registrar el esquema de la herramienta en `src/tools/definitions.rs`
3. Añadir la entrada de dispatch en `src/tools/mod.rs`
4. Actualizar `tests/api_docs_consistency.rs`
5. Añadir pruebas de integración

### Añadir un Nuevo Idioma

1. Añadir la crate de gramática Tree-sitter a `Cargo.toml`
2. Registrar el analizador del idioma en `src/analyzer/mod.rs`
3. Añadir reglas de extracción específicas del idioma
4. Añadir fixtures de prueba en `tests/fixtures/`
5. Actualizar la detección de idiomas en `detect_language()`
