# GuardX - Roadmap de Desarrollo

Este documento es la guia completa para seguir construyendo GuardX.
Leelo antes de empezar cualquier sesion de desarrollo con Claude Code.

## Que es GuardX

Agente de seguridad con IA que tiene 3 fases:
1. ATAQUE: escanea un target, descubre vulnerabilidades, las explota con evidencia real
2. DEFENSA: se conecta por SSH al servidor y repara cada falla con tu aprobacion
3. REPORTE: genera documento completo con hallazgos, evidencia y correcciones

## Estado actual

### Lo que YA funciona:

**Panel web profesional** (`web/app.py` + `web/templates/index.html`)
- Flask backend con Flask-SocketIO (~850 lineas)
- WebSocket en tiempo real (reemplaza polling de 800ms)
- Frontend completo con dark theme profesional (1100+ lineas)
- Socket.IO client con auto-reconexion y fallback HTTP
- Indicador de conexion WebSocket (cyan cuando conectado)
- Barra de progreso en tiempo real durante escaneos
- Sistema de autenticacion (login/logout con session-based auth)
- Chat interactivo via WebSocket (con fallback HTTP)
- Confirmaciones SSH via WebSocket (con fallback HTTP)
- Historial de escaneos con base de datos (tab dedicado)
- Descarga de reportes HTML/JSON (boton en topbar)
- Webhooks (Slack, Discord, Telegram, generic)
- 3 fases separadas con botones + sidebar de progreso
- Boton de cancelar escaneo en curso
- Tabs: Scanner, Historial, Programados, API

**Event Bus** (`guardx/core/events.py`)
- Sistema de eventos central para comunicacion en tiempo real
- Emite via SocketIO a room 'scan' + buffer interno (backward compat)
- Eventos: guardx:message, guardx:phase, guardx:tool, guardx:tool_result, guardx:finding, guardx:progress, guardx:confirm, guardx:complete
- Thread-safe con threading.Lock
- Singleton pattern con fallback graceful si SocketIO no esta disponible

**Agent loop** (`guardx/llm/client.py`)
- Soporte dual: Anthropic (tool_use nativo) + OpenRouter (function calling OpenAI)
- 18 herramientas de escaneo y explotacion
- Timeouts configurables: agent=300s, tool=90s, API=120s
- Max retries: 2 con backoff exponencial
- Retry automatico en ConnectError, TimeoutException, RemoteProtocolError, 5xx
- Tool timing: mide duracion de cada herramienta y reporta exito/fallo
- Progress tracking: contador de iteraciones por loop

**18 Herramientas de ataque** (`guardx/tools/`)
- `port_check.py` - Escaneo TCP rapido (Python sockets)
- `nmap_scan.py` - Escaneo profundo con deteccion de versiones
- `http_headers.py` - Headers de seguridad HTTP
- `nuclei_scan.py` - CVEs y misconfiguraciones
- `sql_check.py` - Deteccion SQL injection
- `ssh_exec.py` - Ejecucion remota SSH (Paramiko)
- `web_spider.py` - BFS crawler: URLs, formularios, params, hidden inputs, comments
- `dir_bruteforce.py` - Fuerza bruta de directorios async (308 rutas comunes)
- `tech_fingerprint.py` - Identificacion de stack tecnologico
- `waf_detect.py` - Deteccion de WAF con 7 payloads trigger
- `subdomain_enum.py` - Enumeracion via crt.sh + DNS brute force
- `cms_scanner.py` - WordPress/Joomla/Drupal: plugins, users, vulns
- `api_fuzzer.py` - Descubrimiento de endpoints API, metodos HTTP, GraphQL
- `js_analyzer.py` - Secrets, API keys, URLs internas en JavaScript
- `cors_scanner.py` - Misconfigs CORS (wildcard, null, subdomain, scheme)
- `ssl_analyzer.py` - Analisis profundo SSL/TLS (protocolos, ciphers, certificado, grade A+ a F)
- `dns_analyzer.py` - Seguridad DNS (SPF, DKIM, DMARC, zone transfer, DNSSEC, MX/NS)
- `screenshot.py` - Captura de evidencia con Playwright (admin panels, error pages, datos expuestos)

**21 Skills de conocimiento** (`guardx/skills/` - auto-discovery)
- sql_injection, xss, command_injection, directory_traversal, ssrf
- csrf, idor, auth_bypass, file_upload, exposed_services
- missing_headers, ssh_hardening, ssl_tls, brute_force, info_disclosure
- cors_misconfig, subdomain_takeover, api_security, js_secrets
- ssl_deep (analisis avanzado SSL/TLS)
- dns_security (seguridad DNS avanzada)
- Cada skill incluye: detection, exploitation, remediation, payloads, references
- Se inyectan automaticamente en los prompts del agente

**10 Nuclei Templates personalizados** (`guardx/nuclei-templates/`)
- exposed-env, exposed-git, exposed-debug, exposed-backup, exposed-admin
- weak-cors, missing-security-headers, default-credentials, open-redirect, information-disclosure

**Modulos core** (`guardx/core/`)
- `state.py` - Estado del agente (findings, fases)
- `database.py` - SQLite historial (~/.guardx/history.db): scans, findings, actions, fixes
- `rate_limiter.py` - Token bucket per-domain (10 RPS default)
- `scope.py` - Control de alcance: CIDR, dominio, wildcard
- `webhooks.py` - Notificaciones: Slack, Discord, Telegram, generic HTTP
- `compliance.py` - Mapeo OWASP Top 10 2021, CIS Benchmarks, risk scoring
- `rollback.py` - Rollback de fixes SSH (backup/restore automatico, verificacion post-fix)
- `scheduler.py` - Escaneos programados con cron (parser propio, SQLite, daemon thread)
- `delta_report.py` - Comparacion entre escaneos (nuevas/resueltas/sin cambio + delta score)
- `plugins.py` - Sistema de plugins (~/.guardx/plugins/, manifest.json, carga dinamica)

**API REST v1** (`guardx/api/`)
- Blueprint Flask con 7 endpoints
- Auth: Bearer token / X-API-Key
- Endpoints: health, scan CRUD, findings, report
- Rate limiting integrado
- Endpoints adicionales en app.py: rollback, schedules, delta, plugins

**Sistema de reportes** (`guardx/reporting/`)
- `generator.py` - Generador HTML/JSON con Jinja2
- `templates/report.html.j2` - Template profesional dark theme (925 lineas)
- Score de seguridad visual, badges de severidad, print-friendly

**Infraestructura**
- Docker (Dockerfile multi-stage + docker-compose.yml)
- .env.example con todas las opciones documentadas
- Auto-discovery de skills (drop .py en skills/ y se carga solo)
- Wordlist incluida: `guardx/wordlists/common.txt` (308 rutas)

### Lo que FALTA (ordenado por prioridad):

## Prioridad 1 - Multi-target y UX

### 1.1 Multi-target scanning
**Que hace:** Escanear multiples targets a la vez.

**Como implementar:**
```
- Input acepta lista de IPs/dominios (textarea, uno por linea)
- Cada target corre como scan independiente con su propio thread
- Panel muestra tabs por target con progreso individual
- Reporte consolidado al final
- Rate limiter global para no saturar
```

### 1.2 Dashboard de tendencias
**Que hace:** Graficar la evolucion de seguridad en el tiempo usando delta reports.

**Como implementar:**
```
- Usar delta_report.py como base de datos de comparacion
- Grafica: # vulnerabilidades por severidad a lo largo del tiempo
- Score de seguridad historico (0-100)
- Top vulnerabilidades recurrentes
- Widget en el panel principal
```

## Prioridad 2 - OpenAI OAuth (usar modelos con suscripcion ChatGPT)

### 2.1 Portar codex-oauth-module a Python
**Que hace:** Autenticarse con tu cuenta de ChatGPT (Free/Plus/Pro) via OAuth 2.0 PKCE para usar modelos de OpenAI sin pagar por token.

**Referencia:** `codex-oauth-module/` (implementacion Node.js ya existente en el repo)

**Como implementar:**
```
Archivo nuevo: guardx/llm/openai_oauth.py
- Portar OAuth 2.0 PKCE flow de Node.js a Python
- Client ID: app_EMoamEEZ73f0CkXaXp7hrann (publico, oficial de Codex)
- Endpoints: auth.openai.com/oauth/authorize + auth.openai.com/oauth/token
- PKCE: code_verifier (32 bytes random base64url) + code_challenge (SHA-256)
- Servidor callback local en puerto 1455 (/auth/callback)
- Abrir navegador automaticamente (webbrowser.open)
- Intercambiar code por access_token + refresh_token
- Auto-refresh cuando falten <5 min para expirar
- Guardar credentials en ~/.guardx/openai_credentials.json (permisos 0600)
- Scope: openai.chat openai.models.read
```

### 2.2 Integrar como tercer provider en client.py
**Que hace:** Agregar "openai" como tercer proveedor junto a Anthropic y OpenRouter.

**Como implementar:**
```
- En .env: LLM_PROVIDER=openai (nueva opcion)
- En client.py: _run_openai_loop() usando Bearer token del OAuth
- Endpoint: api.openai.com/v1/chat/completions
- Formato: igual que OpenRouter (OpenAI function calling)
- Param obligatorio: store=false (requerido para modo OAuth/subscription)
- Reusar OPENROUTER_TOOLS (mismo formato OpenAI)
- Streaming con SSE igual que OpenRouter
```

### 2.3 Login endpoint en panel web
**Que hace:** Boton en el panel para autenticarse con ChatGPT sin usar terminal.

**Como implementar:**
```
- Endpoint: /openai/login → inicia OAuth flow, redirige al navegador
- Endpoint: /openai/callback → recibe code, intercambia tokens
- Endpoint: /openai/status → muestra estado de auth
- En el frontend: boton "Conectar ChatGPT" en settings/topbar
- Indicador visual de conexion (verde si autenticado)
```

### Modelos disponibles por plan:
```
Free:  gpt-4o-mini, gpt-4o (limitado)
Plus:  gpt-4o, gpt-4o-mini, gpt-5.1-codex ($20/mes)
Pro:   Todos los modelos, limites altos ($200/mes)
```

## Prioridad 3 - Integraciones y CI/CD

### 3.1 CI/CD Pipeline Integration
**Que hace:** Integrar GuardX en pipelines de CI/CD (GitHub Actions, GitLab CI, Jenkins).

**Como implementar:**
```
- GitHub Action: guardx-scan que lanza scan via API v1
- Falla el pipeline si se encuentran vulnerabilidades CRITICAL/HIGH
- Output: SARIF format para GitHub Security tab
- Configuracion: guardx.yml en root del repo
- CLI: guardx ci-scan --target URL --fail-on critical,high
```

### 3.2 SIEM Integration
**Que hace:** Enviar findings a sistemas SIEM (Splunk, Elastic, etc.)

**Como implementar:**
```
- Output en formato CEF (Common Event Format)
- Webhook adapter para Splunk HEC
- Elasticsearch bulk indexing
- Syslog output (RFC 5424)
```

### 3.3 Marketplace de plugins
**Que hace:** Repositorio central de plugins comunitarios.

**Como implementar:**
```
- Usar plugin system existente (plugins.py)
- Registry central: JSON con manifests de plugins disponibles
- CLI: guardx plugin search/install/update
- Verificacion de integridad (checksums)
- Rating system
```

## Como agregar una nueva herramienta

1. Crear archivo en `guardx/tools/nombre_tool.py`
2. Definir TOOL_SCHEMA (lo que el agente ve)
3. Implementar `async def execute(params: dict) -> str`
4. Registrar en `guardx/llm/client.py`:
   - Agregar import
   - Agregar schema a TOOLS list
   - Agregar executor a TOOL_EXECUTORS dict
   - (OPENROUTER_TOOLS se genera automaticamente)

Ejemplo minimo:
```python
# guardx/tools/mi_tool.py

TOOL_SCHEMA = {
    "name": "mi_tool",
    "description": "Que hace esta herramienta",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP o URL"},
        },
        "required": ["target"],
    },
}

def is_available() -> bool:
    return True

async def execute(params: dict) -> str:
    target = params["target"]
    # ... logica ...
    return "resultado como texto"
```

## Como agregar una nueva skill

1. Copiar `guardx/skills/_template.py` a `guardx/skills/nombre.py`
2. Llenar: id, name, category, severity, detection, exploitation, remediation
3. Agregar payloads (lista de strings) y references (OWASP/CWE)
4. Listo. Se carga automaticamente al iniciar.

## Estructura actual del proyecto

```
guardx-ai/
├── .env.example                    # Config: API keys, provider, auth, webhooks
├── docker-compose.yml              # Docker: build + run
├── Dockerfile                      # Multi-stage: builder + runtime
├── CLAUDE.md                       # Instrucciones para Claude Code
├── ROADMAP.md                      # ESTE ARCHIVO
├── README.md                       # Documentacion general
├── CORE_MODULES.md                 # Documentacion modulos core
├── CORE_QUICK_REFERENCE.md         # Referencia rapida de integracion
├── requirements.txt                # Dependencias Python
│
├── guardx/
│   ├── cli.py                      # Entry point CLI
│   ├── api/
│   │   ├── __init__.py             # Blueprint export
│   │   └── routes.py               # API REST v1 (7 endpoints, auth, rate limit)
│   ├── core/
│   │   ├── state.py                # Estado del agente (findings, fases)
│   │   ├── database.py             # SQLite historial (~/.guardx/history.db)
│   │   ├── rate_limiter.py         # Token bucket per-domain
│   │   ├── scope.py                # Control de alcance (CIDR/domain/wildcard)
│   │   ├── webhooks.py             # Notificaciones (Slack/Discord/Telegram)
│   │   ├── compliance.py           # Mapeo OWASP/CIS, risk scoring
│   │   ├── rollback.py             # Rollback de fixes SSH (backup/restore)
│   │   ├── scheduler.py            # Escaneos programados (cron parser propio)
│   │   ├── delta_report.py         # Comparacion entre escaneos (delta)
│   │   ├── plugins.py              # Sistema de plugins (carga dinamica)
│   │   └── events.py               # EventBus WebSocket (tiempo real)
│   ├── llm/
│   │   ├── client.py               # Agent loop (Anthropic + OpenRouter, 18 tools)
│   │   └── prompts.py              # Prompts por fase + skills injection
│   ├── tools/                      # 18 herramientas
│   │   ├── port_check.py           # TCP scan rapido
│   │   ├── nmap_scan.py            # Scan profundo + versiones
│   │   ├── http_headers.py         # Security headers
│   │   ├── nuclei_scan.py          # CVEs y misconfiguraciones
│   │   ├── sql_check.py            # SQL injection
│   │   ├── ssh_exec.py             # SSH remoto (Paramiko)
│   │   ├── web_spider.py           # BFS crawler
│   │   ├── dir_bruteforce.py       # Directory brute force
│   │   ├── tech_fingerprint.py     # Stack detection
│   │   ├── waf_detect.py           # WAF detection
│   │   ├── subdomain_enum.py       # Subdomain enumeration
│   │   ├── cms_scanner.py          # CMS vuln scanner
│   │   ├── api_fuzzer.py           # API endpoint discovery
│   │   ├── js_analyzer.py          # JS secrets analyzer
│   │   ├── cors_scanner.py         # CORS misconfiguration
│   │   ├── ssl_analyzer.py         # SSL/TLS deep analysis (grade A+ a F)
│   │   ├── dns_analyzer.py         # DNS security (SPF/DKIM/DMARC/DNSSEC)
│   │   └── screenshot.py           # Evidence screenshots (Playwright)
│   ├── skills/                     # 21 skills (auto-discovery)
│   │   ├── _template.py            # Template para nuevas skills
│   │   ├── sql_injection.py
│   │   ├── xss.py
│   │   ├── command_injection.py
│   │   ├── directory_traversal.py
│   │   ├── ssrf.py
│   │   ├── csrf.py
│   │   ├── idor.py
│   │   ├── auth_bypass.py
│   │   ├── file_upload.py
│   │   ├── exposed_services.py
│   │   ├── missing_headers.py
│   │   ├── ssh_hardening.py
│   │   ├── ssl_tls.py
│   │   ├── brute_force.py
│   │   ├── info_disclosure.py
│   │   ├── cors_misconfig.py
│   │   ├── subdomain_takeover.py
│   │   ├── api_security.py
│   │   ├── js_secrets.py
│   │   ├── ssl_deep.py             # SSL/TLS advanced analysis
│   │   └── dns_security.py         # DNS security advanced
│   ├── nuclei-templates/           # 10 templates personalizados
│   │   ├── exposed-env.yaml
│   │   ├── exposed-git.yaml
│   │   ├── exposed-debug.yaml
│   │   ├── exposed-backup.yaml
│   │   ├── exposed-admin.yaml
│   │   ├── weak-cors.yaml
│   │   ├── missing-security-headers.yaml
│   │   ├── default-credentials.yaml
│   │   ├── open-redirect.yaml
│   │   └── information-disclosure.yaml
│   ├── wordlists/
│   │   └── common.txt              # 308 rutas comunes
│   ├── reporting/
│   │   ├── generator.py            # Generador HTML/JSON
│   │   └── templates/
│   │       └── report.html.j2      # Template reporte profesional
│   └── utils/
│       └── subprocess_runner.py    # Ejecucion segura de comandos
│
└── web/
    ├── app.py                      # Backend Flask (~760 lineas: auth, chat, API, schedules, rollback)
    └── templates/
        └── index.html              # Panel web (login, chat, historial, programados, API)
```

## Dependencias actuales

```
anthropic    # Claude API
httpx        # OpenRouter API calls
paramiko     # SSH conexion
flask        # Panel web
rich         # Terminal formatting
pydantic     # Data models
jinja2       # Templates (reportes + panel)
python-dotenv # .env config
defusedxml   # Parseo seguro XML (nmap)
```

## Dependencias opcionales

```
playwright       # Screenshots (headless browser) - para screenshot.py
```

## Para correr

```bash
# Opcion 1: Docker (recomendado)
cp .env.example .env   # configurar API key
docker-compose up -d
# Abrir http://localhost:5000

# Opcion 2: Local
pip install -r requirements.txt
cp .env.example .env   # configurar API key
python3 web/app.py
# Abrir http://localhost:5000
```

## Notas tecnicas

- El agent loop esta en `guardx/llm/client.py` - es el corazon del sistema
- Los prompts en `guardx/llm/prompts.py` inyectan TODAS las skills automaticamente (detection + payloads + references)
- Las skills se cargan con `pkgutil.iter_modules` (auto-discovery)
- El panel usa WebSocket (Socket.IO) para comunicacion en tiempo real (ya no polling)
- Cada tool recibe params dict y devuelve string (simple, extensible)
- OpenRouter usa formato OpenAI (function calling), Anthropic usa tool_use nativo
- El `subprocess_runner.py` NUNCA usa shell=True (seguridad)
- Imports opcionales con try/except para degradacion graceful (DB, webhooks, reporting, rollback, scheduler, plugins, API)
- EventBus centraliza todos los eventos: emite via SocketIO + buffer interno para backward compat
- Tool timing: cada ejecucion de herramienta mide duracion y reporta exito/fallo via on_tool_result callback
- Rate limiter controla requests per-domain para no saturar targets
- Scope control evita escanear fuera del target autorizado
- OPENROUTER_TOOLS se genera automaticamente desde TOOLS (no necesita mantenimiento manual)
- Scheduler usa cron parser propio (sin dependencia externa) con daemon thread
- Delta report compara scans por tuplas (titulo, severidad)
- Plugin system busca en ~/.guardx/plugins/ con manifest.json
