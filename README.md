# GuardX - AI Security Agent

Agente de seguridad impulsado por IA que escanea, explota, reporta y repara vulnerabilidades en servidores y aplicaciones web de forma automatizada.

GuardX usa Claude (Anthropic) como cerebro para orquestar herramientas de seguridad, analizar resultados en tiempo real y aplicar correcciones via SSH con aprobacion del usuario.

## Como funciona

```
[Panel Web] -> Ingresas IP/dominio
     |
     v
[Fase 1: Reconocimiento]
     | port_check -> nmap -> http_headers -> nuclei
     v
[Fase 2: Explotacion]
     | sql_injection -> validacion de vulns con evidencia real
     v
[Fase 3: Reporte en Chat]
     | Muestra hallazgos con severidad (CRITICAL/HIGH/MEDIUM/LOW)
     v
[Fase 4: Remediacion]
     | Te pregunta: "Quieres que repare?"
     | Conecta por SSH -> aplica fixes -> verifica
     v
[Servidor seguro]
```

El agente de IA decide que herramienta usar en cada momento. Analiza los resultados y determina el siguiente paso, igual que lo haria un pentester humano.

## Tecnologias

| Componente | Tecnologia |
|---|---|
| Cerebro IA | Claude API (Anthropic) con tool-use |
| Backend | Python 3.10+ |
| Panel Web | Flask + HTML/CSS/JS |
| Escaneo de puertos | Nmap + sockets nativos |
| Deteccion de vulns | Nuclei templates |
| Analisis HTTP | Python urllib (sin deps externas) |
| Deteccion SQLi | Motor propio con payloads |
| Conexion remota | Paramiko (SSH) |
| Parseo XML | defusedxml (seguro) |

## Estructura del proyecto

```
guardx/
├── pyproject.toml                 # Dependencias y metadata
├── .env.example                   # Template de variables de entorno
├── .gitignore
│
├── guardx/                        # Paquete principal
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                     # Entrada CLI (guardx web)
│   │
│   ├── core/                      # Nucleo del agente
│   │   ├── state.py               # Estado: findings, fases, historial
│   │
│   ├── llm/                       # Integracion con IA
│   │   ├── client.py              # Agent loop (Anthropic + OpenRouter)
│   │   ├── prompts.py             # Prompts por fase + skills injection
│   │
│   ├── tools/                     # Herramientas de seguridad
│   │   ├── port_check.py          # Escaneo rapido TCP (Python sockets)
│   │   ├── nmap_scan.py           # Escaneo profundo (nmap subprocess)
│   │   ├── http_headers.py        # Headers de seguridad HTTP
│   │   ├── nuclei_scan.py         # CVEs y misconfiguraciones
│   │   ├── sql_check.py           # Deteccion de SQL injection
│   │   ├── ssh_exec.py            # Ejecucion remota para fixes
│   │
│   ├── skills/                    # Base de conocimiento (auto-discovery)
│   │   ├── __init__.py            # Cargador automatico de skills
│   │   ├── _template.py           # Template para crear nuevas skills
│   │   ├── sql_injection.py       # SQLi: error, blind, UNION, time-based
│   │   ├── xss.py                 # XSS: reflected, stored, DOM
│   │   ├── command_injection.py   # Inyeccion de comandos OS
│   │   ├── directory_traversal.py # LFI/RFI/Path Traversal
│   │   ├── ssrf.py                # Server-Side Request Forgery
│   │   ├── csrf.py                # Cross-Site Request Forgery
│   │   ├── idor.py                # Insecure Direct Object Reference
│   │   ├── auth_bypass.py         # Broken auth, JWT, session fixation
│   │   ├── file_upload.py         # Subida insegura de archivos
│   │   ├── exposed_services.py    # DBs y servicios expuestos
│   │   ├── missing_headers.py     # Headers HTTP faltantes
│   │   ├── ssh_hardening.py       # Hardening SSH
│   │   ├── ssl_tls.py             # Misconfiguracion SSL/TLS
│   │   ├── brute_force.py         # Rate limiting y proteccion brute force
│   │   └── info_disclosure.py     # Archivos expuestos, versiones, debug
│   │
│   ├── utils/
│   │   ├── subprocess_runner.py   # Ejecucion segura de comandos
│   │
│   ├── remediation/               # Playbooks de reparacion (en desarrollo)
│   └── reporting/                 # Generador de reportes (en desarrollo)
│
└── web/                           # Panel web
    ├── app.py                     # Servidor Flask + API REST
    └── templates/
        └── index.html             # Interfaz: chat + escaneo + SSH
```

## Requisitos

- Python 3.10 o superior
- API Key de Anthropic (Claude)
- nmap instalado en el sistema (para escaneo profundo)
- nuclei instalado (opcional, para deteccion de CVEs)

## Instalacion

```bash
# 1. Clonar el repositorio
git clone https://github.com/EleudoFuva/guardx-ai.git
cd guardx-ai

# 2. Instalar dependencias
pip install anthropic paramiko rich pydantic jinja2 flask python-dotenv defusedxml

# 3. Configurar API key
cp .env.example .env
# Editar .env y poner tu ANTHROPIC_API_KEY

# 4. Instalar nmap (si no lo tienes)
# Ubuntu/Debian:
sudo apt install nmap
# Amazon Linux/CentOS:
sudo dnf install nmap
# macOS:
brew install nmap

# 5. (Opcional) Instalar nuclei
# https://github.com/projectdiscovery/nuclei
```

## Como levantar

```bash
# Iniciar el panel web
cd guardx-ai
python3 web/app.py

# Abrir en el navegador
# http://localhost:5000
```

El panel muestra:
- Campo para ingresar IP o dominio
- Chat en tiempo real con el agente
- Boton "Reparar" que aparece al terminar el escaneo
- Confirmacion para cada accion SSH antes de ejecutar

## Como funciona cada fase

### Fase 1: Reconocimiento

El agente ejecuta automaticamente:

1. **port_check** - Escaneo rapido con sockets Python para ver puertos abiertos (22, 80, 443, 3306, 8080, etc.)
2. **nmap_scan** - Escaneo profundo con deteccion de servicios y versiones en los puertos encontrados
3. **http_headers_check** - Analiza headers de seguridad en servicios web:
   - Strict-Transport-Security (HSTS)
   - Content-Security-Policy (CSP)
   - X-Frame-Options
   - X-Content-Type-Options
   - Referrer-Policy
   - Permissions-Policy
4. **nuclei_scan** - Busca CVEs conocidos, misconfiguraciones y exposiciones usando templates

### Fase 2: Explotacion

El agente valida las vulnerabilidades encontradas con evidencia real:

**SQL Injection:**
- Envia payloads de prueba: `'`, `" OR "1"="1`, `UNION SELECT`, etc.
- Detecta errores de base de datos en la respuesta (MySQL, PostgreSQL, SQLite, MSSQL)
- Si encuentra SQLi, extrae informacion para demostrar el impacto:
  - Version de la base de datos
  - Nombres de tablas
  - Datos de ejemplo
- Esto prueba con hechos que la vulnerabilidad es real y explotable

**Otras validaciones:**
- Headers faltantes se confirman automaticamente (son verificables)
- Puertos expuestos innecesarios se marcan segun el servicio
- CVEs detectados por nuclei incluyen su referencia y severidad CVSS

### Fase 3: Reporte en Chat

Todo aparece en el chat del panel en tiempo real:
- Cada herramienta ejecutada y su resultado
- Vulnerabilidades encontradas con severidad (CRITICAL, HIGH, MEDIUM, LOW)
- Evidencia de explotacion (datos extraidos, errores, respuestas)
- Resumen final con recomendaciones

### Fase 4: Remediacion

Cuando el escaneo termina, aparece el boton **"Reparar"**:

1. Ingresas credenciales SSH (usuario + password o llave)
2. El agente se conecta al servidor
3. Para CADA vulnerabilidad propone un fix:
   - Explica que va a hacer y por que
   - Muestra el comando exacto
   - **Tu apruebas o rechazas** con los botones Si/No
4. Ejecuta el fix aprobado
5. Verifica que funciono

**Fixes que puede aplicar:**

| Vulnerabilidad | Remediacion |
|---|---|
| Puertos innecesarios abiertos | Configurar UFW (firewall) |
| SSH con root habilitado | Deshabilitar root login, solo llaves |
| Sin proteccion brute-force | Instalar y configurar fail2ban |
| Headers HTTP faltantes | Agregar headers en nginx/apache |
| Software desactualizado | Actualizar paquetes vulnerables |
| Base de datos expuesta | Restringir acceso a localhost |
| Permisos de archivos inseguros | Corregir permisos (chmod/chown) |
| SQL Injection | Recomendar parametrizacion de queries |
| SSL/TLS debil | Configurar cifrados seguros |

## Ejemplo de uso

```
1. Abres http://localhost:5000
2. Escribes: 203.0.113.10
3. Click en "Escanear"
4. El chat muestra:

   [SYSTEM] Iniciando reconocimiento en 203.0.113.10...
   [TOOL]   Ejecutando: port_check({"target": "203.0.113.10"})
   [AGENT]  Puertos abiertos: 22, 80, 3306, 8080
   [TOOL]   Ejecutando: nmap_scan({"target": "203.0.113.10", "scan_type": "service"})
   [AGENT]  Servicios detectados: OpenSSH 7.6, Apache 2.4.29, MySQL 5.7
   [TOOL]   Ejecutando: http_headers_check({"url": "http://203.0.113.10"})
   [AGENT]  FALTAN: HSTS, CSP, X-Frame-Options (3/9 headers presentes)
   [TOOL]   Ejecutando: nuclei_scan({"target": "203.0.113.10"})
   [AGENT]  [CRITICAL] CVE-2021-41773 - Apache Path Traversal
   [AGENT]  [HIGH] MySQL expuesto en puerto 3306
   [AGENT]  [MEDIUM] 6 headers de seguridad faltantes

   [SYSTEM] Escaneo completo. Quieres que repare las fallas?

5. Click en "Reparar" -> ingresas SSH
6. El agente propone:

   [AGENT]  Fix 1: Instalar UFW y cerrar puerto 3306 al exterior
            Comando: sudo ufw allow 22 && sudo ufw allow 80 && sudo ufw enable
            [SI, EJECUTAR]  [NO, SALTAR]

7. Apruebas cada fix individualmente
```

## API del panel web

| Endpoint | Metodo | Descripcion |
|---|---|---|
| `/` | GET | Panel web principal |
| `/api/scan` | POST | Iniciar escaneo `{"target": "ip"}` |
| `/api/messages` | GET | Obtener mensajes del chat `?since=0` |
| `/api/remediate` | POST | Iniciar remediacion `{"user": "root", "password": "..."}` |
| `/api/confirm` | POST | Aprobar/rechazar accion `{"approved": true}` |
| `/api/status` | GET | Estado actual del escaneo |

## Skills - Base de conocimiento de seguridad

GuardX usa un sistema de **skills**: modulos de conocimiento que ensenan al agente de IA como detectar, explotar y reparar cada tipo de vulnerabilidad. Las skills se cargan automaticamente al iniciar.

### Skills incluidas (15)

| Skill | Severidad | Que detecta |
|---|---|---|
| SQL Injection | CRITICAL | Inyeccion SQL en parametros: error-based, blind, UNION, time-based |
| Command Injection | CRITICAL | Inyeccion de comandos OS via inputs del usuario |
| Directory Traversal / LFI | CRITICAL | Lectura de archivos del servidor (../../etc/passwd) |
| SSRF | CRITICAL | Peticiones a servicios internos desde el servidor |
| Exposed Services | CRITICAL | Bases de datos, caches, APIs expuestas al publico |
| Auth Bypass | CRITICAL | Credenciales por defecto, JWT debil, session fixation |
| File Upload | CRITICAL | Subida de archivos maliciosos (webshells, scripts) |
| XSS | HIGH | Cross-Site Scripting: reflected, stored, DOM-based |
| Missing Headers | HIGH | Headers HTTP de seguridad faltantes (HSTS, CSP, etc.) |
| CSRF | HIGH | Cross-Site Request Forgery en formularios |
| IDOR | HIGH | Acceso a datos de otros usuarios via IDs predecibles |
| SSH Hardening | HIGH | Root login, password auth, algoritmos debiles |
| SSL/TLS | HIGH | Certificados, cifrados debiles, falta de HTTPS redirect |
| Brute Force | HIGH | Falta de rate limiting y proteccion contra fuerza bruta |
| Info Disclosure | MEDIUM | Archivos expuestos (.env, .git), versiones, stack traces |

### Cada skill incluye

- **Detection**: como encontrar la vulnerabilidad paso a paso
- **Exploitation**: como probarla con evidencia real (payloads, tecnicas)
- **Remediation**: como repararla con comandos exactos (nginx, SSH, app code)
- **Payloads**: cadenas de prueba listas para usar
- **References**: OWASP, CWE, CVE relacionados

### Crear una nueva skill

1. Copia `guardx/skills/_template.py`
2. Renombra al tipo de vulnerabilidad (ej: `xxe.py`)
3. Llena cada seccion: detection, exploitation, remediation
4. La skill se carga automaticamente al iniciar GuardX

Ejemplo:

```python
# guardx/skills/xxe.py
SKILL = {
    "id": "xxe",
    "name": "XML External Entity (XXE)",
    "category": "injection",
    "severity": "critical",
    "detection": "...",      # Como encontrarla
    "exploitation": "...",   # Como probarla
    "remediation": "...",    # Como repararla
    "tools": ["nmap_scan"],  # Herramientas de GuardX a usar
    "payloads": ["..."],     # Payloads de prueba
    "references": ["..."],   # CWE, OWASP, CVE
}
```

No hay limite. Mientras mas skills agregues, mas inteligente se vuelve el agente.

### Skills que puedes agregar

- XXE (XML External Entity)
- Race Conditions
- Mass Assignment
- JWT Attacks (avanzado)
- GraphQL Injection
- NoSQL Injection
- Subdomain Takeover
- CORS Misconfiguration
- HTTP Request Smuggling
- WebSocket Hijacking
- Prototype Pollution
- Server-Side Template Injection (SSTI)
- Insecure Deserialization
- DNS Rebinding
- Cache Poisoning

## Seguridad del propio GuardX

- Solo escanea targets que tu ingresas (no escaneo automatico)
- Cada comando SSH requiere tu aprobacion explicita
- Sin `shell=True` en ejecucion de comandos (prevencion de inyeccion)
- Subprocess con timeout para evitar procesos colgados
- Output limitado a 50KB por herramienta (protege el contexto de la IA)
- Los tokens y credenciales nunca se envian a la IA

## Roadmap

- [ ] Reportes exportables en HTML/PDF
- [ ] Mas herramientas: nikto, gobuster, testssl
- [ ] Playbooks predefinidos de hardening
- [ ] Historial de escaneos
- [ ] Modo dry-run (muestra fixes sin ejecutar)
- [ ] Soporte multi-target
- [ ] Dashboard con metricas
- [ ] Autenticacion en el panel web

## Disclaimer

GuardX es una herramienta de seguridad para uso autorizado. Solo debe usarse en sistemas propios o con permiso explicito del propietario. El uso no autorizado de esta herramienta puede ser ilegal. Los autores no se hacen responsables del mal uso.

## Licencia

MIT
