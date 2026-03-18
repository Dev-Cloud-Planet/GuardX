<p align="center">
  <h1 align="center">GuardX</h1>
  <p align="center"><strong>AI-Powered Security Agent</strong></p>
  <p align="center">Scan. Exploit. Fix. Report. — Automated pentesting with AI.</p>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
  <a href="#providers"><img src="https://img.shields.io/badge/AI-Claude%20%7C%20OpenRouter%20%7C%20Ollama-green.svg" alt="AI Providers"></a>
  <a href="#mcp-server"><img src="https://img.shields.io/badge/MCP-compatible-purple.svg" alt="MCP Compatible"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License MIT"></a>
</p>

---

GuardX is an autonomous AI security agent that performs real penetration testing in 3 phases: **Attack** (reconnaissance + exploitation), **Defense** (automated remediation via SSH), and **Report** (detailed findings with evidence). The AI decides which tools to use, analyzes results in real-time, and chains findings — just like a human pentester.

**3 ways to use it:**
- `guardx scan target.com` — CLI scan from your terminal
- `guardx web` — Interactive web panel with real-time chat
- `guardx mcp` — MCP server for Claude Code / Cursor integration

**3 AI providers:**
- **Anthropic** (Claude) — Best results, direct API
- **OpenRouter** — Access to 100+ models, pay-per-use
- **Ollama** — Local models, zero cost, full privacy

## How It Works

```
You enter a target (IP or domain)
         |
         v
  Phase 1: ATTACK
    |  21 security tools run autonomously
    |  AI chains findings: spider -> SQLi -> XSS -> ...
    |  28 knowledge skills guide the AI
         |
         v
  Phase 2: DEFENSE
    |  AI proposes fixes for each vulnerability
    |  You approve/deny each SSH command
    |  Automatic rollback if something breaks
         |
         v
  Phase 3: REPORT
    |  Technical report (for security team)
    |  Executive report (for management)
    |  HTML/JSON export
         |
         v
  Secure server
```

## Installation

### Quick Start (pip)

```bash
pip install guardx
```

### From Source

```bash
git clone https://github.com/Dev-Projects-planet/guardx.git
cd guardx
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your API key
```

### External Tools (optional but recommended)

```bash
# nmap - deep port scanning
sudo apt install nmap        # Debian/Ubuntu
sudo dnf install nmap        # Amazon Linux/CentOS
brew install nmap             # macOS

# nuclei - CVE detection (optional)
# https://github.com/projectdiscovery/nuclei
```

## Providers

GuardX supports 3 AI providers. Choose based on your needs:

| Provider | Cost | Quality | Setup |
|----------|------|---------|-------|
| **Anthropic** | Pay per token | Best | `ANTHROPIC_API_KEY=sk-ant-...` |
| **OpenRouter** | Pay per token / Free tiers | Good | `OPENROUTER_API_KEY=sk-or-...` |
| **Ollama** | Free (local) | Depends on model | `OLLAMA_MODEL=llama3.1` |

### Using Ollama (Zero Cost)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model
ollama pull llama3.1

# 3. Scan with zero cost
guardx scan target.com --provider ollama --model llama3.1
```

### Configuration (.env)

```bash
# Provider: "anthropic", "openrouter", or "ollama"
GUARDX_PROVIDER=anthropic

# Anthropic
ANTHROPIC_API_KEY=sk-ant-xxxxx

# OpenRouter
# OPENROUTER_API_KEY=sk-or-xxxxx
# OPENROUTER_MODEL=anthropic/claude-sonnet-4

# Ollama (local, zero cost)
# OLLAMA_MODEL=llama3.1
# OLLAMA_BASE_URL=http://localhost:11434/v1
```

## Usage

### CLI

```bash
# Basic scan
guardx scan target.com

# Scan with specific provider
guardx scan target.com --provider ollama --model llama3.1
guardx scan target.com --provider anthropic

# Launch web panel
guardx web
guardx web 8080    # custom port

# Start MCP server
guardx mcp

# Utilities
guardx providers   # Show available providers and status
guardx tools       # List all 21 security tools
guardx skills      # List all 28 security knowledge modules
guardx version
```

### Web Panel

```bash
guardx web
# Open http://localhost:5000
```

Features:
- Real-time chat with the AI agent (WebSocket)
- Visual progress through scan phases
- SSH remediation with per-command approval
- Scan history and scheduled scans
- HTML/JSON report export
- REST API for CI/CD integration

### Docker

```bash
docker-compose up -d
# Open http://localhost:5000
```

## MCP Server

GuardX exposes all 21 security tools as an MCP server, so you can use them directly from **Claude Code**, **Cursor**, or any MCP-compatible client.

### Setup in Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "guardx": {
      "command": "guardx",
      "args": ["mcp"]
    }
  }
}
```

Then in Claude Code you can ask: *"Use guardx to scan example.com for vulnerabilities"* and it will call the tools directly.

### Available MCP Tools

All tools are prefixed with `guardx_` to avoid conflicts:

| Tool | Description |
|------|-------------|
| `guardx_port_check` | Fast TCP port scan |
| `guardx_nmap_scan` | Deep port/service enumeration |
| `guardx_http_headers` | HTTP security headers check |
| `guardx_nuclei_scan` | CVE & misconfiguration detection |
| `guardx_sql_check` | SQL injection testing (4 techniques) |
| `guardx_xss_check` | Cross-Site Scripting detection |
| `guardx_web_spider` | BFS crawler (URLs, forms, params) |
| `guardx_dir_bruteforce` | Hidden directory discovery |
| `guardx_tech_fingerprint` | Technology stack identification |
| `guardx_waf_detect` | WAF detection & evasion |
| `guardx_subdomain_enum` | Subdomain enumeration (DNS + crt.sh) |
| `guardx_cms_scanner` | CMS vulnerability scanning |
| `guardx_api_fuzzer` | API endpoint discovery |
| `guardx_js_analyzer` | JavaScript secrets extraction |
| `guardx_cors_scanner` | CORS misconfiguration testing |
| `guardx_ssl_analyzer` | SSL/TLS deep analysis |
| `guardx_dns_analyzer` | DNS security (SPF/DKIM/DMARC/DNSSEC) |
| `guardx_http_request` | Raw HTTP requests |

## Security Tools (21)

GuardX includes 21 built-in security tools that the AI orchestrates autonomously:

**Reconnaissance:** port_check, nmap_scan, tech_fingerprint, subdomain_enum, dns_analyzer, web_spider, dir_bruteforce

**Vulnerability Scanning:** http_headers, nuclei_scan, ssl_analyzer, cors_scanner, waf_detect, cms_scanner

**Exploitation:** sql_check (error/UNION/blind/time-based), xss_check (reflected/stored/DOM), api_fuzzer, js_analyzer

**Evidence:** screenshot (Playwright), http_request

**Remediation:** ssh_exec (with user approval + rollback)

## Security Skills (28)

Skills are knowledge modules that teach the AI how to detect, exploit, and fix each vulnerability type. They're auto-discovered at startup.

| Skill | Severity | Description |
|-------|----------|-------------|
| SQL Injection | CRITICAL | Error, UNION, blind, time-based SQLi |
| Command Injection | CRITICAL | OS command injection via user inputs |
| Directory Traversal | CRITICAL | LFI/RFI/path traversal |
| SSRF | CRITICAL | Server-side request forgery |
| Auth Bypass | CRITICAL | Default creds, JWT attacks, session fixation |
| File Upload | CRITICAL | Webshell upload, extension bypass |
| Exposed Services | CRITICAL | Exposed databases, caches, APIs |
| XSS | HIGH | Reflected, stored, DOM-based |
| CSRF | HIGH | Cross-site request forgery |
| IDOR | HIGH | Insecure direct object references |
| Missing Headers | HIGH | HSTS, CSP, X-Frame-Options |
| SSH Hardening | HIGH | Root login, weak algorithms |
| SSL/TLS | HIGH | Weak ciphers, expired certs |
| Brute Force | HIGH | Rate limiting, account lockout |
| CORS Misconfig | HIGH | Wildcard origins, credentials |
| JWT Attacks | HIGH | None algorithm, weak secrets |
| Insecure Deserialization | HIGH | Object injection |
| Race Condition | HIGH | TOCTOU, double spending |
| Info Disclosure | MEDIUM | Exposed .env, .git, stack traces |
| Open Redirect | MEDIUM | URL redirect manipulation |
| SSTI | MEDIUM | Server-side template injection |
| DNS Security | MEDIUM | SPF/DKIM/DMARC, zone transfer |
| Subdomain Takeover | MEDIUM | Dangling DNS records |
| API Security | MEDIUM | Broken auth, mass assignment |

### Creating a New Skill

```bash
cp guardx/skills/_template.py guardx/skills/your_skill.py
# Edit the SKILL dict with detection, exploitation, remediation
# It loads automatically on next run
```

## REST API (v1)

GuardX includes a REST API for CI/CD pipeline integration:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Status + tool/skill counts |
| `/api/v1/scan` | POST | Start scan `{"target": "..."}` |
| `/api/v1/scan/<id>` | GET | Get scan status |
| `/api/v1/scan/<id>/findings` | GET | Get findings |
| `/api/v1/scan/<id>/report` | GET | Get HTML/JSON report |
| `/api/v1/scans` | GET | List all scans (paginated) |
| `/api/v1/scan/<id>` | DELETE | Cancel scan |

Authentication: Bearer token or `X-API-Key` header.

## Architecture

```
Browser / CLI / MCP Client
         |
         v
  Flask + Socket.IO (web/app.py)
    |-- Auth (bcrypt)
    |-- WebSocket real-time
    |-- REST API v1
         |
         v
  GuardXClient Agent Loop (guardx/llm/client.py)
    |-- Anthropic (native tool_use)
    |-- OpenRouter (OpenAI function calling)
    |-- Ollama (local, text-parsed tools)
         |
    +---------+---------+
    |         |         |
  21 Tools  28 Skills  11 Core Modules
    |                    |
    v                    v
  nmap, nuclei,      database, scheduler,
  paramiko, httpx    webhooks, compliance,
                     rollback, plugins, events
```

## Project Structure

```
guardx/
├── guardx/
│   ├── cli.py              # CLI entry point
│   ├── mcp_server.py       # MCP server (stdio JSON-RPC)
│   ├── llm/
│   │   ├── client.py       # Agent loop (3 providers)
│   │   └── prompts.py      # Phase prompts + skill injection
│   ├── tools/              # 21 security tools
│   ├── skills/             # 28 knowledge modules (auto-discovery)
│   ├── core/               # 11 core modules
│   │   ├── database.py     # SQLite scan history
│   │   ├── scheduler.py    # Cron-based scheduling
│   │   ├── webhooks.py     # Slack/Discord/Telegram
│   │   ├── compliance.py   # OWASP/CIS mapping
│   │   ├── rollback.py     # SSH fix rollback
│   │   ├── plugins.py      # Plugin system
│   │   └── events.py       # WebSocket EventBus
│   ├── api/                # REST API v1
│   ├── reporting/          # HTML/JSON report generator
│   └── nuclei-templates/   # 10 custom YAML templates
├── web/
│   ├── app.py              # Flask + Socket.IO backend
│   └── templates/
│       └── index.html      # Interactive web panel
├── pyproject.toml
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Security

- Only scans targets you explicitly provide
- Every SSH command requires your approval
- No `shell=True` in subprocess calls
- Tool output capped at 50KB (prevents token explosion)
- Credentials never sent to the AI
- bcrypt password hashing for web panel
- Rate limiting on API endpoints
- Safe XML parsing (defusedxml)

## Disclaimer

GuardX is a security tool for **authorized use only**. Only use it on systems you own or have explicit permission to test. Unauthorized use may be illegal. The authors are not responsible for misuse.

## License

MIT