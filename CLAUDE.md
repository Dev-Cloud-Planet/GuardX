# GuardX - AI Security Agent

## Contexto
Este proyecto lo construimos desde cero. Es un agente de seguridad con IA que escanea, explota y repara vulnerabilidades web automaticamente. El creador se llama Eleudo y le gusta que lo trates como companero, no como herramienta. El te llama GuardX.

## Que es este proyecto
- Agente de IA que hace pentesting automatizado en 3 fases: Ataque, Defensa, Reporte
- Panel web profesional con WebSocket (tiempo real), login, chat, historial, reportes, schedules, API
- Soporta Anthropic (Claude) y OpenRouter como proveedores de IA
- 18 herramientas de escaneo y explotacion
- 21 skills de conocimiento de seguridad (auto-discovery)
- 10 nuclei templates personalizados
- 11 modulos core: state, database, rate_limiter, scope, webhooks, compliance, rollback, scheduler, delta_report, plugins, events
- API REST v1 con auth y rate limiting
- Sistema de reportes HTML/JSON con template profesional
- Conexion SSH para reparar vulnerabilidades con aprobacion del usuario

## Archivos clave
- `ROADMAP.md` — LEE ESTO PRIMERO. Tiene todo lo que falta por hacer con instrucciones exactas
- `web/app.py` — Backend Flask+SocketIO (~850 lineas), WebSocket, API REST, auth, chat, reports, webhooks, schedules, rollback, DB
- `web/templates/index.html` — Panel web completo (login, chat, historial, programados, API)
- `guardx/llm/client.py` — Agent loop (Anthropic + OpenRouter con tool-use, 18 tools)
- `guardx/llm/prompts.py` — Prompts por fase, inyecta skills con payloads y references
- `guardx/tools/` — 18 herramientas de ataque (ver ROADMAP para lista completa)
- `guardx/skills/` — 21 skills de conocimiento (auto-discovery)
- `guardx/core/` — 11 modulos core (ver ROADMAP para lista completa)
- `guardx/api/` — API REST v1 Blueprint (routes.py)
- `guardx/nuclei-templates/` — 10 templates YAML personalizados
- `guardx/reporting/` — Generador de reportes + template HTML profesional
- `guardx/skills/_template.py` — Copiar para crear nueva skill

## Para correr
```
pip install -r requirements.txt
cp .env.example .env  # poner API key
python3 web/app.py    # abre http://localhost:5000
```

## Que sigue
Lee ROADMAP.md. La prioridad 1 es:
1. Multi-target scanning
2. Dashboard de tendencias

Prioridad 2:
3. CI/CD pipeline integration
4. SIEM integration
5. Marketplace de plugins

## Reglas
- Responde en espanol
- Preguntas cortas, 1 linea (la consola de Eleudo es pequena)
- No toques archivos sin que te lo pida
- Si Eleudo dice "implementa prioridad X" ve al ROADMAP.md y sigue las instrucciones
