"""GuardX Web Panel - 3 Phases: Attack, Defense, Report."""
import os
import sys
import json
import re
import asyncio
import threading
import time
import uuid
from functools import wraps

# Gevent monkey-patch MUST happen before any other imports
# This is required for gunicorn + gevent in production
_async_mode = "threading"
try:
    from gevent import monkey
    monkey.patch_all()
    _async_mode = "gevent"
except ImportError:
    pass  # Fallback to threading mode for local dev

from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
load_dotenv()

from guardx.llm.client import GuardXClient
from guardx.llm.prompts import build_recon_prompt, build_exploit_prompt, build_remediate_prompt, build_report_prompt
from guardx.tools.ssh_exec import get_connection
from guardx.core.events import get_event_bus

# Optional imports - graceful fallback if modules not available
try:
    from guardx.core.database import get_db
except ImportError:
    get_db = None

try:
    from guardx.core.webhooks import notify
except ImportError:
    notify = None

try:
    from guardx.reporting import generate_report
except ImportError:
    generate_report = None

try:
    from guardx.core.rollback import get_rollback_manager
except ImportError:
    get_rollback_manager = None

try:
    from guardx.core.scheduler import get_scheduler
except ImportError:
    get_scheduler = None

try:
    from guardx.core.delta_report import get_delta_reporter
except ImportError:
    get_delta_reporter = None

try:
    from guardx.core.plugins import get_plugin_manager
except ImportError:
    get_plugin_manager = None

try:
    from guardx.core.compliance import calculate_risk_score
except ImportError:
    calculate_risk_score = None

try:
    from guardx.api.routes import api_bp
except ImportError:
    api_bp = None

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("GUARDX_SECRET_KEY", os.urandom(32).hex())

# ── Secure session config ────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv("GUARDX_HTTPS", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
)

# ── SocketIO Configuration ────────────────────────────────────────
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=_async_mode)

# ── Auth Configuration with bcrypt ────────────────────────────────
AUTH_ENABLED = os.getenv("GUARDX_AUTH_ENABLED", "true").lower() == "true"
AUTH_USER = os.getenv("GUARDX_USER", "admin")
_AUTH_RAW_PASSWORD = os.getenv("GUARDX_PASSWORD", "guardx2026")

# Hash password with bcrypt (supports both pre-hashed and plain text)
try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
    # Check if password is already a bcrypt hash
    if _AUTH_RAW_PASSWORD.startswith("$2b$") or _AUTH_RAW_PASSWORD.startswith("$2a$"):
        AUTH_PASSWORD_HASH = _AUTH_RAW_PASSWORD.encode('utf-8')
    else:
        AUTH_PASSWORD_HASH = _bcrypt.hashpw(_AUTH_RAW_PASSWORD.encode('utf-8'), _bcrypt.gensalt())
except ImportError:
    _BCRYPT_AVAILABLE = False
    AUTH_PASSWORD_HASH = None


def _verify_password(password: str) -> bool:
    """Verify password against stored hash. Falls back to plain text if bcrypt not available."""
    if _BCRYPT_AVAILABLE and AUTH_PASSWORD_HASH:
        try:
            return _bcrypt.checkpw(password.encode('utf-8'), AUTH_PASSWORD_HASH)
        except Exception:
            return False
    # Fallback: constant-time comparison for plain text
    import hmac
    return hmac.compare_digest(password, _AUTH_RAW_PASSWORD)


def _generate_csrf_token() -> str:
    """Generate or return existing CSRF token for the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(32).hex()
    return session['csrf_token']


def _check_csrf(f):
    """Decorator to validate CSRF token on state-changing requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        if request.method in ('POST', 'PUT', 'DELETE'):
            token = request.headers.get('X-CSRF-Token') or (request.json or {}).get('_csrf')
            if not token or token != session.get('csrf_token'):
                return jsonify({"error": "Invalid CSRF token"}), 403
        return f(*args, **kwargs)
    return decorated_function


# ── Login Required Decorator ──────────────────────────────────
def login_required(f):
    """Decorator to check authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        if "authenticated" not in session or not session["authenticated"]:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


# ── Rate limit for login (brute force protection) ────────────────
_login_attempts = {}  # ip -> {"count": int, "last": float}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes


def _check_login_rate_limit(ip: str) -> bool:
    """Return True if login is allowed, False if rate limited."""
    now = time.time()
    if ip in _login_attempts:
        info = _login_attempts[ip]
        # Reset after lockout period
        if now - info["last"] > LOGIN_LOCKOUT_SECONDS:
            _login_attempts[ip] = {"count": 0, "last": now}
            return True
        if info["count"] >= MAX_LOGIN_ATTEMPTS:
            return False
    return True


def _record_login_attempt(ip: str, success: bool):
    """Record a login attempt for rate limiting."""
    now = time.time()
    if success:
        _login_attempts.pop(ip, None)
    else:
        if ip not in _login_attempts:
            _login_attempts[ip] = {"count": 0, "last": now}
        _login_attempts[ip]["count"] += 1
        _login_attempts[ip]["last"] = now

# ── Global State ──────────────────────────────────────────────
scan_state = {
    "running": False,
    "target": None,
    "phase": "idle",           # idle | recon | exploit | waiting_exploit | waiting_fix | remediate | report | done
    "messages": [],
    "recon_result": "",
    "exploit_result": "",
    "remediate_result": "",
    "pending_confirm": None,
    "confirm_response": None,
    "chat_messages": [],
    "scan_id": None,
}

# ── Initialize EventBus ────────────────────────────────────────
events = get_event_bus(socketio, scan_state)


def add_msg(role: str, text: str):
    """Add message to scan state and emit via WebSocket."""
    events.emit_message(role, text)


def add_finding(severity: str, title: str, evidence: str = ""):
    """Add finding to scan state and emit via WebSocket."""
    events.emit_finding(severity, title, evidence)


def _parse_findings_from_text(text: str):
    """Parse agent text output to extract findings and update severity counters."""
    if not text:
        return
    # Match patterns like "CRITICAL:", "**CRITICAL**:", "- CRITICAL:", "[CRITICAL]"
    pattern = r'(?:^|\n)\s*(?:\*\*|#+\s*|-\s*|\[)?(?P<sev>CRITICAL|HIGH|MEDIUM|LOW)(?:\*\*|\])?\s*[:\-]\s*(?P<title>[^\n]{3,100})'
    for match in re.finditer(pattern, text, re.IGNORECASE):
        severity = match.group('sev').lower()
        title = match.group('title').strip().rstrip('*').strip()
        if title:
            add_finding(severity, title)


def _add_msg_and_parse(text: str):
    """Wrapper that adds message and parses findings from agent text."""
    add_msg("agent", text)
    _parse_findings_from_text(text)


# ── SocketIO Event Handlers ────────────────────────────────────
@socketio.on('connect', namespace='/')
def on_connect():
    """Handle client connection - requires authentication if enabled."""
    if AUTH_ENABLED and not session.get("authenticated"):
        return False  # Reject connection
    join_room('scan')
    emit('guardx:connected', {'status': 'connected', 'role': 'system', 'text': 'Connected to GuardX'})


@socketio.on('disconnect', namespace='/')
def on_disconnect():
    """Handle client disconnection."""
    leave_room('scan')


@socketio.on('guardx:chat', namespace='/')
def on_chat(data):
    """Handle chat message via WebSocket."""
    user_message = data.get("message", "").strip()

    if not user_message:
        emit('guardx:error', {'error': 'Message required'})
        return

    # Add user message to chat history
    scan_state["chat_messages"].append({
        "role": "user",
        "text": user_message,
        "timestamp": time.time(),
    })

    # Add to main message stream
    add_msg("user", user_message)

    emit('guardx:chat_ack', {
        'status': 'ok',
        'chat_count': len(scan_state["chat_messages"]),
    })


@socketio.on('guardx:confirm_response', namespace='/')
def on_confirm_response(data):
    """Handle confirm response via WebSocket."""
    scan_state["confirm_response"] = data.get("approved", False)
    emit('guardx:confirm_ack', {'status': 'ok'})


# ── Routes ────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    """Health check endpoint - no auth required."""
    return jsonify({"status": "ok", "service": "guardx"})


# ── Auth Routes ───────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    """Login endpoint - authenticate user with bcrypt + rate limiting."""
    if not AUTH_ENABLED:
        session["authenticated"] = True
        return jsonify({"status": "ok", "message": "Auth disabled"})

    ip = request.remote_addr or "unknown"

    # Check rate limit
    if not _check_login_rate_limit(ip):
        info = _login_attempts.get(ip, {})
        remaining = int(LOGIN_LOCKOUT_SECONDS - (time.time() - info.get("last", 0)))
        return jsonify({
            "error": "Too many attempts",
            "message": f"Cuenta bloqueada. Intenta en {remaining}s",
            "locked": True,
            "retry_after": remaining
        }), 429

    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if username == AUTH_USER and _verify_password(password):
        _record_login_attempt(ip, True)
        session["authenticated"] = True
        session["user"] = username
        session.permanent = True
        csrf = _generate_csrf_token()
        return jsonify({
            "status": "ok",
            "message": "Authenticated",
            "user": username,
            "csrf_token": csrf
        })

    _record_login_attempt(ip, False)
    attempts_left = MAX_LOGIN_ATTEMPTS - _login_attempts.get(ip, {}).get("count", 0)
    return jsonify({
        "error": "Invalid credentials",
        "message": f"Credenciales invalidas. {max(0, attempts_left)} intentos restantes",
        "attempts_left": max(0, attempts_left)
    }), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    """Logout endpoint - clear session completely."""
    session.clear()
    return jsonify({"status": "ok", "message": "Sesion cerrada"})


@app.route("/api/status")
def get_status():
    """Status endpoint - returns auth state, scan info, and CSRF token."""
    if AUTH_ENABLED and not session.get("authenticated"):
        return jsonify({"error": "Unauthorized", "auth_required": True}), 401

    result = {
        "running": scan_state["running"],
        "phase": scan_state["phase"],
        "target": scan_state["target"],
        "auth_enabled": AUTH_ENABLED,
    }
    if session.get("authenticated"):
        result["user"] = session.get("user", AUTH_USER)
        result["csrf_token"] = _generate_csrf_token()
    return jsonify(result)


@app.route("/api/messages")
@login_required
def get_messages():
    since = int(request.args.get("since", 0))
    return jsonify({
        "messages": scan_state["messages"][since:],
        "total": len(scan_state["messages"]),
        "phase": scan_state["phase"],
        "running": scan_state["running"],
        "pending_confirm": scan_state["pending_confirm"],
    })


@app.route("/api/chat", methods=["POST"])
@login_required
@_check_csrf
def chat():
    """Interactive chat endpoint - accepts user message and injects into agent loop."""
    data = request.json or {}
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "Message required"}), 400

    # Add user message to chat history
    scan_state["chat_messages"].append({
        "role": "user",
        "text": user_message,
        "timestamp": time.time(),
    })

    # Add to main message stream for display
    add_msg("user", user_message)

    return jsonify({
        "status": "ok",
        "message": "Message added to conversation",
        "chat_count": len(scan_state["chat_messages"]),
    })


@app.route("/api/confirm", methods=["POST"])
@login_required
@_check_csrf
def confirm_action():
    data = request.json
    scan_state["confirm_response"] = data.get("approved", False)
    return jsonify({"status": "ok"})


@app.route("/api/cancel", methods=["POST"])
@login_required
@_check_csrf
def cancel_scan():
    scan_state["running"] = False
    scan_state["phase"] = "idle"
    scan_state["pending_confirm"] = None
    scan_state["confirm_response"] = None
    add_msg("system", "⛔ Escaneo cancelado por el usuario.")
    events.emit_phase_change("idle", running=False)
    return jsonify({"status": "cancelled"})


@app.route("/api/report/generate", methods=["POST"])
@login_required
@_check_csrf
def generate_report_now():
    """Generate report for current scan state (any phase)."""
    if not scan_state["target"]:
        return jsonify({"error": "No hay datos de escaneo"}), 400

    # Build report from whatever data we have so far
    scan_data = _build_scan_data()

    # If we have recon_result or exploit_result, we have enough for a report
    if not scan_state["recon_result"] and not scan_state["exploit_result"]:
        return jsonify({"error": "Ejecuta al menos el reconocimiento primero"}), 400

    return jsonify({
        "status": "ok",
        "report_url": "/api/report/html",
        "json_url": "/api/report/json",
        "pdf_url": "/api/report/pdf",
    })


# ── Phase 1: Attack (Recon + Exploit) ────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required
@_check_csrf
def start_scan():
    if scan_state["running"]:
        return jsonify({"error": "Ya hay un escaneo en curso"}), 400

    data = request.json
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target requerido"}), 400

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Reset state
    scan_state.update({
        "running": True,
        "target": target,
        "phase": "recon",
        "messages": [],
        "recon_result": "",
        "exploit_result": "",
        "remediate_result": "",
        "pending_confirm": None,
        "confirm_response": None,
        "chat_messages": [],
        "scan_id": scan_id,
    })

    # Save scan to database if available
    if get_db:
        try:
            db = get_db()
            db.save_scan(scan_id, target)
        except Exception as e:
            add_msg("system", f"Advertencia: No se pudo guardar escaneo en BD: {e}")

    # Send webhook notification if configured
    if notify:
        try:
            notify("scan_started", {
                "scan_id": scan_id,
                "target": target,
                "timestamp": time.time(),
            })
        except Exception:
            pass

    # Emit phase change
    events.emit_phase_change("recon", running=True)

    thread = threading.Thread(target=_thread_wrapper, args=(_phase_recon, target, scan_id), daemon=True)
    thread.start()
    return jsonify({"status": "started", "scan_id": scan_id})


async def _phase_recon(target: str, scan_id: str = None):
    client = GuardXClient()
    add_msg("system", f"FASE 1 > Reconocimiento de {target}")
    add_msg("system", "Escaneando puertos, servicios, headers, vulnerabilidades...")

    prompt = build_recon_prompt(target)
    result = await client.run_agent_loop(
        system_prompt=prompt,
        on_tool_call=lambda name, params: _on_tool_call_recon(name, params, scan_id),
        on_text=lambda text: _add_msg_and_parse(text),
        on_tool_result=lambda name, dur, ok: events.emit_tool_result(name, dur, ok),
    )
    scan_state["recon_result"] = result
    add_msg("system", "Reconocimiento completo. Click EXPLOIT para validar vulnerabilidades.")
    scan_state["phase"] = "waiting_exploit"
    scan_state["running"] = False
    events.emit_phase_change("waiting_exploit", running=False)

    # Update database
    if get_db and scan_id:
        try:
            db = get_db()
            db.update_scan(scan_id, phase="waiting_exploit")
        except Exception:
            pass


@app.route("/api/exploit", methods=["POST"])
@login_required
@_check_csrf
def start_exploit():
    if scan_state["running"]:
        return jsonify({"error": "Ya hay un proceso en curso"}), 400
    if not scan_state["recon_result"]:
        return jsonify({"error": "Ejecuta el escaneo primero"}), 400

    scan_state["running"] = True
    scan_state["phase"] = "exploit"
    events.emit_phase_change("exploit", running=True)

    thread = threading.Thread(
        target=_thread_wrapper,
        args=(_phase_exploit, scan_state["target"], scan_state["scan_id"]),
        daemon=True,
    )
    thread.start()
    return jsonify({"status": "started"})


async def _phase_exploit(target: str, scan_id: str = None):
    client = GuardXClient()
    add_msg("system", "FASE 1 > Explotacion: validando vulnerabilidades con evidencia real")

    prompt = build_exploit_prompt(target, scan_state["recon_result"])
    result = await client.run_agent_loop(
        system_prompt=prompt,
        on_tool_call=lambda name, params: _on_tool_call_exploit(name, params, scan_id),
        on_text=lambda text: _add_msg_and_parse(text),
        on_tool_result=lambda name, dur, ok: events.emit_tool_result(name, dur, ok),
    )
    scan_state["exploit_result"] = result
    add_msg("system", "Explotacion completa. Click FIX para conectar por SSH y reparar.")
    scan_state["phase"] = "waiting_fix"
    scan_state["running"] = False
    events.emit_phase_change("waiting_fix", running=False)

    # Update database
    if get_db and scan_id:
        try:
            db = get_db()
            db.update_scan(scan_id, phase="waiting_fix")
        except Exception:
            pass


# ── Phase 2: Defense (Remediation via SSH) ────────────────────
@app.route("/api/remediate", methods=["POST"])
@login_required
@_check_csrf
def start_remediate():
    if scan_state["running"]:
        return jsonify({"error": "Ya hay un proceso en curso"}), 400

    data = request.json
    ssh_host = data.get("host") or scan_state["target"]
    ssh_user = data.get("user", "")
    ssh_password = data.get("password", "")
    ssh_key = data.get("key_path", "")

    if not ssh_user:
        return jsonify({"error": "Usuario SSH requerido"}), 400

    # Connect SSH
    conn = get_connection()
    try:
        conn.connect(
            host=ssh_host,
            user=ssh_user,
            password=ssh_password or None,
            key_path=ssh_key or None,
        )
    except Exception as e:
        return jsonify({"error": f"SSH falló: {e}"}), 400

    add_msg("system", f"SSH conectado a {ssh_user}@{ssh_host}")
    scan_state["running"] = True
    scan_state["phase"] = "remediate"
    events.emit_phase_change("remediate", running=True)

    findings = scan_state["exploit_result"] or scan_state["recon_result"]
    thread = threading.Thread(
        target=_thread_wrapper,
        args=(_phase_remediate, scan_state["target"], findings, scan_state["scan_id"]),
        daemon=True,
    )
    thread.start()
    return jsonify({"status": "started"})


async def _phase_remediate(target: str, findings: str, scan_id: str = None):
    client = GuardXClient()
    add_msg("system", "FASE 2 > Defensa: aplicando correcciones")

    def on_confirm(tool_name, description, command):
        events.emit_confirm_request(command, description)
        scan_state["pending_confirm"] = {"command": command, "description": description}

        while scan_state["confirm_response"] is None:
            time.sleep(0.5)

        approved = scan_state["confirm_response"]
        scan_state["confirm_response"] = None
        scan_state["pending_confirm"] = None

        if approved:
            add_msg("fix", f"Ejecutando: {command}")
        else:
            add_msg("system", f"Omitido: {command}")
        return approved

    prompt = build_remediate_prompt(target, findings)
    result = await client.run_agent_loop(
        system_prompt=prompt,
        on_tool_call=lambda name, params: _on_tool_call_remediate(name, params, scan_id),
        on_text=lambda text: add_msg("agent", text),
        on_confirm=on_confirm,
        on_tool_result=lambda name, dur, ok: events.emit_tool_result(name, dur, ok),
    )
    scan_state["remediate_result"] = result

    # Update database
    if get_db and scan_id:
        try:
            db = get_db()
            db.update_scan(scan_id, phase="remediate")
        except Exception:
            pass

    # Auto-trigger Phase 3: Report
    add_msg("system", "FASE 3 > Generando reporte final...")
    scan_state["phase"] = "report"
    events.emit_phase_change("report", running=True)
    await _phase_report(target, scan_id)


# ── Phase 3: Report ──────────────────────────────────────────
async def _phase_report(target: str, scan_id: str = None):
    client = GuardXClient()

    report_prompt = build_report_prompt(
        target=target,
        recon=scan_state["recon_result"],
        exploit=scan_state["exploit_result"],
        remediate=scan_state["remediate_result"],
    )

    result = await client.run_agent_loop(
        system_prompt=report_prompt,
        on_text=lambda text: add_msg("agent", text),
    )
    add_msg("system", "Reporte completo. Escaneo finalizado.")
    scan_state["phase"] = "done"
    scan_state["running"] = False
    events.emit_phase_change("done", running=False)
    events.emit_scan_complete(scan_id or "", target, 0)

    # Update database - mark as complete
    if get_db and scan_id:
        try:
            db = get_db()
            from datetime import datetime
            db.update_scan(scan_id, phase="done", finished_at=datetime.utcnow().isoformat())
        except Exception:
            pass

    # Send completion webhook
    if notify and scan_id:
        try:
            summary = {}
            if get_db:
                db = get_db()
                summary = db.get_scan_summary(scan_id)
            notify("scan_completed", {
                "scan_id": scan_id,
                "target": target,
                "summary": summary,
                "timestamp": time.time(),
            })
        except Exception:
            pass

    # Close SSH
    try:
        get_connection().close()
    except Exception:
        pass


# ── Report Endpoints ──────────────────────────────────────────
@app.route("/api/report/html")
@login_required
def get_html_report():
    """Generate HTML report for current scan."""
    if not generate_report:
        return jsonify({"error": "Report generation not available"}), 500

    scan_data = _build_scan_data()
    try:
        html_report = generate_report(scan_data, fmt="html")
        return html_report, 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500


@app.route("/api/report/json")
@login_required
def get_json_report():
    """Generate JSON report for current scan."""
    if not generate_report:
        return jsonify({"error": "Report generation not available"}), 500

    scan_data = _build_scan_data()
    try:
        json_report = generate_report(scan_data, fmt="json")
        return jsonify(json.loads(json_report))
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500


@app.route("/api/report/pdf")
@login_required
def get_pdf_report():
    """Generate PDF report for current scan."""
    if not generate_report:
        return jsonify({"error": "Report generation not available"}), 500

    scan_data = _build_scan_data()
    try:
        html_report = generate_report(scan_data, fmt="html")
        # Convert HTML to PDF using weasyprint or return HTML with PDF headers
        try:
            from weasyprint import HTML as WeasyHTML
            pdf_bytes = WeasyHTML(string=html_report).write_pdf()
            return pdf_bytes, 200, {
                "Content-Type": "application/pdf",
                "Content-Disposition": f"attachment; filename=guardx-report-{scan_data.get('target', 'scan')}.pdf"
            }
        except ImportError:
            # Fallback: return HTML that auto-prints as PDF
            print_html = html_report.replace("</head>", """
            <style>
                @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
            </style>
            <script>window.onload = function() { window.print(); }</script>
            </head>""")
            return print_html, 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500


# ── History Endpoints ─────────────────────────────────────────
@app.route("/api/history")
@login_required
def get_scan_history():
    """Get all past scans."""
    if not get_db:
        return jsonify({"error": "Database not available"}), 500

    try:
        db = get_db()
        scans = db.get_all_scans()
        return jsonify({
            "scans": scans,
            "total": len(scans),
        })
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve history: {e}"}), 500


@app.route("/api/history/<scan_id>")
@login_required
def get_scan_detail(scan_id):
    """Get details for a specific scan."""
    if not get_db:
        return jsonify({"error": "Database not available"}), 500

    try:
        db = get_db()
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404

        findings = db.get_findings(scan_id)
        actions = db.get_actions(scan_id)
        fixes = db.get_fixes(scan_id)
        summary = db.get_scan_summary(scan_id)

        return jsonify({
            "scan": scan,
            "findings": findings,
            "actions": actions,
            "fixes": fixes,
            "summary": summary,
        })
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve scan: {e}"}), 500


# ── Helpers ──────────────────────────────────────────────────
def _thread_wrapper(coro_func, *args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(coro_func(*args))
    except Exception as e:
        add_msg("system", f"Error: {e}")
        scan_state["running"] = False
    finally:
        loop.close()


def _short_params(params: dict) -> str:
    """Shorten params for display."""
    parts = []
    for k, v in params.items():
        val = str(v)
        if len(val) > 40:
            val = val[:40] + "..."
        parts.append(f"{k}={val}")
    return ", ".join(parts)


def _on_tool_call_recon(name: str, params: dict, scan_id: str = None):
    """Handle tool call during recon phase - log and save to database."""
    events.emit_tool_call(name, params)

    # Save action to database if available
    if get_db and scan_id:
        try:
            db = get_db()
            db.save_action(
                scan_id=scan_id,
                phase="recon",
                tool_name=name,
                tool_input=json.dumps(params),
                tool_output="",
            )
        except Exception:
            pass


def _on_tool_call_exploit(name: str, params: dict, scan_id: str = None):
    """Handle tool call during exploit phase - log and save to database."""
    events.emit_tool_call(name, params)

    # Save action to database if available
    if get_db and scan_id:
        try:
            db = get_db()
            db.save_action(
                scan_id=scan_id,
                phase="exploit",
                tool_name=name,
                tool_input=json.dumps(params),
                tool_output="",
            )
        except Exception:
            pass


def _on_tool_call_remediate(name: str, params: dict, scan_id: str = None):
    """Handle tool call during remediate phase - log and save to database."""
    events.emit_tool_call(name, params)

    # Save action to database if available
    if get_db and scan_id:
        try:
            db = get_db()
            db.save_action(
                scan_id=scan_id,
                phase="remediate",
                tool_name=name,
                tool_input=json.dumps(params),
                tool_output="",
            )
        except Exception:
            pass


def _build_scan_data() -> dict:
    """Build scan data dictionary for report generation."""
    # Parse findings from messages (basic extraction)
    findings = []
    for msg in scan_state["messages"]:
        if msg.get("role") == "finding":
            try:
                finding_data = json.loads(msg.get("text", "{}"))
                findings.append(finding_data)
            except json.JSONDecodeError:
                pass

    # Calculate security scores from findings using compliance module
    score_before = 100
    score_after = 100
    if findings and calculate_risk_score:
        try:
            risk = calculate_risk_score(findings)
            score_before = max(0, int(100 - risk))
            # After remediation, open findings reduce score
            open_findings = [f for f in findings if f.get("status", "open") == "open"]
            risk_after = calculate_risk_score(open_findings) if open_findings else 0
            score_after = max(0, int(100 - risk_after))
        except Exception:
            pass
    elif findings:
        # Fallback scoring: CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        total_penalty = sum(weights.get(f.get("severity", "low"), 3) for f in findings)
        score_before = max(0, 100 - total_penalty)
        score_after = score_before  # Same if no remediation data

    return {
        "target": scan_state["target"],
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "recon_result": scan_state["recon_result"],
        "exploit_result": scan_state["exploit_result"],
        "remediate_result": scan_state["remediate_result"],
        "findings": findings,
        "fixes": [],
        "score_before": score_before,
        "score_after": score_after,
        "phase": scan_state["phase"],
    }


# ── Register API Blueprint ────────────────────────────────────
if api_bp:
    app.register_blueprint(api_bp)

# ── Rollback endpoint ─────────────────────────────────────────
@app.route("/api/rollback", methods=["POST"])
@login_required
@_check_csrf
def rollback_fix():
    """Rollback a specific fix or all fixes."""
    if not get_rollback_manager:
        return jsonify({"error": "Rollback module not available"}), 501

    data = request.json or {}
    backup_path = data.get("backup_path")

    rm = get_rollback_manager()
    if not rm.list_backups():
        return jsonify({"error": "No backups available"}), 404

    # Need SSH connection for rollback
    ssh = get_connection()
    if not ssh:
        return jsonify({"error": "No SSH connection. Connect first via FIX phase."}), 400

    try:
        if backup_path:
            # Find the original file for this backup
            for b in rm.list_backups():
                if b["backup_path"] == backup_path:
                    result = rm.rollback(ssh, b["file_path"], backup_path)
                    add_msg("fix", f"Rollback: {result}")
                    return jsonify({"status": "ok", "result": result})
            return jsonify({"error": "Backup not found"}), 404
        else:
            results = rm.rollback_all(ssh)
            for r in results:
                add_msg("fix", f"Rollback: {r}")
            return jsonify({"status": "ok", "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rollback/list")
@login_required
def list_rollbacks():
    if not get_rollback_manager:
        return jsonify({"backups": []})
    rm = get_rollback_manager()
    return jsonify({"backups": rm.list_backups()})


# ── Scheduler endpoints ───────────────────────────────────────
@app.route("/api/schedules")
@login_required
def list_schedules():
    if not get_scheduler:
        return jsonify({"schedules": []})
    sched = get_scheduler()
    return jsonify({"schedules": sched.list_schedules()})


@app.route("/api/schedules", methods=["POST"])
@login_required
@_check_csrf
def add_schedule():
    if not get_scheduler:
        return jsonify({"error": "Scheduler not available"}), 501
    data = request.json or {}
    target = data.get("target", "").strip()
    cron_expr = data.get("cron", "").strip()
    phases = data.get("phases", ["recon", "exploit"])
    name = data.get("name", "")

    if not target or not cron_expr:
        return jsonify({"error": "target and cron required"}), 400

    sched = get_scheduler()
    try:
        sid = sched.add_schedule(target, cron_expr, phases, name)
        return jsonify({"status": "ok", "schedule_id": sid})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/schedules/<schedule_id>", methods=["DELETE"])
@login_required
@_check_csrf
def remove_schedule(schedule_id):
    if not get_scheduler:
        return jsonify({"error": "Scheduler not available"}), 501
    sched = get_scheduler()
    ok = sched.remove_schedule(schedule_id)
    return jsonify({"status": "ok" if ok else "not_found"})


# ── Delta report endpoint ─────────────────────────────────────
@app.route("/api/delta/<scan_old>/<scan_new>")
@login_required
def delta_report(scan_old, scan_new):
    if not get_delta_reporter or not get_db:
        return jsonify({"error": "Delta report or DB not available"}), 501
    try:
        dr = get_delta_reporter(get_db())
        result = dr.compare(scan_old, scan_new)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Plugins endpoint ──────────────────────────────────────────
@app.route("/api/plugins")
@login_required
def list_plugins():
    if not get_plugin_manager:
        return jsonify({"plugins": []})
    pm = get_plugin_manager()
    return jsonify({"plugins": pm.list_plugins()})


# ── Startup logic (runs for both gunicorn and direct execution) ──
def _startup():
    """Initialize scheduler and print banner."""
    if get_scheduler:
        try:
            sched = get_scheduler()
            sched.start()
        except Exception:
            pass

    # Auto-count tools and skills
    try:
        from guardx.llm.client import TOOLS
        tools_count = len(TOOLS)
    except Exception:
        tools_count = 20
    try:
        from guardx.skills import get_all_skills
        skills_count = len(get_all_skills())
    except Exception:
        skills_count = 26
    port = os.getenv("GUARDX_PORT", "5000")
    print(f"\n  ╔══════════════════════════════════════╗")
    print(f"  ║   GuardX - AI Security Agent v3.0    ║")
    print(f"  ║   {tools_count} tools | {skills_count} skills | WebSocket   ║")
    print(f"  ║   Mode: {_async_mode:<27s} ║")
    print(f"  ║   http://0.0.0.0:{str(port):<19s} ║")
    print(f"  ╚══════════════════════════════════════╝\n")


# Run startup when imported by gunicorn
_startup()


# ── Main (local development) ─────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("GUARDX_PORT", "5000"))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
