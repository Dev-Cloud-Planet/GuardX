"""GuardX Event Bus - Real-time event system via WebSocket."""
import json
import time
import threading


class EventBus:
    """Central event emitter for real-time WebSocket communication."""

    def __init__(self, socketio=None, scan_state=None):
        self._sio = socketio
        self._state = scan_state or {"messages": []}
        self._lock = threading.Lock()

    def set_socketio(self, sio):
        self._sio = sio

    def set_state(self, state):
        self._state = state

    def _emit(self, event, data):
        """Emit event via SocketIO and append to buffer."""
        with self._lock:
            self._state.setdefault("messages", []).append({
                "role": data.get("role", "system"),
                "text": data.get("text", ""),
                "event": event,
                "timestamp": time.time(),
            })
        if self._sio:
            try:
                self._sio.emit(event, data, namespace="/", to="scan")
            except Exception:
                pass

    def emit_message(self, role, text):
        self._emit("guardx:message", {"role": role, "text": text})

    def emit_phase_change(self, phase, running=True):
        self._emit("guardx:phase", {"phase": phase, "running": running, "role": "system", "text": f"Phase: {phase}"})

    def emit_tool_call(self, name, params):
        short = ", ".join(f"{k}={str(v)[:40]}..." if len(str(v)) > 40 else f"{k}={v}" for k, v in params.items())
        self._emit("guardx:tool", {"name": name, "params": params, "role": "tool", "text": f"{name}({short})"})

    def emit_tool_result(self, name, duration, success=True):
        status = "OK" if success else "FAIL"
        self._emit("guardx:tool_result", {"name": name, "duration": round(duration, 2), "success": success, "role": "tool", "text": f"{name} [{status} {duration:.1f}s]"})

    def emit_finding(self, severity, title, evidence=""):
        self._emit("guardx:finding", {"severity": severity, "title": title, "evidence": evidence, "role": "finding", "text": json.dumps({"severity": severity, "title": title, "evidence": evidence})})

    def emit_progress(self, phase, step, total, description=""):
        pct = int((step / total) * 100) if total > 0 else 0
        self._emit("guardx:progress", {"phase": phase, "step": step, "total": total, "percent": pct, "description": description, "role": "system", "text": f"[{pct}%] {description}"})

    def emit_confirm_request(self, command, description):
        self._emit("guardx:confirm", {"command": command, "description": description, "role": "confirm", "text": json.dumps({"command": command, "description": description})})

    def emit_scan_complete(self, scan_id, target, duration=0):
        self._emit("guardx:complete", {"scan_id": scan_id, "target": target, "duration": round(duration, 2), "role": "system", "text": f"Scan complete: {target} ({duration:.1f}s)"})

    def clear(self):
        with self._lock:
            self._state["messages"] = []


# Singleton
_event_bus = None

def get_event_bus(socketio=None, scan_state=None):
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus(socketio, scan_state)
    if socketio:
        _event_bus.set_socketio(socketio)
    if scan_state:
        _event_bus.set_state(scan_state)
    return _event_bus
