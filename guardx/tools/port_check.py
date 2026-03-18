"""Fast port check using Python sockets. No external deps."""
import socket

TOOL_SCHEMA = {
    "name": "port_check",
    "description": "Quick TCP port check on a target. Faster than nmap for basic checks.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP or hostname"},
            "ports": {
                "type": "string",
                "description": "Comma-separated ports e.g. 22,80,443,3306,8080",
                "default": "21,22,80,443,3306,5432,8080,8443,27017",
            },
        },
        "required": ["target"],
    },
}


def is_available() -> bool:
    return True


async def execute(params: dict) -> str:
    target = params["target"]
    ports_str = params.get("ports", "21,22,80,443,3306,5432,8080,8443,27017")

    try:
        ports = [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        return "Invalid ports format. Use comma-separated numbers."

    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"
        except socket.gaierror:
            return f"Cannot resolve hostname: {target}"
        except Exception:
            status = "ERROR"
        finally:
            sock.close()
        if status == "OPEN":
            results.append(f"  {port}/tcp  OPEN")

    if not results:
        return f"No open ports found on {target} (checked: {ports_str})"

    return f"Open ports on {target}:\n" + "\n".join(results)
