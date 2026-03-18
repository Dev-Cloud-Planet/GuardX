"""Nmap scanner tool."""
import shutil
from defusedxml import ElementTree as ET
from guardx.utils.subprocess_runner import run, RunResult


TOOL_SCHEMA = {
    "name": "nmap_scan",
    "description": (
        "Run nmap against a target. Returns open ports, services, versions. "
        "scan_type: quick (top 100 ports), full (all ports), service (top 100 + service detection). "
        "If ports is specified, it overrides the default port selection for that scan_type."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP or hostname"},
            "scan_type": {
                "type": "string",
                "enum": ["quick", "full", "service"],
                "default": "quick",
                "description": "quick: -F (top 100), full: -p- (all ports), service: -F + service detection"
            },
            "ports": {"type": "string", "description": "Optional port range (e.g. 1-1000 or 22,80,443). Overrides the default port selection."},
        },
        "required": ["target"],
    },
}

SCAN_ARGS = {
    "quick": "-Pn -T4 -F --host-timeout 3m",
    "full": "-Pn -p- -sV -T4 --host-timeout 10m",
    "service": "-Pn -sV -sC -T4 -F --host-timeout 5m",
}


def is_available() -> bool:
    return shutil.which("nmap") is not None


async def execute(params: dict) -> str:
    target = params["target"]
    scan_type = params.get("scan_type", "quick")
    ports = params.get("ports")

    args = ["nmap"] + SCAN_ARGS.get(scan_type, SCAN_ARGS["quick"]).split()

    # If ports is explicitly provided, remove conflicting flags
    if ports:
        # Remove -F (fast scan) flag
        if "-F" in args:
            args.remove("-F")
        # Remove -p- (all ports) flag
        if "-p-" in args:
            args.remove("-p-")
        # Add explicit port specification
        args += ["-p", ports]

    args += ["-oX", "-", target]

    result = await run(args, timeout=600)
    if result.returncode != 0:
        return f"Nmap error: {result.stderr}"

    return _parse_xml(result.stdout)


def _parse_xml(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text.encode("utf-8"))
    except Exception as e:
        return f"Failed to parse nmap XML: {e}"

    lines = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr", "unknown") if addr is not None else "unknown"
        state_el = host.find("status")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        lines.append(f"\nHost: {ip} ({state})")

        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            portid = port.get("portid", "?")
            protocol = port.get("protocol", "?")
            state_el = port.find("state")
            port_state = state_el.get("state", "?") if state_el is not None else "?"
            service = port.find("service")
            svc_name = service.get("name", "?") if service is not None else "?"
            svc_ver = service.get("version", "") if service is not None else ""
            lines.append(f"  {portid}/{protocol}  {port_state}  {svc_name} {svc_ver}".rstrip())

    return "\n".join(lines) if lines else "No hosts found or all ports filtered."
