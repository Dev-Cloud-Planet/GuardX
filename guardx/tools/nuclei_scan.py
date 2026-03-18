"""Nuclei vulnerability scanner tool."""
import shutil
import json
from guardx.utils.subprocess_runner import run


TOOL_SCHEMA = {
    "name": "nuclei_scan",
    "description": (
        "Run nuclei vulnerability scanner against a target. "
        "Detects CVEs, misconfigurations, exposures using templates."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL or IP"},
            "templates": {
                "type": "string",
                "description": "Template tags: cves,misconfig,exposure,tech",
                "default": "cves,misconfig",
            },
            "severity": {
                "type": "string",
                "description": "Filter by severity: critical,high,medium,low",
                "default": "critical,high,medium",
            },
        },
        "required": ["target"],
    },
}


def is_available() -> bool:
    return shutil.which("nuclei") is not None


async def execute(params: dict) -> str:
    target = params["target"]
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    templates = params.get("templates", "cves,misconfig")
    severity = params.get("severity", "critical,high,medium")

    args = [
        "nuclei",
        "-u", target,
        "-tags", templates,
        "-severity", severity,
        "-jsonl",
        "-silent",
        "-timeout", "10",
    ]

    result = await run(args, timeout=300)
    if result.returncode != 0 and not result.stdout:
        return f"Nuclei error: {result.stderr}"

    findings = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            findings.append(
                f"[{data.get('info', {}).get('severity', '?').upper()}] "
                f"{data.get('info', {}).get('name', '?')} - "
                f"{data.get('matched-at', '?')}"
            )
        except json.JSONDecodeError:
            continue

    if not findings:
        return "Nuclei: No vulnerabilities found with current templates."

    return "Nuclei findings:\n" + "\n".join(findings)
