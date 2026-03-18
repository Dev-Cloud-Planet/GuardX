"""HTTP security headers analyzer. Pure Python, no external deps."""
import urllib.request
import ssl

TOOL_SCHEMA = {
    "name": "http_headers_check",
    "description": (
        "Check HTTP security headers of a target URL. "
        "Detects missing headers like HSTS, CSP, X-Frame-Options, etc."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL e.g. http://example.com"},
        },
        "required": ["url"],
    },
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS - Protects against downgrade attacks",
    "Content-Security-Policy": "CSP - Prevents XSS and injection",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-XSS-Protection": "Legacy XSS filter",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features",
    "Cross-Origin-Opener-Policy": "Isolates browsing context",
    "Cross-Origin-Resource-Policy": "Controls cross-origin reads",
}


def is_available() -> bool:
    return True


async def execute(params: dict) -> str:
    url = params["url"]
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "GuardX-Scanner/0.1")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
    except Exception as e:
        return f"Error connecting to {url}: {e}"

    lines = [f"URL: {url} (HTTP {status})", "", "Security Headers:"]

    missing = []
    present = []
    for header, desc in SECURITY_HEADERS.items():
        val = headers.get(header.lower())
        if val:
            present.append(f"  [OK] {header}: {val}")
        else:
            missing.append(f"  [MISSING] {header} - {desc}")

    lines.extend(present)
    lines.extend(missing)
    lines.append(f"\nScore: {len(present)}/{len(SECURITY_HEADERS)} headers present")

    if headers.get("server"):
        lines.append(f"\n[WARN] Server header exposed: {headers['server']}")

    return "\n".join(lines)
