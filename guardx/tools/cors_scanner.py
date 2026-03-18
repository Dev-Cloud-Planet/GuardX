"""CORS misconfiguration scanner."""
import urllib.request
import ssl

TOOL_SCHEMA = {
    "name": "cors_scanner",
    "description": (
        "Scan for CORS (Cross-Origin Resource Sharing) misconfigurations. "
        "Tests various origin bypass techniques and classifies vulnerability severity "
        "based on Allow-Origin header and credentials policies."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL e.g. http://example.com"
            },
        },
        "required": ["url"],
    },
}


def is_available() -> bool:
    return True


def _test_cors(url: str, origin: str) -> dict:
    """Test CORS with a specific origin header."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {
        "origin": origin,
        "allow_origin": None,
        "allow_credentials": False,
        "allow_methods": None,
        "allow_headers": None,
        "status": None,
        "accessible": False,
    }

    try:
        req = urllib.request.Request(url, method="OPTIONS")
        req.add_header("User-Agent", "GuardX-CORSScanner/0.1")
        req.add_header("Origin", origin)

        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            result["status"] = resp.status
            result["accessible"] = resp.status < 400

            # Get CORS headers
            headers = {k.lower(): v for k, v in resp.headers.items()}
            result["allow_origin"] = headers.get("access-control-allow-origin")
            result["allow_credentials"] = headers.get("access-control-allow-credentials", "").lower() == "true"
            result["allow_methods"] = headers.get("access-control-allow-methods")
            result["allow_headers"] = headers.get("access-control-allow-headers")

    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            headers = {k.lower(): v for k, v in e.headers.items()}
            result["allow_origin"] = headers.get("access-control-allow-origin")
            result["allow_credentials"] = headers.get("access-control-allow-credentials", "").lower() == "true"
            result["allow_methods"] = headers.get("access-control-allow-methods")
            result["allow_headers"] = headers.get("access-control-allow-headers")
        except Exception:
            pass
    except Exception as e:
        pass

    return result


def _classify_severity(results: list) -> tuple[str, list]:
    """Classify CORS vulnerability severity based on test results."""
    findings = []

    # Check for wildcard + credentials (CRITICAL)
    for r in results:
        if r["allow_origin"] == "*" and r["allow_credentials"]:
            findings.append(("CRITICAL", f"Wildcard origin (*) + credentials allowed - complete compromise", r))
        elif r["allow_origin"] == "*":
            if r["allow_methods"] and ("POST" in r["allow_methods"] or "PUT" in r["allow_methods"]):
                findings.append(("HIGH", f"Wildcard origin (*) with state-changing methods allowed", r))
            else:
                findings.append(("MEDIUM", f"Wildcard origin (*) allowed", r))

    # Check for origin reflection (can be dangerous)
    for r in results:
        if r["allow_origin"] and r["allow_origin"] != "*":
            if r["origin"] in r["allow_origin"]:
                # Origin was reflected
                if r["allow_credentials"]:
                    findings.append(("CRITICAL", f"Origin reflected + credentials - bypassed SOP", r))
                else:
                    findings.append(("MEDIUM", f"Origin reflected without credentials", r))

    # Check for null origin (can bypass some checks)
    for r in results:
        if r["origin"] == "null" and r["allow_origin"] == "null":
            if r["allow_credentials"]:
                findings.append(("HIGH", f"null origin allowed with credentials", r))
            else:
                findings.append(("MEDIUM", f"null origin allowed", r))

    # Check for subdomain bypass
    for r in results:
        if r["origin"].endswith(".target.com") and r["allow_origin"]:
            findings.append(("MEDIUM", f"Subdomain bypass may be possible", r))

    # Check for scheme bypass
    for r in results:
        if r["origin"].startswith("http://") and r["allow_origin"] and "https://" not in r["origin"]:
            if "https" in r["allow_origin"]:
                findings.append(("MEDIUM", f"Scheme mismatch may indicate flexible CORS", r))

    # Classify overall risk
    if any(sev == "CRITICAL" for sev, _, _ in findings):
        overall = "CRITICAL"
    elif any(sev == "HIGH" for sev, _, _ in findings):
        overall = "HIGH"
    elif any(sev == "MEDIUM" for sev, _, _ in findings):
        overall = "MEDIUM"
    else:
        overall = "LOW"

    return overall, findings


async def execute(params: dict) -> str:
    url = params.get("url", "").strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    # Parse base URL to get domain
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_domain = parsed.hostname or "example.com"

    # Test different origin scenarios
    origins_to_test = [
        "https://evil.com",
        "http://evil.com",
        "null",
        f"https://{base_domain}",
        f"http://{base_domain}",
        f"https://sub.{base_domain}",
        f"https://{base_domain}.evil.com",
        f"https://evil.com",
        "https://localhost",
        "http://localhost",
    ]

    lines = [
        f"=== CORS Scanner Results ===",
        f"Target: {url}",
        "",
    ]

    results = []
    for origin in origins_to_test:
        result = _test_cors(url, origin)
        if result["status"]:
            results.append(result)

    # Classify findings
    severity, findings = _classify_severity(results)

    lines.append(f"Overall Severity: {severity}")
    lines.append("")

    if findings:
        lines.append("--- Findings ---")
        seen = set()
        for sev, desc, result in findings:
            key = (sev, desc)
            if key not in seen:
                seen.add(key)
                lines.append(f"[{sev}] {desc}")
                lines.append(f"  Origin: {result['origin']}")
                lines.append(f"  Access-Control-Allow-Origin: {result['allow_origin']}")
                if result["allow_credentials"]:
                    lines.append(f"  Access-Control-Allow-Credentials: true")
                if result["allow_methods"]:
                    lines.append(f"  Methods: {result['allow_methods']}")
                lines.append("")
    else:
        lines.append("--- Testing Summary ---")
        lines.append("No CORS vulnerabilities detected in tested origins")
        lines.append("")

    # Show all responses
    lines.append("--- All CORS Test Results ---")
    for r in results:
        status_str = f"HTTP {r['status']}" if r["status"] else "No response"
        allow_str = r["allow_origin"] or "Not present"
        cred_str = " (with credentials)" if r["allow_credentials"] else ""
        lines.append(f"  {r['origin']:30} -> {allow_str:30} {status_str}{cred_str}")

    return "\n".join(lines)
