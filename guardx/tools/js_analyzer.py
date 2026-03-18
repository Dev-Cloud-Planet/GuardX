"""JavaScript static analyzer for secrets, endpoints, and source maps."""
import urllib.request
import urllib.parse
import ssl
import re
from html.parser import HTMLParser

TOOL_SCHEMA = {
    "name": "js_analyzer",
    "description": (
        "Analyze JavaScript files for hardcoded secrets (API keys, tokens), "
        "exposed internal URLs, API endpoints, and source maps. "
        "Extracts all script sources from HTML and analyzes their content."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL e.g. http://example.com"
            },
            "max_files": {
                "type": "integer",
                "description": "Maximum JS files to analyze",
                "default": 20,
            },
        },
        "required": ["url"],
    },
}

# Regex patterns for secrets and vulnerabilities
PATTERNS = {
    "api_keys": (
        r"(?:api[_-]?key|apikey|api_secret|api-secret)[\s]*[:=][\s]*['\"]([a-zA-Z0-9]{20,})['\"]",
        "API Key"
    ),
    "aws_keys": (
        r"(AKIA[0-9A-Z]{16})",
        "AWS Access Key"
    ),
    "tokens": (
        r"(?:token|secret|password|jwt|bearer|auth|authorization)[\s]*[:=][\s]*['\"]([^\s'\"]{8,})['\"]",
        "Token/Secret"
    ),
    "internal_urls": (
        r"https?://(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s'\"<>]*",
        "Internal URL"
    ),
    "api_endpoints": (
        r"(?:fetch|axios|XMLHttpRequest|\.ajax|\.get|\.post)\s*\(\s*['\"`]([/\w\-\.]+)['\"`]",
        "API Endpoint"
    ),
    "private_keys": (
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "Private Key"
    ),
    "hardcoded_urls": (
        r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+[^\s'\"<>]*",
        "Hardcoded URL"
    ),
}


def is_available() -> bool:
    return True


class _ScriptExtractor(HTMLParser):
    """Extract script src URLs from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.scripts = set()

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            attrs_dict = dict(attrs)
            src = attrs_dict.get("src")
            if src:
                # Resolve relative URLs
                resolved = urllib.parse.urljoin(self.base_url, src)
                self.scripts.add(resolved)


def _fetch_page(url: str, timeout: int = 10) -> str | None:
    """Fetch a page and return HTML body."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "GuardX-JSAnalyzer/0.1")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(500_000).decode("utf-8", errors="replace")
    except Exception:
        return None


def _fetch_js(url: str, max_size: int = 500_000) -> str | None:
    """Fetch JavaScript file with size limit."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "GuardX-JSAnalyzer/0.1")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "javascript" not in content_type and not url.endswith(".js"):
                return None
            return resp.read(max_size).decode("utf-8", errors="replace")
    except Exception:
        return None


def _analyze_js(js_content: str) -> dict:
    """Analyze JavaScript content for secrets and vulnerabilities."""
    findings = {
        "api_keys": [],
        "aws_keys": [],
        "tokens": [],
        "internal_urls": [],
        "api_endpoints": [],
        "private_keys": [],
        "hardcoded_urls": [],
        "source_maps": [],
    }

    # Check for source maps
    if "sourceMappingURL=" in js_content:
        maps = re.findall(r"//# sourceMappingURL=([^\n\r]+)", js_content)
        findings["source_maps"].extend(maps)

    # Run each pattern
    for pattern_key, (pattern, desc) in PATTERNS.items():
        try:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                for match in matches:
                    # Avoid false positives - check if it's not obviously a placeholder
                    if isinstance(match, str):
                        if match not in ["test", "example", "placeholder", "secret", "token", "key"]:
                            findings[pattern_key].append(match[:100])  # Limit to 100 chars
                    elif isinstance(match, tuple):
                        findings[pattern_key].append(str(match[0])[:100])
        except Exception:
            pass

    return findings


def _same_domain(script_url: str, base_url: str) -> bool:
    """Check if script is from same domain."""
    try:
        script_parsed = urllib.parse.urlparse(script_url)
        base_parsed = urllib.parse.urlparse(base_url)
        return script_parsed.hostname == base_parsed.hostname or script_url.startswith("/")
    except Exception:
        return False


async def execute(params: dict) -> str:
    base_url = params.get("url", "").strip()
    max_files = min(params.get("max_files", 20), 50)

    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    # Fetch main page
    html = _fetch_page(base_url)
    if not html:
        return f"Cannot fetch {base_url}"

    # Extract script sources
    extractor = _ScriptExtractor(base_url)
    try:
        extractor.feed(html)
    except Exception:
        pass

    # Filter to same domain only
    scripts = [s for s in extractor.scripts if _same_domain(s, base_url)]
    scripts = list(scripts)[:max_files]

    if not scripts:
        return f"No scripts found on {base_url}"

    lines = [
        f"=== JavaScript Analyzer Results ===",
        f"URL: {base_url}",
        f"Scripts analyzed: {len(scripts)}",
        "",
    ]

    all_findings = {
        "api_keys": [],
        "aws_keys": [],
        "tokens": [],
        "internal_urls": [],
        "api_endpoints": [],
        "private_keys": [],
        "hardcoded_urls": [],
        "source_maps": [],
    }

    analyzed_count = 0

    # Analyze each script
    for script_url in scripts:
        js_content = _fetch_js(script_url)
        if not js_content:
            continue

        analyzed_count += 1
        findings = _analyze_js(js_content)

        # Aggregate findings
        for key in all_findings:
            all_findings[key].extend(findings[key])

    lines.append(f"Successfully analyzed: {analyzed_count}/{len(scripts)} scripts")
    lines.append("")

    # Report findings
    has_findings = False

    if all_findings["private_keys"]:
        has_findings = True
        lines.append(f"[CRITICAL] Private Keys found: {len(all_findings['private_keys'])}")
        for key in all_findings["private_keys"][:5]:
            lines.append(f"  - {key[:80]}")

    if all_findings["aws_keys"]:
        has_findings = True
        lines.append(f"[CRITICAL] AWS Keys found: {len(all_findings['aws_keys'])}")
        for key in all_findings["aws_keys"][:5]:
            lines.append(f"  - {key}")

    if all_findings["api_keys"]:
        has_findings = True
        lines.append(f"[HIGH] API Keys found: {len(all_findings['api_keys'])}")
        for key in all_findings["api_keys"][:5]:
            lines.append(f"  - {key[:80]}")

    if all_findings["tokens"]:
        has_findings = True
        lines.append(f"[HIGH] Tokens/Secrets found: {len(all_findings['tokens'])}")
        for token in set(all_findings["tokens"])[:5]:
            lines.append(f"  - {token[:80]}")

    if all_findings["internal_urls"]:
        has_findings = True
        lines.append(f"[MEDIUM] Internal URLs found: {len(set(all_findings['internal_urls']))}")
        for url in set(all_findings["internal_urls"])[:5]:
            lines.append(f"  - {url[:100]}")

    if all_findings["api_endpoints"]:
        has_findings = True
        unique_endpoints = set(all_findings["api_endpoints"])
        lines.append(f"[INFO] API Endpoints found: {len(unique_endpoints)}")
        for ep in sorted(unique_endpoints)[:10]:
            lines.append(f"  - {ep[:80]}")

    if all_findings["source_maps"]:
        has_findings = True
        lines.append(f"[MEDIUM] Source Maps found: {len(set(all_findings['source_maps']))}")
        for sm in set(all_findings["source_maps"])[:5]:
            lines.append(f"  - {sm[:100]}")

    if not has_findings:
        lines.append("No secrets or vulnerabilities detected in analyzed scripts")

    return "\n".join(lines)
