"""Subdomain enumeration via certificate transparency and DNS resolution."""
import urllib.request
import urllib.parse
import ssl
import socket
import json

TOOL_SCHEMA = {
    "name": "subdomain_enum",
    "description": (
        "Enumerate subdomains using certificate transparency logs (crt.sh) "
        "and common subdomain wordlist with DNS resolution. "
        "Returns active subdomains with IP addresses."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Target domain e.g. example.com"
            },
            "use_crtsh": {
                "type": "boolean",
                "description": "Query certificate transparency logs",
                "default": True,
            },
        },
        "required": ["domain"],
    },
}

# Common subdomains to bruteforce
COMMON_SUBDOMAINS = [
    "www", "dev", "staging", "api", "admin", "mail", "test", "beta",
    "internal", "vpn", "cdn", "app", "portal", "shop", "blog", "docs",
    "git", "ci", "monitor", "grafana", "jenkins", "jira", "wiki",
    "confluence", "sso", "auth", "oauth", "m", "mobile", "api-test",
    "api-dev", "api-staging", "backup", "db", "database", "ftp", "sftp",
    "imap", "pop", "smtp", "old", "archive", "temp", "tmp", "static",
    "assets", "images", "downloads", "files", "upload", "admin-panel",
    "management", "control", "dashboard", "status", "health", "metrics"
]


def is_available() -> bool:
    return True


def _query_crtsh(domain: str) -> set[str]:
    """Query crt.sh for certificate transparency entries."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "GuardX-SubdomainEnum/0.1")

        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))

            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name_value = entry.get("name_value", "")
                        # Split multiple SANs
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name and name.endswith("." + domain):
                                subdomains.add(name)
    except Exception as e:
        pass  # crt.sh may fail or rate limit, continue with wordlist

    return subdomains


def _resolve_subdomain(subdomain: str) -> str | None:
    """Try to resolve a subdomain to an IP."""
    try:
        result = socket.getaddrinfo(subdomain, 80, socket.AF_INET, socket.SOCK_STREAM)
        if result:
            # Return first IP
            return result[0][4][0]
    except (socket.gaierror, socket.error, OSError):
        pass
    return None


def _check_http_response(subdomain: str) -> bool:
    """Check if HTTP responds on the subdomain."""
    try:
        url = f"http://{subdomain}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "GuardX-SubdomainEnum/0.1")

        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return resp.status < 400
    except Exception:
        return False


async def execute(params: dict) -> str:
    domain = params.get("domain", "").strip().lower()
    use_crtsh = params.get("use_crtsh", True)

    if not domain or "." not in domain:
        return f"Invalid domain: {domain}"

    found_subdomains = set()

    # Query cert transparency if enabled
    if use_crtsh:
        found_subdomains.update(_query_crtsh(domain))

    # Bruteforce common subdomains
    for sub in COMMON_SUBDOMAINS:
        subdomain = f"{sub}.{domain}"
        ip = _resolve_subdomain(subdomain)
        if ip:
            found_subdomains.add(subdomain)

    if not found_subdomains:
        return f"No subdomains found for {domain}"

    # Resolve and check HTTP for each found subdomain
    lines = [
        f"=== Subdomain Enumeration Results for {domain} ===",
        f"Found {len(found_subdomains)} subdomains",
        "",
        "--- Subdomains with HTTP ---"
    ]

    results = []
    for subdomain in sorted(found_subdomains):
        ip = _resolve_subdomain(subdomain)
        if ip:
            http_ok = _check_http_response(subdomain)
            status = "[HTTP OK]" if http_ok else "[RESOLVES]"
            results.append((subdomain, ip, status))
            lines.append(f"  {subdomain:40} {ip:20} {status}")

    if results:
        lines.append(f"\nTotal active subdomains: {len(results)}")
    else:
        lines.append("No subdomains resolved.")

    return "\n".join(lines)
