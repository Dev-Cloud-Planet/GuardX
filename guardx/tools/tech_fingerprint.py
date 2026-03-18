"""Technology fingerprinting tool. Identifies the tech stack of a target."""
import urllib.request
import urllib.parse
import ssl
import re

TOOL_SCHEMA = {
    "name": "tech_fingerprint",
    "description": (
        "Identify technologies used by a website: frameworks, CMS, languages, "
        "servers, CDNs, JS libraries. Analyzes headers, HTML, cookies, and known paths. "
        "This changes the attack strategy completely."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL e.g. http://example.com"},
        },
        "required": ["url"],
    },
}

# ── Fingerprint signatures ─────────────────────────────────

# Headers that reveal technology
HEADER_SIGNATURES = {
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js (Node.js)",
        "servlet": "Java Servlet",
        "django": "Django",
        "flask": "Flask",
        "ruby": "Ruby",
        "perl": "Perl",
        "next.js": "Next.js",
    },
    "server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "iis": "Microsoft IIS",
        "litespeed": "LiteSpeed",
        "caddy": "Caddy",
        "gunicorn": "Gunicorn (Python)",
        "uvicorn": "Uvicorn (Python ASGI)",
        "openresty": "OpenResty (Nginx+Lua)",
        "cloudflare": "Cloudflare",
        "amazons3": "Amazon S3",
        "gws": "Google Web Server",
    },
    "x-aspnet-version": {"": "ASP.NET"},
    "x-generator": {
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "ghost": "Ghost CMS",
    },
}

# Cookie names that reveal technology
COOKIE_SIGNATURES = {
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "jsessionid": "Java (Tomcat/Spring)",
    "csrftoken": "Django",
    "laravel_session": "Laravel (PHP)",
    "_rails": "Ruby on Rails",
    "connect.sid": "Express.js (Node.js)",
    "ci_session": "CodeIgniter (PHP)",
    "cakephp": "CakePHP",
    "wp-settings": "WordPress",
    "_gh_sess": "GitHub",
    "rack.session": "Ruby Rack",
    "flask": "Flask",
    "session": "Generic session cookie",
}

# HTML patterns
HTML_SIGNATURES = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', "CMS/Generator"),
    (r'wp-content/', "WordPress"),
    (r'wp-includes/', "WordPress"),
    (r'/sites/default/files/', "Drupal"),
    (r'Joomla!', "Joomla"),
    (r'data-reactroot', "React"),
    (r'__next', "Next.js"),
    (r'_nuxt/', "Nuxt.js (Vue)"),
    (r'ng-version="([^"]+)"', "Angular"),
    (r'ng-app', "AngularJS (legacy)"),
    (r'__vue', "Vue.js"),
    (r'svelte', "Svelte"),
    (r'ember', "Ember.js"),
    (r'cdn\.shopify\.com', "Shopify"),
    (r'squarespace\.com', "Squarespace"),
    (r'wix\.com', "Wix"),
    (r'gatsby', "Gatsby"),
    (r'/static/django', "Django"),
    (r'flask', "Flask"),
    (r'laravel', "Laravel"),
    (r'bootstrap', "Bootstrap CSS"),
    (r'tailwindcss\|tailwind', "Tailwind CSS"),
    (r'jquery', "jQuery"),
    (r'analytics\.js\|gtag', "Google Analytics"),
    (r'cloudflare', "Cloudflare"),
    (r'recaptcha', "Google reCAPTCHA"),
]

# Known paths to probe
PATH_SIGNATURES = {
    "/wp-login.php": "WordPress",
    "/wp-json/wp/v2/": "WordPress REST API",
    "/admin/login/": "Django Admin",
    "/api/swagger.json": "Swagger API",
    "/api-docs": "API Documentation",
    "/graphql": "GraphQL",
    "/xmlrpc.php": "WordPress XML-RPC",
    "/phpmyadmin/": "phpMyAdmin",
    "/server-info": "Apache Server Info",
    "/elmah.axd": "ASP.NET ELMAH",
    "/actuator/health": "Spring Boot Actuator",
    "/package.json": "Node.js (exposed)",
    "/composer.json": "PHP Composer (exposed)",
}

# CDN/WAF/Hosting headers
INFRA_HEADERS = {
    "cf-ray": "Cloudflare CDN",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-request-id": "AWS S3",
    "x-azure-ref": "Azure CDN",
    "x-vercel-id": "Vercel",
    "x-netlify-request-id": "Netlify",
    "fly-request-id": "Fly.io",
    "x-render-origin-server": "Render",
    "x-heroku-queue-depth": "Heroku",
    "x-github-request-id": "GitHub Pages",
    "x-firebase-hosting": "Firebase Hosting",
}


def is_available() -> bool:
    return True


def _fetch(url: str, method: str = "GET", timeout: int = 8) -> dict | None:
    """Fetch URL and return headers + body."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "GuardX-Fingerprint/0.1")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = ""
            if method == "GET":
                body = resp.read(200_000).decode("utf-8", errors="replace")
            return {"headers": headers, "body": body, "status": resp.status}
    except Exception:
        return None


def _probe_path(base_url: str, path: str) -> bool:
    """Check if a path exists (200 or 301/302)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"{base_url.rstrip('/')}{path}"
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "GuardX-Fingerprint/0.1")
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return resp.status in (200, 301, 302, 307)
    except urllib.error.HTTPError as e:
        return e.code in (200, 301, 302, 307, 401, 403)
    except Exception:
        return False


async def execute(params: dict) -> str:
    url = params["url"]
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    technologies = {}  # name -> evidence
    infra = {}  # infra component -> evidence

    # 1. Fetch main page
    result = _fetch(url)
    if result is None:
        return f"Could not connect to {url}"

    headers = result["headers"]
    body = result["body"]

    # 2. Analyze headers
    for header_name, sigs in HEADER_SIGNATURES.items():
        val = headers.get(header_name, "").lower()
        if val:
            for keyword, tech in sigs.items():
                if not keyword or keyword in val:
                    evidence = f"Header {header_name}: {headers.get(header_name, '')}"
                    if tech not in technologies:
                        technologies[tech] = evidence

    # 3. Infrastructure headers
    for header_name, component in INFRA_HEADERS.items():
        if header_name in headers:
            infra[component] = f"Header: {header_name}"

    # 4. Analyze cookies
    cookies = headers.get("set-cookie", "").lower()
    for cookie_name, tech in COOKIE_SIGNATURES.items():
        if cookie_name in cookies:
            technologies[tech] = f"Cookie: {cookie_name}"

    # 5. Analyze HTML body
    body_lower = body.lower()
    for pattern, tech in HTML_SIGNATURES:
        match = re.search(pattern, body_lower)
        if match:
            evidence = f"HTML pattern: {pattern}"
            if match.groups():
                evidence = f"HTML: {match.group(1)}"
            if tech not in technologies:
                technologies[tech] = evidence

    # 6. Probe known paths
    for path, tech in PATH_SIGNATURES.items():
        if tech not in technologies:
            if _probe_path(url, path):
                technologies[tech] = f"Path exists: {path}"

    # 7. Version extraction from headers
    versions = {}
    server = headers.get("server", "")
    if server:
        ver_match = re.search(r'[\d]+\.[\d]+[\.\d]*', server)
        if ver_match:
            versions["Server"] = f"{server} (v{ver_match.group()})"

    powered = headers.get("x-powered-by", "")
    if powered:
        versions["Runtime"] = powered

    # Build output
    lines = [
        f"=== Technology Fingerprint for {url} ===",
        f"HTTP Status: {result['status']}",
        "",
    ]

    if technologies:
        lines.append(f"--- Technologies Detected ({len(technologies)}) ---")
        for tech, evidence in sorted(technologies.items()):
            lines.append(f"  [{tech}] - {evidence}")
    else:
        lines.append("No specific technologies detected.")

    if infra:
        lines.append(f"\n--- Infrastructure ---")
        for component, evidence in sorted(infra.items()):
            lines.append(f"  [{component}] - {evidence}")

    if versions:
        lines.append(f"\n--- Version Information ---")
        for what, ver in versions.items():
            lines.append(f"  {what}: {ver}")

    # Security observations
    observations = []
    if "x-powered-by" in headers:
        observations.append("[WARN] X-Powered-By header exposes technology - should be removed")
    if "server" in headers and re.search(r'[\d]+\.[\d]+', headers["server"]):
        observations.append("[WARN] Server header exposes version number")
    if "WordPress" in technologies:
        observations.append("[INFO] WordPress detected - check for plugin vulnerabilities")
    if "phpMyAdmin" in technologies:
        observations.append("[CRITICAL] phpMyAdmin accessible - major security risk")
    if any("exposed" in t.lower() for t in technologies):
        observations.append("[HIGH] Sensitive files exposed publicly")

    if observations:
        lines.append(f"\n--- Security Observations ---")
        for obs in observations:
            lines.append(f"  {obs}")

    return "\n".join(lines)
