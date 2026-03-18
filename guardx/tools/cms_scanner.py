"""CMS vulnerability scanner for WordPress, Joomla, and Drupal."""
import urllib.request
import urllib.parse
import ssl
import json
import re

TOOL_SCHEMA = {
    "name": "cms_scanner",
    "description": (
        "Detect and scan CMS platforms (WordPress, Joomla, Drupal) for "
        "known vulnerabilities, plugin enumeration, user enumeration, "
        "and common security misconfigurations."
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

# Common WordPress plugins to check
WP_PLUGINS = [
    "contact-form-7", "woocommerce", "elementor", "yoast-seo", "akismet",
    "wordfence", "jetpack", "wp-super-cache", "all-in-one-seo-pack",
    "classic-editor", "updraftplus", "loginizer", "really-simple-ssl",
    "duplicator", "wp-mail-smtp", "litespeed-cache", "redirection",
    "w3-total-cache", "sucuri-scanner", "ithemes-security", "define-me",
    "wordpress-seo", "hello-dolly", "akismet-anti-spam", "easy-table-of-contents",
]


def is_available() -> bool:
    return True


def _fetch_url(url: str, timeout: int = 10) -> tuple[str, int] | None:
    """Fetch URL and return (body, status_code) or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "GuardX-CMSScanner/0.1")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(500_000).decode("utf-8", errors="replace")
            return body, resp.status
    except Exception:
        return None


def _url_exists(url: str) -> bool:
    """Quick check if URL responds (HEAD or GET)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "GuardX-CMSScanner/0.1")
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return resp.status < 400
    except Exception:
        return False


def _detect_wordpress(base_url: str, body: str) -> dict:
    """Detect WordPress and enumerate plugins, users, issues."""
    results = {
        "cms": "WordPress",
        "version": None,
        "plugins": [],
        "users": [],
        "issues": []
    }

    # Check for common WordPress patterns
    if "wp-content" in body or "wp-includes" in body or "wp-json" in body:
        results["issues"].append("WordPress detected")

        # Look for version in comments or generator meta
        version_match = re.search(r'<meta name="generator" content="WordPress ([^\s"]+)"', body)
        if version_match:
            results["version"] = version_match.group(1)
            results["issues"].append(f"WordPress version disclosed: {results['version']}")

    # Enumerate plugins
    for plugin in WP_PLUGINS:
        plugin_url = f"{base_url.rstrip('/')}/wp-content/plugins/{plugin}/"
        if _url_exists(plugin_url):
            results["plugins"].append(plugin)

    # Check for user enumeration via REST API
    users_api = f"{base_url.rstrip('/')}/wp-json/wp/v2/users"
    try:
        resp = _fetch_url(users_api, timeout=5)
        if resp:
            body, status = resp
            if status == 200:
                try:
                    users_data = json.loads(body)
                    if isinstance(users_data, list):
                        for user in users_data[:5]:
                            if isinstance(user, dict) and "name" in user:
                                results["users"].append(user["name"])
                        results["issues"].append(f"User enumeration via REST API: {len(results['users'])} users found")
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    # Check for xmlrpc.php (brute force vector)
    xmlrpc_url = f"{base_url.rstrip('/')}/xmlrpc.php"
    if _url_exists(xmlrpc_url):
        results["issues"].append("xmlrpc.php enabled - brute force vector present")

    return results


def _detect_joomla(base_url: str, body: str) -> dict:
    """Detect Joomla and check for vulnerabilities."""
    results = {
        "cms": "Joomla",
        "version": None,
        "plugins": [],
        "users": [],
        "issues": []
    }

    # Check for Joomla patterns
    if "joomla" in body.lower() or "component=com_" in body:
        results["issues"].append("Joomla detected")

        # Look for version
        version_match = re.search(r'(?:Joomla|joomla)["\']?\s*:\s*["\']([0-9.]+)', body)
        if version_match:
            results["version"] = version_match.group(1)

    # Check for administrator panel
    admin_url = f"{base_url.rstrip('/')}/administrator/"
    if _url_exists(admin_url):
        results["issues"].append("Administrator panel accessible at /administrator/")

    # Check for configuration.php backup
    config_bak = f"{base_url.rstrip('/')}/configuration.php.bak"
    if _url_exists(config_bak):
        results["issues"].append("Backup configuration file exposed: configuration.php.bak")

    return results


def _detect_drupal(base_url: str, body: str) -> dict:
    """Detect Drupal and check for vulnerabilities."""
    results = {
        "cms": "Drupal",
        "version": None,
        "plugins": [],
        "users": [],
        "issues": []
    }

    # Check for Drupal patterns
    if "drupal" in body.lower() or "sites/all/modules" in body or "sites/default" in body:
        results["issues"].append("Drupal detected")

    # Check for CHANGELOG.txt (version disclosure)
    changelog = f"{base_url.rstrip('/')}/CHANGELOG.txt"
    try:
        resp = _fetch_url(changelog, timeout=5)
        if resp and resp[1] == 200:
            # Extract version from first line
            lines = resp[0].split("\n")
            if lines:
                version_match = re.search(r"Drupal (\d+\.\d+\.\d+)", lines[0])
                if version_match:
                    results["version"] = version_match.group(1)
                    results["issues"].append(f"Drupal version disclosed in CHANGELOG.txt: {results['version']}")
    except Exception:
        pass

    # Check user registration
    user_reg = f"{base_url.rstrip('/')}/user/register"
    if _url_exists(user_reg):
        results["issues"].append("User registration enabled at /user/register")

    return results


async def execute(params: dict) -> str:
    url = params.get("url", "").strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    # Fetch main page
    result = _fetch_url(url, timeout=10)
    if not result:
        return f"Cannot fetch {url}"

    body, status = result

    lines = [
        f"=== CMS Scanner Results ===",
        f"URL: {url}",
        f"Status: HTTP {status}",
        ""
    ]

    # Try to detect CMS
    detected = None

    # WordPress
    wp_result = _detect_wordpress(url, body)
    if wp_result["issues"]:
        detected = wp_result
        lines.append("--- WordPress ---")
        if wp_result["version"]:
            lines.append(f"Version: {wp_result['version']}")
        if wp_result["plugins"]:
            lines.append(f"Plugins found ({len(wp_result['plugins'])}): {', '.join(wp_result['plugins'][:10])}")
        for issue in wp_result["issues"]:
            lines.append(f"  [!] {issue}")

    # Joomla
    joomla_result = _detect_joomla(url, body)
    if joomla_result["issues"]:
        detected = joomla_result
        lines.append("--- Joomla ---")
        if joomla_result["version"]:
            lines.append(f"Version: {joomla_result['version']}")
        for issue in joomla_result["issues"]:
            lines.append(f"  [!] {issue}")

    # Drupal
    drupal_result = _detect_drupal(url, body)
    if drupal_result["issues"]:
        detected = drupal_result
        lines.append("--- Drupal ---")
        if drupal_result["version"]:
            lines.append(f"Version: {drupal_result['version']}")
        for issue in drupal_result["issues"]:
            lines.append(f"  [!] {issue}")

    if not detected or not detected["issues"]:
        lines.append("No known CMS detected")

    return "\n".join(lines)
