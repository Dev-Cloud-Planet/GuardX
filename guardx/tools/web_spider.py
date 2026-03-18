"""Web Spider / Crawler tool. Discovers URLs, forms, parameters and inputs."""
import urllib.request
import urllib.parse
import ssl
import re
from html.parser import HTMLParser
from collections import deque

TOOL_SCHEMA = {
    "name": "web_spider",
    "description": (
        "Crawl a website discovering URLs, forms, parameters and inputs. "
        "Follows links within the same domain up to max_depth levels. "
        "Returns endpoints, forms with fields, URL parameters, hidden inputs and HTML comments."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Starting URL e.g. http://example.com"},
            "max_depth": {
                "type": "integer",
                "description": "Maximum crawl depth (1-5)",
                "default": 3,
            },
            "max_pages": {
                "type": "integer",
                "description": "Maximum pages to crawl",
                "default": 50,
            },
        },
        "required": ["url"],
    },
}


def is_available() -> bool:
    return True


class _PageParser(HTMLParser):
    """Extract links, forms, scripts, comments, and meta tags from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.comments = []
        self.scripts = set()
        self.meta_info = []
        self._current_form = None
        self._current_form_fields = []

    def _resolve(self, href: str) -> str | None:
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return None
        return urllib.parse.urljoin(self.base_url, href)

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        # Links from <a>, <area>
        if tag in ("a", "area"):
            href = attrs_dict.get("href")
            resolved = self._resolve(href)
            if resolved:
                self.links.add(resolved)

        # Script sources
        if tag == "script":
            src = attrs_dict.get("src")
            resolved = self._resolve(src)
            if resolved:
                self.scripts.add(resolved)

        # Meta tags (generator, etc.)
        if tag == "meta":
            name = attrs_dict.get("name", "").lower()
            content = attrs_dict.get("content", "")
            if name and content:
                self.meta_info.append((name, content))

        # Forms
        if tag == "form":
            self._current_form = {
                "action": self._resolve(attrs_dict.get("action", "")) or self.base_url,
                "method": attrs_dict.get("method", "GET").upper(),
            }
            self._current_form_fields = []

        # Form inputs
        if tag in ("input", "textarea", "select") and self._current_form is not None:
            field = {
                "tag": tag,
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            }
            if tag == "input" and attrs_dict.get("type") == "hidden":
                field["hidden"] = True
            self._current_form_fields.append(field)

        # Links from iframes
        if tag == "iframe":
            src = attrs_dict.get("src")
            resolved = self._resolve(src)
            if resolved:
                self.links.add(resolved)

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self._current_form["fields"] = self._current_form_fields
            self.forms.append(self._current_form)
            self._current_form = None
            self._current_form_fields = []

    def handle_comment(self, data):
        stripped = data.strip()
        if stripped and len(stripped) > 3:
            self.comments.append(stripped[:200])


def _same_domain(url: str, base_domain: str) -> bool:
    """Check if URL belongs to the same domain."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname and (
            parsed.hostname == base_domain
            or parsed.hostname.endswith("." + base_domain)
        )
    except Exception:
        return False


def _extract_url_params(url: str) -> list[tuple[str, str]]:
    """Extract query parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qsl(parsed.query)


def _fetch_page(url: str, timeout: int = 10) -> tuple[str, int] | None:
    """Fetch a page and return (body, status_code) or None on error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "GuardX-Spider/0.1")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "text/xml" not in content_type:
                return None
            body = resp.read(500_000).decode("utf-8", errors="replace")
            return body, resp.status
    except Exception:
        return None


async def execute(params: dict) -> str:
    url = params["url"]
    max_depth = min(params.get("max_depth", 3), 5)
    max_pages = min(params.get("max_pages", 50), 100)

    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed_base = urllib.parse.urlparse(url)
    base_domain = parsed_base.hostname
    if not base_domain:
        return f"Invalid URL: {url}"

    # BFS crawl
    visited = set()
    queue = deque([(url, 0)])  # (url, depth)
    all_urls = set()
    all_forms = []
    all_params = {}  # url -> [(name, value)]
    all_comments = []
    all_scripts = set()
    all_meta = []

    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        current_url, depth = queue.popleft()

        # Normalize URL (remove fragment)
        current_url = urllib.parse.urldefrag(current_url)[0]

        if current_url in visited:
            continue
        visited.add(current_url)

        if not _same_domain(current_url, base_domain):
            continue

        result = _fetch_page(current_url)
        if result is None:
            continue

        body, status = result
        pages_crawled += 1
        all_urls.add(current_url)

        # Extract URL params
        url_params = _extract_url_params(current_url)
        if url_params:
            all_params[current_url] = url_params

        # Parse HTML
        parser = _PageParser(current_url)
        try:
            parser.feed(body)
        except Exception:
            continue

        all_forms.extend(parser.forms)
        all_comments.extend(parser.comments)
        all_scripts.update(parser.scripts)
        all_meta.extend(parser.meta_info)

        # Enqueue discovered links
        if depth < max_depth:
            for link in parser.links:
                link_clean = urllib.parse.urldefrag(link)[0]
                if link_clean not in visited and _same_domain(link_clean, base_domain):
                    queue.append((link_clean, depth + 1))

                # Track params from discovered links too
                link_params = _extract_url_params(link_clean)
                if link_params and link_clean not in all_params:
                    all_params[link_clean] = link_params

    # Build output
    lines = [
        f"=== Web Spider Results for {base_domain} ===",
        f"Pages crawled: {pages_crawled}",
        "",
    ]

    # URLs found
    lines.append(f"--- URLs Discovered ({len(all_urls)}) ---")
    for u in sorted(all_urls):
        lines.append(f"  {u}")

    # Forms
    if all_forms:
        lines.append(f"\n--- Forms Found ({len(all_forms)}) ---")
        for i, form in enumerate(all_forms, 1):
            lines.append(f"  Form #{i}: {form['method']} {form['action']}")
            for field in form["fields"]:
                hidden = " [HIDDEN]" if field.get("hidden") else ""
                value = f" = '{field['value']}'" if field["value"] else ""
                lines.append(
                    f"    - {field['tag']} name='{field['name']}' "
                    f"type='{field['type']}'{value}{hidden}"
                )

    # URL Parameters
    if all_params:
        lines.append(f"\n--- URL Parameters Found ({len(all_params)} URLs with params) ---")
        for param_url, param_list in all_params.items():
            lines.append(f"  {param_url}")
            for name, val in param_list:
                lines.append(f"    - {name} = {val}")

    # Comments with potential info
    interesting_comments = [
        c for c in all_comments
        if any(kw in c.lower() for kw in [
            "todo", "fixme", "hack", "password", "secret", "api",
            "key", "token", "debug", "admin", "config", "version",
            "deprecated", "temporary", "remove", "bug",
        ])
    ]
    if interesting_comments:
        lines.append(f"\n--- Interesting HTML Comments ({len(interesting_comments)}) ---")
        for c in interesting_comments[:20]:
            lines.append(f"  <!-- {c[:150]} -->")

    # Scripts
    if all_scripts:
        lines.append(f"\n--- External Scripts ({len(all_scripts)}) ---")
        for s in sorted(all_scripts)[:30]:
            lines.append(f"  {s}")

    # Meta info
    if all_meta:
        lines.append(f"\n--- Meta Tags ---")
        for name, content in all_meta[:20]:
            lines.append(f"  {name}: {content}")

    return "\n".join(lines)
