"""Directory bruteforce tool. Discovers hidden paths and files."""
import os
import asyncio
import urllib.request
import urllib.parse
import urllib.error
import ssl
import time

TOOL_SCHEMA = {
    "name": "dir_bruteforce",
    "description": (
        "Bruteforce directories and files on a web server using a wordlist. "
        "Discovers hidden paths like /admin, /api, /.env, /backup.zip, etc. "
        "Reports paths that return non-404 status codes. "
        "Uses HEAD requests first for speed, then GET to confirm findings."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Base URL e.g. http://example.com"},
            "extensions": {
                "type": "string",
                "description": "Comma-separated extensions to try e.g. php,html,json,bak,txt",
                "default": "",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent requests (1-30)",
                "default": 15,
            },
            "timeout_per_request": {
                "type": "integer",
                "description": "Timeout per request in seconds (1-10)",
                "default": 5,
            },
        },
        "required": ["url"],
    },
}

# Status codes worth reporting
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def is_available() -> bool:
    return True


def _load_wordlist() -> list[str]:
    """Load the built-in wordlist."""
    wordlist_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "wordlists", "common.txt"
    )
    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return words
    except FileNotFoundError:
        return [
            "admin", "api", "backup", "config", ".env", ".git", "login",
            "test", "debug", "docs", "dashboard", "phpmyadmin", "wp-admin",
            "robots.txt", "sitemap.xml", ".htaccess", "server-status",
        ]


def _build_paths(words: list[str], extensions: str) -> list[str]:
    """Build list of paths to check, optionally with extensions."""
    paths = list(words)
    if extensions:
        ext_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
        for word in words:
            if "." in word.split("/")[-1]:
                continue
            for ext in ext_list:
                paths.append(f"{word}.{ext}")
    return paths


def _check_path_head(base_url: str, path: str, ctx: ssl.SSLContext, timeout: int) -> dict | None:
    """Quick HEAD check - only returns result if non-404."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; GuardX/1.0)")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            if status in INTERESTING_CODES:
                content_type = resp.headers.get("Content-Type", "")
                content_length = resp.headers.get("Content-Length", "?")
                return {
                    "path": f"/{path}",
                    "url": url,
                    "status": status,
                    "size": content_length,
                    "content_type": content_type.split(";")[0].strip(),
                }
    except urllib.error.HTTPError as e:
        if e.code in INTERESTING_CODES and e.code != 404:
            return {
                "path": f"/{path}",
                "url": url,
                "status": e.code,
                "size": "?",
                "content_type": "",
            }
    except Exception:
        pass
    return None


def _check_path_get(url: str, ctx: ssl.SSLContext, timeout: int) -> int:
    """GET request to confirm and get actual size."""
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; GuardX/1.0)")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(50_000)
            return len(body)
    except Exception:
        return 0


async def execute(params: dict) -> str:
    url = params["url"]
    extensions = params.get("extensions", "")
    threads = min(max(params.get("threads", 15), 1), 30)
    req_timeout = min(max(params.get("timeout_per_request", 5), 1), 10)

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    words = _load_wordlist()
    paths = _build_paths(words, extensions)
    total = len(paths)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Phase 1: Fast HEAD scan
    semaphore = asyncio.Semaphore(threads)
    results = []
    errors = 0
    start_time = time.time()
    MAX_SCAN_TIME = 150  # hard limit 2.5 min to stay under tool timeout

    async def check_one(path: str):
        nonlocal errors
        # Check time limit
        if time.time() - start_time > MAX_SCAN_TIME:
            return
        async with semaphore:
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, _check_path_head, url, path, ctx, req_timeout),
                    timeout=req_timeout + 2
                )
                if result:
                    results.append(result)
            except (asyncio.TimeoutError, Exception):
                errors += 1

    tasks = [check_one(p) for p in paths]
    await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - start_time
    timed_out = elapsed >= MAX_SCAN_TIME

    # Phase 2: GET confirm for interesting findings (get actual sizes)
    for r in results:
        if r["status"] == 200 and r["size"] == "?":
            loop = asyncio.get_event_loop()
            try:
                size = await asyncio.wait_for(
                    loop.run_in_executor(None, _check_path_get, r["url"], ctx, req_timeout),
                    timeout=req_timeout + 2
                )
                r["size"] = f"{size}B"
            except Exception:
                r["size"] = "?"
        elif r["size"] != "?":
            r["size"] = f"{r['size']}B"

    # Sort by status code, then path
    results.sort(key=lambda r: (r["status"], r["path"]))

    # Build output
    lines = [
        f"=== Directory Bruteforce Results for {url} ===",
        f"Paths tested: {total} | Found: {len(results)} | Time: {elapsed:.1f}s",
    ]
    if timed_out:
        lines.append(f"WARNING: Scan hit time limit ({MAX_SCAN_TIME}s), some paths may not have been checked.")
    if errors > 0:
        lines.append(f"Timeouts/errors: {errors}")
    lines.append("")

    if not results:
        lines.append("No interesting paths found.")
        return "\n".join(lines)

    # Group by status
    status_groups = {}
    for r in results:
        code = r["status"]
        if code not in status_groups:
            status_groups[code] = []
        status_groups[code].append(r)

    status_labels = {
        200: "OK (accessible)",
        301: "Redirect (moved)",
        302: "Redirect (found)",
        307: "Temporary redirect",
        308: "Permanent redirect",
        401: "Unauthorized (auth required)",
        403: "Forbidden (exists but blocked)",
        405: "Method not allowed",
        500: "Server error",
    }

    for code in sorted(status_groups.keys()):
        group = status_groups[code]
        label = status_labels.get(code, f"HTTP {code}")
        lines.append(f"--- Status {code}: {label} ({len(group)} paths) ---")
        for r in group:
            size_str = r.get("size", "?")
            ct = f" [{r['content_type']}]" if r["content_type"] else ""
            lines.append(f"  {r['path']}  ({size_str}){ct}")
        lines.append("")

    # Highlight critical finds
    critical_keywords = [
        ".env", ".git", "backup", "dump", "config", "phpinfo",
        "phpmyadmin", "adminer", ".htpasswd", "server-status",
        "debug", "actuator", "elmah", "trace", ".bak", "wp-config",
        ".sql", "database", "credentials", "secret",
    ]
    critical_paths = [
        r for r in results
        if r["status"] == 200 and any(
            kw in r["path"].lower() for kw in critical_keywords
        )
    ]
    if critical_paths:
        lines.append("!!! CRITICAL FINDINGS !!!")
        for r in critical_paths:
            lines.append(f"  [CRITICAL] {url}{r['path']} - ACCESSIBLE (HTTP {r['status']})")
        lines.append("")

    return "\n".join(lines)
