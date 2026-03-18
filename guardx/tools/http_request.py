"""HTTP Request tool - Make raw HTTP requests and get full response."""
import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import gzip
import zlib
import io

TOOL_SCHEMA = {
    "name": "http_request",
    "description": (
        "Make an HTTP request and get the FULL response including status, headers, and body. "
        "Use this to: read exposed files (config backups, .env, .git), test login forms with credentials, "
        "check API responses, verify directory listings, extract sensitive data from pages. "
        "Supports GET, POST, PUT, DELETE methods with custom headers and body data."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL to request"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                "default": "GET",
                "description": "HTTP method"
            },
            "headers": {
                "type": "object",
                "description": "Custom headers as key-value pairs (e.g. {\"Authorization\": \"Bearer xxx\"})",
                "default": {}
            },
            "body": {
                "type": "string",
                "description": "Request body for POST/PUT (form data or JSON string)"
            },
            "follow_redirects": {
                "type": "boolean",
                "default": True,
                "description": "Follow HTTP redirects"
            },
            "max_response_size": {
                "type": "integer",
                "default": 50000,
                "description": "Max response body size in bytes to return (truncates if larger)"
            }
        },
        "required": ["url"],
    },
}


def is_available() -> bool:
    return True


async def execute(params: dict) -> str:
    url = params["url"]
    method = params.get("method", "GET").upper()
    custom_headers = params.get("headers", {})
    body = params.get("body")
    follow_redirects = params.get("follow_redirects", True)
    max_size = params.get("max_response_size", 50000)

    # Build request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    }
    headers.update(custom_headers)

    data = None
    if body:
        data = body.encode("utf-8")
        if "Content-Type" not in headers:
            # Auto-detect content type
            try:
                json.loads(body)
                headers["Content-Type"] = "application/json"
            except (json.JSONDecodeError, ValueError):
                headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    # SSL context that doesn't verify (for pentesting)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
        else:
            # No redirect handler
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
                NoRedirectHandler
            )

        response = opener.open(req, timeout=30)
        status = response.getcode()
        resp_headers = dict(response.headers)
        raw_bytes = response.read(max_size * 2)  # read more since compressed

        # Decompress gzip/deflate if needed
        content_encoding = resp_headers.get("Content-Encoding", "").lower().strip()
        body_bytes = raw_bytes
        if content_encoding == "gzip":
            try:
                body_bytes = gzip.decompress(raw_bytes)
            except Exception:
                try:
                    body_bytes = zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
                except Exception:
                    pass  # keep raw bytes
        elif content_encoding == "deflate":
            try:
                body_bytes = zlib.decompress(raw_bytes)
            except Exception:
                try:
                    body_bytes = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
                except Exception:
                    pass
        elif content_encoding == "br":
            try:
                import brotli
                body_bytes = brotli.decompress(raw_bytes)
            except Exception:
                pass

        # Truncate decompressed body to max_size
        if len(body_bytes) > max_size:
            body_bytes = body_bytes[:max_size]

        # Try decode as text
        try:
            body_text = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_text = body_bytes.decode("latin-1", errors="replace")

        # Build output
        lines = []
        lines.append(f"HTTP {status}")
        lines.append(f"URL: {response.geturl()}")
        lines.append("")
        lines.append("=== RESPONSE HEADERS ===")
        for k, v in resp_headers.items():
            lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append(f"=== RESPONSE BODY ({len(body_bytes)} bytes) ===")

        # Truncate very long responses but keep useful content
        if len(body_text) > max_size:
            body_text = body_text[:max_size] + f"\n\n... [TRUNCATED at {max_size} bytes, total: {len(body_bytes)}]"

        lines.append(body_text)

        return "\n".join(lines)

    except urllib.error.HTTPError as e:
        # Still useful - 403, 404, 500 responses contain info
        status = e.code
        resp_headers = dict(e.headers) if e.headers else {}
        try:
            raw_err = e.read(max_size * 2)
            err_encoding = resp_headers.get("Content-Encoding", "").lower().strip()
            if err_encoding == "gzip":
                try:
                    raw_err = gzip.decompress(raw_err)
                except Exception:
                    pass
            elif err_encoding == "deflate":
                try:
                    raw_err = zlib.decompress(raw_err)
                except Exception:
                    pass
            error_body = raw_err[:max_size].decode("utf-8", errors="replace")
        except Exception:
            error_body = "(could not read error body)"

        lines = []
        lines.append(f"HTTP {status} (Error)")
        lines.append(f"URL: {url}")
        lines.append("")
        lines.append("=== RESPONSE HEADERS ===")
        for k, v in resp_headers.items():
            lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append(f"=== ERROR BODY ===")
        lines.append(error_body)

        return "\n".join(lines)

    except urllib.error.URLError as e:
        return f"Connection error: {e.reason}"
    except Exception as e:
        return f"Request failed: {type(e).__name__}: {e}"
