"""API endpoint discovery and fuzzing for common endpoints."""
import urllib.request
import urllib.parse
import ssl
import json

TOOL_SCHEMA = {
    "name": "api_fuzzer",
    "description": (
        "Discover and fuzz API endpoints by testing common paths, "
        "HTTP methods, GraphQL introspection, authentication bypass, "
        "and exposed API documentation."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL e.g. http://example.com"
            },
            "wordlist_mode": {
                "type": "string",
                "enum": ["common", "aggressive"],
                "description": "Wordlist size and scope",
                "default": "common",
            },
        },
        "required": ["url"],
    },
}

# Common API paths to check
COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/rest",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger-ui",
    "/redoc",
    "/api/docs",
    "/api/swagger",
    "/api-docs.json",
    "/openapi.yaml",
    "/swagger.yaml",
]

AGGRESSIVE_PATHS = COMMON_API_PATHS + [
    "/v1",
    "/v2",
    "/v3",
    "/api/v4",
    "/api/v5",
    "/rest/api",
    "/rest/api/v1",
    "/rest/api/v2",
    "/service",
    "/services",
    "/data",
    "/graphql/v1",
    "/gql",
    "/graphql/debug",
    "/api/internal",
    "/api/admin",
    "/api/public",
    "/api/mobile",
    "/api/client",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# GraphQL introspection query
GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { types { name } } }"
}


def is_available() -> bool:
    return True


def _test_endpoint(base_url: str, path: str, method: str = "GET", data: str | None = None) -> dict:
    """Test an endpoint with a specific HTTP method."""
    url = base_url.rstrip("/") + path
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {
        "path": path,
        "method": method,
        "status": None,
        "accessible": False,
        "content_length": 0
    }

    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "GuardX-APIFuzzer/0.1")

        if data:
            req.add_header("Content-Type", "application/json")
            req.data = data.encode("utf-8")

        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            result["status"] = resp.status
            result["accessible"] = resp.status < 400
            try:
                body = resp.read(10000)
                result["content_length"] = len(body)
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["accessible"] = e.code < 400
    except Exception:
        result["status"] = "timeout/error"

    return result


def _test_graphql_introspection(base_url: str, path: str) -> dict | None:
    """Test GraphQL introspection on an endpoint."""
    url = base_url.rstrip("/") + path
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        data = json.dumps(GRAPHQL_INTROSPECTION).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("User-Agent", "GuardX-APIFuzzer/0.1")
        req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            if resp.status < 400:
                body = resp.read(50000).decode("utf-8", errors="replace")
                if "__schema" in body or "types" in body:
                    return {
                        "path": path,
                        "introspectable": True,
                        "response_size": len(body)
                    }
    except Exception:
        pass

    return None


def _test_auth_bypass(base_url: str, path: str) -> bool:
    """Test if endpoint is accessible without authentication."""
    result = _test_endpoint(base_url, path, "GET")
    # No auth headers provided, so if it responds with 200-399, it's likely unauthenticated
    return result["accessible"] and result["status"] not in [401, 403]


async def execute(params: dict) -> str:
    base_url = params.get("url", "").strip()
    wordlist_mode = params.get("wordlist_mode", "common")

    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    # Select wordlist based on mode
    paths = AGGRESSIVE_PATHS if wordlist_mode == "aggressive" else COMMON_API_PATHS

    lines = [
        f"=== API Fuzzer Results ===",
        f"Base URL: {base_url}",
        f"Mode: {wordlist_mode}",
        "",
    ]

    found_endpoints = []
    graphql_endpoints = []
    unauth_endpoints = []

    # Test each API path
    lines.append(f"--- Testing {len(paths)} API Paths ---")
    for path in paths:
        # Test GET
        result = _test_endpoint(base_url, path, "GET")
        if result["accessible"]:
            found_endpoints.append(result)
            lines.append(f"  {path:30} GET {result['status']}")

            # Check if auth is required
            if result["status"] == 200:
                unauth_endpoints.append((path, "GET"))

            # Test GraphQL introspection if path contains graphql
            if "graphql" in path.lower():
                gql_result = _test_graphql_introspection(base_url, path)
                if gql_result:
                    graphql_endpoints.append(gql_result)
                    lines.append(f"    [!] GraphQL introspection enabled")

    # Test additional HTTP methods on found endpoints
    lines.append(f"\n--- Testing HTTP Methods on Found Endpoints ---")
    for endpoint in found_endpoints[:10]:  # Limit to first 10 to avoid too many requests
        path = endpoint["path"]
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
            result = _test_endpoint(base_url, path, method)
            if result["status"] and result["status"] < 400:
                lines.append(f"  {path:30} {method:6} {result['status']}")

    # Summary
    lines.append(f"\n--- Summary ---")
    lines.append(f"Endpoints found: {len(found_endpoints)}")
    if graphql_endpoints:
        lines.append(f"GraphQL endpoints: {len(graphql_endpoints)}")
        for gql in graphql_endpoints:
            lines.append(f"  [CRITICAL] {gql['path']} - Introspection enabled ({gql['response_size']} bytes)")
    if unauth_endpoints:
        lines.append(f"Endpoints without authentication: {len(unauth_endpoints)}")
        for path, method in unauth_endpoints[:10]:
            lines.append(f"  [!] {path} {method}")

    if not found_endpoints:
        lines.append("No API endpoints discovered")

    return "\n".join(lines)
