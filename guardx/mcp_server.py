"""GuardX MCP Server - Expone herramientas de seguridad via Model Context Protocol.

Permite usar GuardX desde Claude Code, Cursor, y cualquier cliente MCP.

Uso:
  guardx mcp                          # Inicia el server stdio
  python -m guardx.mcp_server         # Alternativa directa

Configurar en Claude Code (~/.claude/settings.json):
  {
    "mcpServers": {
      "guardx": {
        "command": "guardx",
        "args": ["mcp"]
      }
    }
  }
"""
import sys
import json
import asyncio
from guardx.tools import (
    port_check, nmap_scan, http_headers, nuclei_scan, sql_check,
    web_spider, dir_bruteforce, tech_fingerprint, waf_detect,
    subdomain_enum, cms_scanner, api_fuzzer, js_analyzer, cors_scanner,
    ssl_analyzer, dns_analyzer, http_request,
)

try:
    from guardx.tools import xss_check
except ImportError:
    xss_check = None

# Registry: name -> (module, description)
MCP_TOOLS = {
    "guardx_port_check": (port_check, "Escaneo rapido de puertos TCP"),
    "guardx_nmap_scan": (nmap_scan, "Escaneo profundo con nmap (puertos, servicios, versiones)"),
    "guardx_http_headers": (http_headers, "Verifica headers de seguridad HTTP"),
    "guardx_nuclei_scan": (nuclei_scan, "Deteccion de CVEs y misconfigs con Nuclei"),
    "guardx_sql_check": (sql_check, "Test de SQL injection (error, UNION, blind, time-based)"),
    "guardx_web_spider": (web_spider, "Crawler BFS: URLs, formularios, parametros"),
    "guardx_dir_bruteforce": (dir_bruteforce, "Descubrimiento de directorios ocultos"),
    "guardx_tech_fingerprint": (tech_fingerprint, "Identificacion de tecnologias del stack"),
    "guardx_waf_detect": (waf_detect, "Deteccion de Web Application Firewall"),
    "guardx_subdomain_enum": (subdomain_enum, "Enumeracion de subdominios (DNS + crt.sh)"),
    "guardx_cms_scanner": (cms_scanner, "Escaneo de vulnerabilidades en CMS"),
    "guardx_api_fuzzer": (api_fuzzer, "Descubrimiento y testing de endpoints API"),
    "guardx_js_analyzer": (js_analyzer, "Analisis de JS: secretos, URLs, API keys"),
    "guardx_cors_scanner": (cors_scanner, "Test de misconfiguraciones CORS"),
    "guardx_ssl_analyzer": (ssl_analyzer, "Analisis profundo SSL/TLS"),
    "guardx_dns_analyzer": (dns_analyzer, "Analisis DNS: SPF, DKIM, DMARC, DNSSEC"),
    "guardx_http_request": (http_request, "Peticion HTTP raw (GET/POST)"),
}

if xss_check:
    MCP_TOOLS["guardx_xss_check"] = (xss_check, "Test de Cross-Site Scripting (XSS)")


def build_tool_list():
    """Build MCP tools/list response."""
    tools = []
    for name, (module, description) in MCP_TOOLS.items():
        schema = module.TOOL_SCHEMA
        tools.append({
            "name": name,
            "description": f"[GuardX] {description}",
            "inputSchema": schema["input_schema"],
        })
    return tools


async def execute_tool(name: str, arguments: dict) -> str:
    """Execute a GuardX tool and return result."""
    if name not in MCP_TOOLS:
        return f"Herramienta desconocida: {name}"

    module, _ = MCP_TOOLS[name]
    try:
        result = await asyncio.wait_for(module.execute(arguments), timeout=300)
        return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    except asyncio.TimeoutError:
        return f"Timeout (300s): {name}"
    except Exception as e:
        return f"Error en {name}: {e}"


class MCPServer:
    """MCP Server implementacion stdio (JSON-RPC 2.0)."""

    def __init__(self):
        self.tools = build_tool_list()

    async def handle_message(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "guardx",
                        "version": "0.2.0",
                    },
                },
            }

        if method == "notifications/initialized":
            return None  # No response for notifications

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.tools},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            result = await execute_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": result}],
                    "isError": False,
                },
            }

        # Unknown method
        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return None

    async def run(self):
        """Main stdio loop."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break

                line = line.decode("utf-8").strip()
                if not line:
                    continue

                msg = json.loads(line)
                response = await self.handle_message(msg)

                if response is not None:
                    out = json.dumps(response, ensure_ascii=False) + "\n"
                    sys.stdout.write(out)
                    sys.stdout.flush()

            except json.JSONDecodeError:
                continue
            except Exception as e:
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)},
                }
                sys.stdout.write(json.dumps(error_resp) + "\n")
                sys.stdout.flush()


def run_mcp_server():
    """Entry point for MCP server."""
    server = MCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    run_mcp_server()
