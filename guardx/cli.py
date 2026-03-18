"""GuardX CLI - AI Security Agent."""
import sys
import os
import asyncio

__all__ = ["main"]


def print_banner():
    print("""
  ╔══════════════════════════════════════╗
  ║  GuardX - AI Security Agent         ║
  ║  Scan. Exploit. Fix. Report.        ║
  ╚══════════════════════════════════════╝
""")


def cmd_version():
    from guardx import __version__
    print(f"guardx {__version__}")


def cmd_web(args):
    """Launch web panel."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from web.app import app
    port = int(os.getenv("GUARDX_PORT", "5000"))
    host = "0.0.0.0"
    if args and args[0].isdigit():
        port = int(args[0])
    print(f"\n  GuardX Web Panel: http://{host}:{port}\n")
    app.run(host=host, port=port, debug=False)


def cmd_scan(args):
    """Run a scan from CLI."""
    if not args:
        print("Uso: guardx scan <target> [--provider ollama|anthropic|openrouter] [--model modelo]")
        print("     guardx scan example.com")
        print("     guardx scan example.com --provider ollama --model llama3.1")
        print("     guardx scan example.com --provider anthropic")
        return

    target = args[0]
    provider = None
    model = None

    # Parse flags
    i = 1
    while i < len(args):
        if args[i] == "--provider" and i + 1 < len(args):
            provider = args[i + 1]
            i += 2
        elif args[i] == "--model" and i + 1 < len(args):
            model = args[i + 1]
            i += 2
        else:
            i += 1

    from dotenv import load_dotenv
    load_dotenv()

    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    print_banner()
    console.print(Panel(f"[bold green]Target:[/] {target}\n[bold green]Provider:[/] {provider or 'auto'}\n[bold green]Model:[/] {model or 'auto'}", title="GuardX Scan"))

    from guardx.llm.client import GuardXClient
    from guardx.llm.prompts import build_recon_prompt

    client = GuardXClient(model=model, provider=provider)
    console.print(f"[dim]Usando provider: {client.provider} | modelo: {client.model}[/]\n")

    prompt = build_recon_prompt(target)

    def on_text(text):
        console.print(text)

    def on_tool_call(name, params):
        target_param = params.get("target", params.get("url", params.get("domain", "")))
        console.print(f"[bold cyan]>> {name}[/] {target_param}")

    def on_tool_result(name, duration, success):
        status = "[green]OK[/]" if success else "[red]FAIL[/]"
        console.print(f"[dim]   {name}: {duration:.1f}s {status}[/]")

    async def run():
        return await client.run_agent_loop(
            prompt,
            on_tool_call=on_tool_call,
            on_text=on_text,
            on_tool_result=on_tool_result,
        )

    result = asyncio.run(run())
    console.print("\n[bold green]Scan completado.[/]")


def cmd_providers():
    """Show available providers and their status."""
    from dotenv import load_dotenv
    load_dotenv()

    print("\nProviders disponibles:\n")

    # Anthropic
    key = os.getenv("ANTHROPIC_API_KEY", "")
    status = "configurado" if key and key != "sk-ant-xxxxx" else "no configurado"
    print(f"  anthropic   - Claude API directo [{status}]")

    # OpenRouter
    key = os.getenv("OPENROUTER_API_KEY", "")
    status = "configurado" if key and key != "sk-or-xxxxx" else "no configurado"
    print(f"  openrouter  - Multi-modelo via OpenRouter [{status}]")

    # Ollama
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    try:
        import httpx
        resp = httpx.get(ollama_url.replace("/v1", "/api/tags"), timeout=3)
        models = [m["name"] for m in resp.json().get("models", [])]
        if models:
            print(f"  ollama      - Local, cero costo [activo: {', '.join(models[:5])}]")
        else:
            print(f"  ollama      - Local, cero costo [activo, sin modelos]")
    except Exception:
        print(f"  ollama      - Local, cero costo [no disponible]")

    print(f"\nUso: guardx scan <target> --provider <nombre> --model <modelo>")
    print(f"     GUARDX_PROVIDER=ollama en .env para default\n")


def cmd_tools():
    """List available security tools."""
    from guardx.llm.client import TOOLS
    print(f"\n{len(TOOLS)} herramientas disponibles:\n")
    for tool in TOOLS:
        print(f"  {tool['name']:25s} {tool['description'][:60]}")
    print()


def cmd_skills():
    """List available security skills."""
    from guardx.skills import load_skills
    skills = load_skills()
    print(f"\n{len(skills)} skills de seguridad:\n")
    for skill in skills:
        name = skill.get("name", "unknown")
        severity = skill.get("severity", "?")
        print(f"  {name:30s} [{severity}]")
    print()


def cmd_mcp():
    """Launch MCP server for Claude Code / Cursor integration."""
    print("Iniciando GuardX MCP Server...")
    from guardx.mcp_server import run_mcp_server
    run_mcp_server()


def cmd_help():
    print_banner()
    print("Comandos:")
    print("  guardx scan <target>     - Escanear un objetivo")
    print("    --provider <p>         - anthropic, openrouter, ollama")
    print("    --model <m>            - Modelo a usar")
    print("  guardx web [port]        - Lanzar panel web")
    print("  guardx mcp               - Iniciar MCP server")
    print("  guardx providers         - Ver providers disponibles")
    print("  guardx tools             - Listar herramientas")
    print("  guardx skills            - Listar skills de seguridad")
    print("  guardx version           - Version")
    print("  guardx help              - Esta ayuda")
    print()


def main():
    args = sys.argv[1:]

    if not args:
        cmd_help()
        return

    cmd = args[0].lower()
    rest = args[1:]

    commands = {
        "scan": lambda: cmd_scan(rest),
        "web": lambda: cmd_web(rest),
        "mcp": cmd_mcp,
        "providers": cmd_providers,
        "tools": cmd_tools,
        "skills": cmd_skills,
        "version": cmd_version,
        "--version": cmd_version,
        "-v": cmd_version,
        "help": cmd_help,
        "--help": cmd_help,
        "-h": cmd_help,
    }

    handler = commands.get(cmd)
    if handler:
        handler()
    else:
        print(f"Comando desconocido: {cmd}")
        cmd_help()


if __name__ == "__main__":
    main()
