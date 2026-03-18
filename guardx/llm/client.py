"""LLM client with tool-use agent loop. Supports Anthropic and OpenRouter."""
import os
import json
import asyncio
import time
import anthropic
import httpx
from guardx.tools import (
    nmap_scan, http_headers, nuclei_scan, port_check, ssh_exec, sql_check,
    web_spider, dir_bruteforce, tech_fingerprint, waf_detect,
    subdomain_enum, cms_scanner, api_fuzzer, js_analyzer, cors_scanner,
    ssl_analyzer, dns_analyzer, screenshot, http_request,
)

# Import new tools (graceful fallback)
try:
    from guardx.tools import xss_check
except ImportError:
    xss_check = None

TOOLS = [
    nmap_scan.TOOL_SCHEMA,
    http_headers.TOOL_SCHEMA,
    nuclei_scan.TOOL_SCHEMA,
    port_check.TOOL_SCHEMA,
    ssh_exec.TOOL_SCHEMA,
    sql_check.TOOL_SCHEMA,
    web_spider.TOOL_SCHEMA,
    dir_bruteforce.TOOL_SCHEMA,
    tech_fingerprint.TOOL_SCHEMA,
    waf_detect.TOOL_SCHEMA,
    subdomain_enum.TOOL_SCHEMA,
    cms_scanner.TOOL_SCHEMA,
    api_fuzzer.TOOL_SCHEMA,
    js_analyzer.TOOL_SCHEMA,
    cors_scanner.TOOL_SCHEMA,
    ssl_analyzer.TOOL_SCHEMA,
    dns_analyzer.TOOL_SCHEMA,
    screenshot.TOOL_SCHEMA,
    http_request.TOOL_SCHEMA,
]

# Add new tools if available
if xss_check:
    TOOLS.append(xss_check.TOOL_SCHEMA)

TOOL_EXECUTORS = {
    "nmap_scan": nmap_scan.execute,
    "http_headers_check": http_headers.execute,
    "nuclei_scan": nuclei_scan.execute,
    "port_check": port_check.execute,
    "ssh_exec": ssh_exec.execute,
    "sql_injection_check": sql_check.execute,
    "web_spider": web_spider.execute,
    "dir_bruteforce": dir_bruteforce.execute,
    "tech_fingerprint": tech_fingerprint.execute,
    "waf_detect": waf_detect.execute,
    "subdomain_enum": subdomain_enum.execute,
    "cms_scanner": cms_scanner.execute,
    "api_fuzzer": api_fuzzer.execute,
    "js_analyzer": js_analyzer.execute,
    "cors_scanner": cors_scanner.execute,
    "ssl_analyzer": ssl_analyzer.execute,
    "dns_analyzer": dns_analyzer.execute,
    "screenshot": screenshot.execute,
    "http_request": http_request.execute,
}

# Register new tools
if xss_check:
    TOOL_EXECUTORS["xss_check"] = xss_check.execute

# OpenRouter tool schema uses 'parameters' instead of 'input_schema'
OPENROUTER_TOOLS = []
for tool in TOOLS:
    OPENROUTER_TOOLS.append({
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["input_schema"],
        },
    })

# Max time for the entire agent loop (45 minutes - extended for thorough scans)
AGENT_LOOP_TIMEOUT = int(os.getenv("GUARDX_LOOP_TIMEOUT", "2700"))
# Max time for a single tool execution (5 minutes - nmap/nuclei need time)
TOOL_TIMEOUT = int(os.getenv("GUARDX_TOOL_TIMEOUT", "300"))
# Max time for a single LLM API call (3 minutes - free models are slower)
API_TIMEOUT = int(os.getenv("GUARDX_API_TIMEOUT", "180"))
# Max retries for API errors (higher for free tier rate limits)
MAX_RETRIES = 4


def detect_provider() -> str:
    """Detect which provider to use based on env vars."""
    provider = os.getenv("GUARDX_PROVIDER", "").lower()
    if provider:
        return provider
    if os.getenv("OLLAMA_MODEL") or os.getenv("OLLAMA_BASE_URL"):
        return "ollama"
    if os.getenv("OPENROUTER_API_KEY"):
        return "openrouter"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "anthropic"


class GuardXClient:
    def __init__(self, api_key: str = None, model: str = None, provider: str = None):
        self.provider = provider or detect_provider()

        if self.provider == "ollama":
            self.api_key = "ollama"  # Ollama no requiere API key
            self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1")
            self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            self.client = None
        elif self.provider == "openrouter":
            self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
            self.model = model or os.getenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4")
            self.base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
            self.client = None
        else:
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
            self.client = anthropic.Anthropic(api_key=self.api_key)

    async def run_agent_loop(self, system_prompt: str, on_tool_call=None, on_text=None, on_confirm=None, on_tool_result=None):
        """Run the agentic tool-use loop with global timeout.

        Callbacks:
            on_tool_call(tool_name, params) -> called when agent wants to use a tool
            on_text(text) -> called when agent outputs text
            on_confirm(tool_name, description, command) -> for destructive tools, must return True/False
            on_tool_result(tool_name, duration, success) -> called after tool execution with timing
        """
        try:
            return await asyncio.wait_for(
                self._run_loop(system_prompt, on_tool_call, on_text, on_confirm, on_tool_result),
                timeout=AGENT_LOOP_TIMEOUT,
            )
        except asyncio.TimeoutError:
            msg = f"Agent loop timeout ({AGENT_LOOP_TIMEOUT}s). Deteniendo."
            if on_text:
                on_text(msg)
            return msg
        except Exception as e:
            msg = f"Agent loop error: {e}"
            if on_text:
                on_text(msg)
            return msg

    async def _run_loop(self, system_prompt, on_tool_call, on_text, on_confirm, on_tool_result):
        if self.provider == "ollama":
            return await self._run_ollama_loop(system_prompt, on_tool_call, on_text, on_confirm, on_tool_result)
        elif self.provider == "openrouter":
            return await self._run_openrouter_loop(system_prompt, on_tool_call, on_text, on_confirm, on_tool_result)
        else:
            return await self._run_anthropic_loop(system_prompt, on_tool_call, on_text, on_confirm, on_tool_result)

    # ── Anthropic (direct) ────────────────────────────────────
    async def _run_anthropic_loop(self, system_prompt, on_tool_call, on_text, on_confirm, on_tool_result):
        # Extract target from system prompt for the user message
        import re
        target_match = re.search(r'(?:TARGET|OBJETIVO):\s*(\S+)', system_prompt)
        target_str = target_match.group(1) if target_match else "el objetivo"

        messages = [{"role": "user", "content": f"Inicia la evaluacion de seguridad en {target_str} AHORA. El objetivo es {target_str}. Comienza con tech_fingerprint en {target_str}, luego continua con TODAS las herramientas en orden. No me preguntes el objetivo - es {target_str}. Se exhaustivo y no te detengas hasta haber probado todo."}]
        iteration = 0
        MAX_ITERATIONS = 80

        while True:
            iteration += 1
            progress = f"[{iteration}/{MAX_ITERATIONS}]"

            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=system_prompt,
                    tools=TOOLS,
                    messages=messages,
                )
            except Exception as e:
                error_msg = f"Anthropic API error: {e}"
                if on_text:
                    on_text(error_msg)
                return error_msg

            assistant_content = response.content
            messages.append({"role": "assistant", "content": assistant_content})

            tool_uses = [b for b in assistant_content if b.type == "tool_use"]
            text_blocks = [b for b in assistant_content if b.type == "text"]

            for block in text_blocks:
                if on_text:
                    on_text(block.text)

            if not tool_uses:
                return "\n".join(b.text for b in text_blocks)

            tool_results = []
            for tool_use in tool_uses:
                result = await self._execute_tool(
                    tool_use.name, tool_use.input, on_tool_call, on_confirm, on_tool_result
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": result,
                })

            messages.append({"role": "user", "content": tool_results})

            if len(messages) > 120:
                return "Limite del agente alcanzado. Generando resumen de hallazgos hasta ahora."

    # ── OpenRouter (OpenAI-compatible) ────────────────────────
    async def _run_openrouter_loop(self, system_prompt, on_tool_call, on_text, on_confirm, on_tool_result):
        # Extract target from system prompt for the user message
        import re
        target_match = re.search(r'(?:TARGET|OBJETIVO):\s*(\S+)', system_prompt)
        target_str = target_match.group(1) if target_match else "el objetivo"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Inicia la evaluacion de seguridad en {target_str} AHORA. El objetivo es {target_str}. Comienza con tech_fingerprint en {target_str}, luego continua con TODAS las herramientas en orden. No me preguntes el objetivo - es {target_str}. Se exhaustivo y no te detengas hasta haber probado todo. Responde SIEMPRE en espanol."},
        ]

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/EleudoFuva/guardx-ai",
            "X-Title": "GuardX AI Security Agent",
        }

        retries = 0
        iteration = 0
        MAX_ITERATIONS = 80
        native_tools_supported = True  # Assume true, disable if model doesn't support

        while True:
            iteration += 1
            progress = f"[{iteration}/{MAX_ITERATIONS}]"
            payload = {
                "model": self.model,
                "max_tokens": 4096,
                "messages": messages,
            }

            # Only include tools if model supports them natively
            if native_tools_supported:
                payload["tools"] = OPENROUTER_TOOLS
                payload["tool_choice"] = "auto"

            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(API_TIMEOUT, connect=30.0)) as client:
                    resp = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                    )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"⏱ OpenRouter error ({type(e).__name__}), reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(2 * retries)  # Backoff
                    continue
                msg = f"OpenRouter fallo después de {MAX_RETRIES} reintentos: {type(e).__name__}: {e}"
                if on_text:
                    on_text(msg)
                return msg
            except Exception as e:
                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"⏱ Error HTTP ({type(e).__name__}), reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(2 * retries)
                    continue
                msg = f"Error HTTP después de {MAX_RETRIES} reintentos: {type(e).__name__}: {e}"
                if on_text:
                    on_text(msg)
                return msg

            # Retry on rate limit (429) - common with free models
            if resp.status_code == 429:
                if retries < MAX_RETRIES:
                    retries += 1
                    # Longer backoff for rate limits
                    wait_time = min(30, 5 * retries)
                    if on_text:
                        on_text(f"⏱ Rate limit (429), esperando {wait_time}s ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(wait_time)
                    continue

            # Retry on server errors (5xx)
            if resp.status_code >= 500:
                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"⏱ OpenRouter {resp.status_code}, reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(3 * retries)
                    continue
                error_text = resp.text[:500]
                msg = f"OpenRouter server error ({resp.status_code}): {error_text}"
                if on_text:
                    on_text(msg)
                return msg

            # Reset retries on success (after 5xx check)
            retries = 0

            if resp.status_code != 200:
                error_text = resp.text[:500]
                msg = f"OpenRouter error ({resp.status_code}): {error_text}"
                if on_text:
                    on_text(msg)
                return msg

            try:
                data = resp.json()
            except json.JSONDecodeError:
                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"⏱ Respuesta no-JSON de OpenRouter, reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(2 * retries)
                    continue
                msg = f"OpenRouter devolvió respuesta no-JSON: {resp.text[:300]}"
                if on_text:
                    on_text(msg)
                return msg

            # Handle OpenRouter error responses
            if "error" in data:
                error_msg = data["error"].get("message", str(data["error"])) if isinstance(data["error"], dict) else str(data["error"])

                # If model doesn't support tools, disable and retry with text-based tool calls
                if "tool" in error_msg.lower() and ("not support" in error_msg.lower() or "unsupported" in error_msg.lower() or "invalid" in error_msg.lower()):
                    native_tools_supported = False
                    if on_text:
                        on_text(f"⚙ Modelo no soporta tools nativas, cambiando a modo texto...")
                    # Add tool instructions to system prompt if not already there
                    tool_names = [t["function"]["name"] for t in OPENROUTER_TOOLS]
                    tool_instruction = f"\n\nIMPORTANT: To call a tool, write it as JSON: {{\"name\": \"tool_name\", \"arguments\": {{...}}}}\nAvailable tools: {', '.join(tool_names)}"
                    if messages[0]["role"] == "system" and "To call a tool" not in messages[0]["content"]:
                        messages[0]["content"] += tool_instruction
                    continue

                if "rate" in error_msg.lower() or "limit" in error_msg.lower() or "429" in error_msg:
                    if retries < MAX_RETRIES:
                        retries += 1
                        wait_time = min(30, 5 * retries)
                        if on_text:
                            on_text(f"⏱ Rate limit: {error_msg[:100]}. Esperando {wait_time}s ({retries}/{MAX_RETRIES})...")
                        await asyncio.sleep(wait_time)
                        continue

                # Provider errors (400) - transient issues from upstream providers
                if "provider returned error" in error_msg.lower() or "INVALID_ARGUMENT" in error_msg:
                    if retries < MAX_RETRIES:
                        retries += 1
                        if on_text:
                            on_text(f"⏱ Error del provider, reintentando ({retries}/{MAX_RETRIES})...")
                        await asyncio.sleep(3 * retries)
                        continue
                    # After max retries, don't kill the loop - return what we have so far
                    if on_text:
                        on_text("⚠ Provider con errores persistentes. Generando resultados parciales...")
                    return "Error del provider despues de reintentos. Generando resultados parciales con las herramientas ejecutadas."

                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"⏱ OpenRouter error: {error_msg[:150]}. Reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(3 * retries)
                    continue
                msg = f"OpenRouter error: {error_msg[:300]}"
                if on_text:
                    on_text(msg)
                return msg

            # Handle missing choices
            if "choices" not in data or not data["choices"]:
                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"⏱ Respuesta vacía de OpenRouter, reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(2 * retries)
                    continue
                msg = f"OpenRouter respuesta sin choices: {json.dumps(data)[:300]}"
                if on_text:
                    on_text(msg)
                return msg

            try:
                choice = data["choices"][0]
                message = choice["message"]
            except (KeyError, IndexError) as e:
                msg = f"Formato inesperado de OpenRouter: {e}. Data: {json.dumps(data)[:300]}"
                if on_text:
                    on_text(msg)
                return msg

            # Add assistant message to history
            messages.append(message)

            # Extract text content
            content = message.get("content")
            if content and on_text:
                on_text(content)

            # Check for tool calls
            tool_calls = message.get("tool_calls")

            # If no proper tool_calls, check if model wrote tool calls as text
            if not tool_calls and content:
                parsed = self._parse_text_tool_calls(content)
                if parsed:
                    tool_calls = parsed

            if not tool_calls:
                return content or ""

            # Detect if these are parsed-from-text tool calls (not native API tool calls)
            is_text_parsed = any("function" not in tc for tc in tool_calls)

            # Execute tools and build responses
            tool_results_text = []
            for tc in tool_calls:
                # Handle both OpenAI format and our parsed format
                if "function" in tc:
                    func = tc["function"]
                    tool_name = func["name"]
                    try:
                        tool_input = json.loads(func["arguments"]) if isinstance(func["arguments"], str) else func["arguments"]
                    except json.JSONDecodeError:
                        tool_input = {}
                    tc_id = tc.get("id", f"call_{iteration}_{tool_name}")
                else:
                    tool_name = tc["name"]
                    tool_input = tc.get("arguments", {})
                    tc_id = tc.get("id", f"call_{iteration}_{tool_name}")

                result = await self._execute_tool(
                    tool_name, tool_input, on_tool_call, on_confirm, on_tool_result
                )

                if is_text_parsed:
                    # For text-parsed tool calls, collect results to inject as user message
                    tool_results_text.append(f"[TOOL RESULT: {tool_name}]\n{result}\n[/TOOL RESULT]")
                else:
                    # Native API tool calls - use proper tool message format
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": result,
                    })

            # For text-parsed tool calls, inject results as user message
            if is_text_parsed and tool_results_text:
                results_msg = "\n\n".join(tool_results_text)
                messages.append({
                    "role": "user",
                    "content": f"Aqui estan los resultados de las herramientas. Analiza y continua con la SIGUIENTE herramienta en la secuencia. NO te detengas - sigue hasta que TODAS las herramientas hayan sido usadas. Responde en espanol.\n\n{results_msg}"
                })

            if len(messages) > 120:
                return "Limite del agente alcanzado. Generando resumen de hallazgos hasta ahora."

    # ── Ollama (local, zero cost) ─────────────────────────────
    async def _run_ollama_loop(self, system_prompt, on_tool_call, on_text, on_confirm, on_tool_result):
        """Agent loop for Ollama local models (OpenAI-compatible API)."""
        import re
        target_match = re.search(r'(?:TARGET|OBJETIVO):\s*(\S+)', system_prompt)
        target_str = target_match.group(1) if target_match else "el objetivo"

        # Build tool instructions for the system prompt (Ollama models may not support native tools)
        tool_names = [t["function"]["name"] for t in OPENROUTER_TOOLS]
        tool_descriptions = "\n".join(
            f'- {t["function"]["name"]}: {t["function"]["description"]}'
            for t in OPENROUTER_TOOLS
        )
        tool_instruction = (
            f"\n\n## HERRAMIENTAS DISPONIBLES:\n{tool_descriptions}\n\n"
            f"Para usar una herramienta, responde SOLO con este formato JSON (sin texto antes ni despues):\n"
            f'```tool_call\n{{"name": "nombre_herramienta", "arguments": {{"param": "valor"}}}}\n```\n'
            f"Despues de recibir el resultado, analiza y usa la siguiente herramienta."
        )

        messages = [
            {"role": "system", "content": system_prompt + tool_instruction},
            {"role": "user", "content": f"Inicia la evaluacion de seguridad en {target_str} AHORA. Comienza con tech_fingerprint. Responde en espanol."},
        ]

        iteration = 0
        MAX_ITERATIONS = 80
        retries = 0

        while iteration < MAX_ITERATIONS:
            iteration += 1

            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
            }

            # Try native tool support first
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(API_TIMEOUT, connect=30.0)) as client:
                    resp = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers={"Content-Type": "application/json"},
                        json=payload,
                    )
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if retries < MAX_RETRIES:
                    retries += 1
                    if on_text:
                        on_text(f"Ollama error ({type(e).__name__}), reintentando ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(2 * retries)
                    continue
                msg = f"Ollama no disponible despues de {MAX_RETRIES} reintentos: {e}"
                if on_text:
                    on_text(msg)
                return msg

            retries = 0

            if resp.status_code != 200:
                msg = f"Ollama error ({resp.status_code}): {resp.text[:300]}"
                if on_text:
                    on_text(msg)
                return msg

            try:
                data = resp.json()
                message = data["choices"][0]["message"]
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                msg = f"Respuesta inesperada de Ollama: {e}"
                if on_text:
                    on_text(msg)
                return msg

            messages.append(message)
            content = message.get("content", "")

            # Check for native tool calls first
            tool_calls = message.get("tool_calls")

            # If no native tool calls, parse from text
            if not tool_calls and content:
                tool_calls = self._parse_text_tool_calls(content)

            if not tool_calls:
                if content and on_text:
                    on_text(content)
                return content or ""

            # Show text before tool calls
            if content and on_text:
                # Filter out the JSON tool call from displayed text
                display_text = re.sub(r'```tool_call\s*\n?\{.*?\}\s*\n?```', '', content, flags=re.DOTALL).strip()
                if display_text:
                    on_text(display_text)

            # Execute tools
            tool_results_text = []
            for tc in tool_calls:
                if "function" in tc:
                    tool_name = tc["function"]["name"]
                    try:
                        tool_input = json.loads(tc["function"]["arguments"]) if isinstance(tc["function"]["arguments"], str) else tc["function"]["arguments"]
                    except json.JSONDecodeError:
                        tool_input = {}
                else:
                    tool_name = tc["name"]
                    tool_input = tc.get("arguments", {})

                result = await self._execute_tool(
                    tool_name, tool_input, on_tool_call, on_confirm, on_tool_result
                )
                tool_results_text.append(f"[RESULTADO: {tool_name}]\n{result}\n[/RESULTADO]")

            results_msg = "\n\n".join(tool_results_text)
            messages.append({
                "role": "user",
                "content": f"Resultados:\n\n{results_msg}\n\nAnaliza y continua con la SIGUIENTE herramienta. No te detengas."
            })

            if len(messages) > 120:
                return "Limite del agente alcanzado."

        return "Iteraciones maximas alcanzadas."

    # ── Parse tool calls written as text by free models ────────
    def _parse_text_tool_calls(self, text: str) -> list:
        """Parse tool calls that free models write as text instead of using proper API.

        Supports formats like:
        - TOOLCALL>[{"name": "tech_fingerprint", "arguments": {"url": "..."}}]CALL>
        - ```tool_call\n{"name": "...", "arguments": {...}}\n```
        - {"tool": "tech_fingerprint", "parameters": {"url": "..."}}
        - <tool_call>{"name": "...", "arguments": {...}}</tool_call>
        """
        import re
        calls = []

        # Pattern 1: TOOLCALL>[...]CALL>
        matches = re.findall(r'TOOLCALL>\s*\[?\s*(\{.*?\})\s*\]?\s*CALL>', text, re.DOTALL)
        for m in matches:
            try:
                obj = json.loads(m)
                name = obj.get("name", "")
                args = obj.get("arguments", obj.get("parameters", obj.get("input", {})))
                if isinstance(args, str):
                    args = json.loads(args)
                if name and name in TOOL_EXECUTORS:
                    calls.append({"name": name, "arguments": args, "id": f"text_{name}"})
            except (json.JSONDecodeError, TypeError):
                continue

        if calls:
            return calls

        # Pattern 2: ```tool_call ... ``` or ```json ... ```
        code_blocks = re.findall(r'```(?:tool_call|json)?\s*\n?\s*(\{.*?\})\s*\n?```', text, re.DOTALL)
        for block in code_blocks:
            try:
                obj = json.loads(block)
                name = obj.get("name", obj.get("tool", ""))
                args = obj.get("arguments", obj.get("parameters", obj.get("input", {})))
                if isinstance(args, str):
                    args = json.loads(args)
                if name and name in TOOL_EXECUTORS:
                    calls.append({"name": name, "arguments": args, "id": f"text_{name}"})
            except (json.JSONDecodeError, TypeError):
                continue

        if calls:
            return calls

        # Pattern 3: <tool_call>...</tool_call>
        xml_matches = re.findall(r'<tool_call>\s*(\{.*?\})\s*</tool_call>', text, re.DOTALL)
        for m in xml_matches:
            try:
                obj = json.loads(m)
                name = obj.get("name", obj.get("tool", ""))
                args = obj.get("arguments", obj.get("parameters", obj.get("input", {})))
                if isinstance(args, str):
                    args = json.loads(args)
                if name and name in TOOL_EXECUTORS:
                    calls.append({"name": name, "arguments": args, "id": f"text_{name}"})
            except (json.JSONDecodeError, TypeError):
                continue

        if calls:
            return calls

        # Pattern 4: Direct JSON with tool name anywhere in text
        json_matches = re.findall(r'\{[^{}]*"(?:name|tool)":\s*"(\w+)"[^{}]*"(?:arguments|parameters|input)":\s*(\{[^{}]*\})[^{}]*\}', text)
        for name, args_str in json_matches:
            try:
                args = json.loads(args_str)
                if name in TOOL_EXECUTORS:
                    calls.append({"name": name, "arguments": args, "id": f"text_{name}"})
            except (json.JSONDecodeError, TypeError):
                continue

        return calls

    # ── Shared tool execution with timeout ────────────────────
    async def _execute_tool(self, tool_name, tool_input, on_tool_call, on_confirm, on_tool_result=None):
        # Confirmation for destructive tools
        if tool_name == "ssh_exec" and on_confirm:
            desc = tool_input.get("description", tool_input.get("command", ""))
            approved = on_confirm(tool_name, desc, tool_input.get("command", ""))
            if not approved:
                return "User DENIED this action. Skip and continue."

        if on_tool_call:
            on_tool_call(tool_name, tool_input)

        executor = TOOL_EXECUTORS.get(tool_name)
        if executor:
            start_time = time.time()
            try:
                result = await asyncio.wait_for(
                    executor(tool_input),
                    timeout=TOOL_TIMEOUT,
                )
                duration = time.time() - start_time
                if on_tool_result:
                    on_tool_result(tool_name, duration, True)
                return result
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                if on_tool_result:
                    on_tool_result(tool_name, duration, False)
                return f"Tool timeout ({TOOL_TIMEOUT}s): {tool_name}"
            except Exception as e:
                duration = time.time() - start_time
                if on_tool_result:
                    on_tool_result(tool_name, duration, False)
                return f"Tool error: {e}"
        return f"Unknown tool: {tool_name}"
