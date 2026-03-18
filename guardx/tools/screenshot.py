"""Screenshot evidence capture tool using Playwright."""
import asyncio
import os
from datetime import datetime
from pathlib import Path

TOOL_SCHEMA = {
    "name": "screenshot",
    "description": (
        "Capture screenshots of web pages for visual evidence. "
        "Useful for documenting vulnerabilities, exposed interfaces, and page states. "
        "Supports full-page capture and custom viewport sizes."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL e.g. http://example.com",
            },
            "full_page": {
                "type": "boolean",
                "description": "Capture full page height (default: False for viewport-only)",
                "default": False,
            },
            "viewport_width": {
                "type": "integer",
                "description": "Viewport width in pixels (default: 1280)",
                "default": 1280,
            },
            "viewport_height": {
                "type": "integer",
                "description": "Viewport height in pixels (default: 720)",
                "default": 720,
            },
        },
        "required": ["url"],
    },
}


def is_available() -> bool:
    """Check if playwright is installed."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def execute(params: dict) -> str:
    """Capture screenshot of target URL."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return (
            "Playwright not installed. Install with:\n"
            "  pip install playwright && playwright install chromium"
        )

    url = params.get("url", "").strip()
    full_page = params.get("full_page", False)
    viewport_width = params.get("viewport_width", 1280)
    viewport_height = params.get("viewport_height", 720)

    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    # Create screenshots directory
    screenshots_dir = Path.home() / ".guardx" / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"screenshot_{timestamp}.png"
    filepath = screenshots_dir / filename

    try:
        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(headless=True)

            # Create context with specified viewport
            context = await browser.new_context(
                viewport={"width": viewport_width, "height": viewport_height}
            )

            page = await context.new_page()

            # Navigate with 30-second timeout
            try:
                await asyncio.wait_for(
                    page.goto(url, wait_until="domcontentloaded"),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                return f"Page load timeout (30s) for {url}"
            except Exception as e:
                return f"Navigation error for {url}: {e}"

            # Get page title and URL
            page_title = await page.title()
            final_url = page.url

            # Capture screenshot
            try:
                await page.screenshot(
                    path=str(filepath),
                    full_page=full_page,
                )
            except Exception as e:
                await browser.close()
                return f"Screenshot capture failed: {e}"

            await browser.close()

    except Exception as e:
        return f"Browser error: {e}"

    # Return result with file path and metadata
    file_size = filepath.stat().st_size
    return (
        f"Screenshot captured successfully\n"
        f"File: {filepath}\n"
        f"Size: {file_size} bytes\n"
        f"URL: {final_url}\n"
        f"Title: {page_title}\n"
        f"Viewport: {viewport_width}x{viewport_height}\n"
        f"Full Page: {full_page}"
    )
