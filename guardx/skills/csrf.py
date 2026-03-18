"""Cross-Site Request Forgery (CSRF)."""

SKILL = {
    "id": "csrf",
    "name": "Cross-Site Request Forgery (CSRF)",
    "category": "web",
    "severity": "high",

    "detection": """
- Check if forms include CSRF tokens (hidden input with random value)
- Check if state-changing requests (POST, PUT, DELETE) verify a token
- Look for SameSite cookie attribute: None = vulnerable
- Test: create HTML page with auto-submitting form pointing to target
- Check if API accepts requests without Origin/Referer validation
- Check if CORS is misconfigured: Access-Control-Allow-Origin: *
- Test if token is actually validated (send request without token)
- Check if token is tied to session (reuse token from another session)
- Test GET-based state changes: /transfer?to=attacker&amount=1000
""",

    "exploitation": """
- Create PoC HTML page:
  <form action="https://target.com/transfer" method="POST" id="f">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
  </form>
  <script>document.getElementById('f').submit()</script>
- Host PoC and trick victim into visiting it
- Actions that can be exploited: password change, email change, money transfer,
  admin actions, account deletion, settings modification
- Chain with XSS: inject auto-submitting form via stored XSS
- Document: show PoC HTML and evidence that action executed without user consent
""",

    "remediation": """
- Implement CSRF tokens on ALL state-changing forms:
  Python/Flask: flask-wtf CSRFProtect
  Django: {% csrf_token %} (built-in)
  Node/Express: csurf middleware
- Set SameSite attribute on cookies:
  Set-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly
- Validate Origin and Referer headers on server side
- Use custom request headers for APIs (X-Requested-With)
- Don't use GET for state-changing operations
- Configure CORS properly:
  Access-Control-Allow-Origin: https://yourdomain.com (not *)
  Access-Control-Allow-Credentials: true only with specific origin
- SSH fix: add CSRF middleware to application framework
- SSH fix: set SameSite on session cookies in nginx/app
- Verify: test PoC form again, confirm request is blocked
""",

    "tools": ["http_headers_check", "web_spider"],

    "payloads": [],

    "references": [
        "OWASP A01:2021 - Broken Access Control",
        "CWE-352: Cross-Site Request Forgery",
        "CAPEC-62: Cross Site Request Forgery",
    ],
}
