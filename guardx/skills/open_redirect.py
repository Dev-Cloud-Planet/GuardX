"""Open Redirect - URL redirection vulnerabilities."""

SKILL = {
    "id": "open_redirect",
    "name": "Open Redirect",
    "category": "web",
    "severity": "medium",

    "detection": """
- Look for URL parameters that control redirects: ?url=, ?redirect=, ?next=, ?return=, ?goto=, ?dest=, ?redir=, ?return_to=, ?continue=
- Check login pages: after login, does it redirect to a user-controlled URL?
- Check logout pages: redirect after logout
- Test with external domains: ?redirect=https://evil.com
- Check JavaScript redirects: window.location = user_input
- Look for meta refresh tags with user-controlled URLs
- Check all 3xx responses for user-controlled Location headers
""",

    "exploitation": """
- Basic: ?redirect=https://evil.com → redirects to attacker site
- Bypass double-slash: ?redirect=//evil.com (protocol-relative)
- Bypass domain check: ?redirect=https://trusted.com@evil.com
- Bypass with encoding: ?redirect=https%3A%2F%2Fevil.com
- Bypass subdomain check: ?redirect=https://evil.com.trusted.com
- Bypass path check: ?redirect=https://trusted.com.evil.com
- Backslash trick: ?redirect=https://trusted.com\\@evil.com
- Null byte: ?redirect=https://trusted.com%00.evil.com
- Use for: phishing (fake login page), token theft (OAuth redirect), SSRF chain
- Document: show the redirect happening to an external domain
""",

    "remediation": """
- NEVER redirect to user-controlled URLs without validation
- Use allowlist of permitted redirect destinations
- Use relative paths only for redirects (no absolute URLs)
- If absolute URLs needed: validate against allowlist of domains
- Strip protocol and check only domain portion
- Warn users when redirecting to external sites
- For OAuth: strictly validate redirect_uri against registered callbacks
- SSH fix: Add URL validation to redirect parameters
- SSH fix: Configure nginx to block open redirect patterns
- Verify: Test bypass payloads, confirm all blocked
""",

    "tools": ["web_spider", "http_request", "waf_detect"],

    "payloads": [
        "https://evil.com", "//evil.com", "/\\evil.com",
        "https://trusted.com@evil.com",
        "https://trusted.com%00.evil.com",
        "https://evil.com/trusted.com",
        "//evil.com/%2f..",
        "///evil.com", "////evil.com",
        "https:evil.com", "http:evil.com",
        "/%09/evil.com", "/%5cevil.com",
        "https://evil.com#trusted.com",
    ],

    "references": [
        "OWASP A01:2021 - Broken Access Control",
        "CWE-601: URL Redirection to Untrusted Site",
    ],
}
