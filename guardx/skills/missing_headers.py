"""Missing HTTP Security Headers."""

SKILL = {
    "id": "missing_headers",
    "name": "Missing HTTP Security Headers",
    "category": "config",
    "severity": "high",

    "detection": """
- Send HEAD/GET request to target and analyze response headers
- Check for each critical header:
  - Strict-Transport-Security (HSTS): forces HTTPS
  - Content-Security-Policy (CSP): prevents XSS, clickjacking, data injection
  - X-Frame-Options: prevents clickjacking (DENY or SAMEORIGIN)
  - X-Content-Type-Options: must be 'nosniff'
  - Referrer-Policy: controls referrer leakage
  - Permissions-Policy: restricts browser features (camera, mic, geolocation)
  - Cross-Origin-Opener-Policy: isolates browsing context
  - Cross-Origin-Resource-Policy: controls cross-origin reads
- Check if Server header reveals version (information disclosure)
- Check if X-Powered-By reveals technology stack
- Verify HSTS includes max-age >= 31536000 and includeSubDomains
- Verify CSP is not too permissive (no 'unsafe-inline', 'unsafe-eval', or *)
""",

    "exploitation": """
- No HSTS: perform SSL stripping attack (MITM downgrades HTTPS to HTTP)
- No CSP: inject scripts via XSS without browser blocking them
- No X-Frame-Options: embed target in iframe for clickjacking
  Create page: <iframe src="https://target.com/transfer" style="opacity:0">
  Overlay fake UI that tricks user into clicking the hidden iframe
- No X-Content-Type-Options: upload .html file disguised as image, browser executes it
- Server version exposed: search CVE database for known vulnerabilities of that version
- Document: screenshot showing missing headers and proof-of-concept clickjacking page
""",

    "remediation": """
- Add all headers in nginx server block:
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
  add_header Cross-Origin-Opener-Policy "same-origin" always;
  add_header Cross-Origin-Resource-Policy "same-origin" always;
  server_tokens off;
  proxy_hide_header X-Powered-By;

- For Apache (.htaccess or httpd.conf):
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set Content-Security-Policy "default-src 'self'"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always unset Server
  Header always unset X-Powered-By

- SSH fix: edit /etc/nginx/sites-available/default or apache config
- SSH fix: nginx -t && systemctl reload nginx
- Verify: re-check headers after applying changes
""",

    "tools": ["http_headers_check", "tech_fingerprint"],

    "payloads": [],

    "references": [
        "OWASP A05:2021 - Security Misconfiguration",
        "CWE-693: Protection Mechanism Failure",
        "CWE-1021: Improper Restriction of Rendered UI Layers",
    ],
}
