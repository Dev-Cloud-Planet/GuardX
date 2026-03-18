"""SSL/TLS Misconfiguration."""

SKILL = {
    "id": "ssl_tls",
    "name": "SSL/TLS Misconfiguration",
    "category": "crypto",
    "severity": "high",

    "detection": """
- Check TLS version: TLS 1.0 and 1.1 are deprecated and vulnerable
- Check cipher suites: RC4, DES, 3DES, NULL ciphers are weak
- Check certificate validity: expired, self-signed, wrong domain
- Check certificate chain: missing intermediate certs
- Verify HTTP to HTTPS redirect exists
- Check for mixed content (HTTPS page loading HTTP resources)
- Test for BEAST, POODLE, Heartbleed, CRIME, BREACH attacks
- Check OCSP stapling is enabled
- Verify certificate transparency logs
- Check if wildcard cert is used (*.domain.com) - broader attack surface
- Test renegotiation: client-initiated renegotiation should be disabled
""",

    "exploitation": """
- TLS 1.0/1.1: BEAST and POODLE attacks can decrypt traffic
- Weak ciphers: brute force encrypted traffic
- Expired/invalid cert: users trained to click through warnings = phishing opportunity
- No HTTPS redirect: MITM can intercept all traffic on HTTP
- Missing HSTS: SSL stripping attack with tools like sslstrip
- Self-signed cert: no trust chain, easy to impersonate
- Document: show TLS version, cipher list, cert details, and specific weakness
""",

    "remediation": """
- Configure nginx for modern TLS only:
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
  ssl_prefer_server_ciphers on;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:50m;
  ssl_stapling on;
  ssl_stapling_verify on;

- Force HTTPS redirect:
  server { listen 80; return 301 https://$host$request_uri; }

- Auto-renew certificates with certbot:
  certbot renew --dry-run
  crontab: 0 0 1 * * certbot renew --quiet

- Disable client-initiated renegotiation
- Enable OCSP stapling for faster cert verification
- SSH fix: edit nginx ssl config, test with nginx -t, reload
- Verify: test with ssl_check tool or ssllabs.com
""",

    "tools": ["http_headers_check", "port_check", "tech_fingerprint"],

    "payloads": [],

    "references": [
        "OWASP A02:2021 - Cryptographic Failures",
        "CWE-326: Inadequate Encryption Strength",
        "CWE-295: Improper Certificate Validation",
    ],
}
