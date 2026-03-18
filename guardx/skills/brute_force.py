"""Brute Force Protection - Login, SSH, API rate limiting."""

SKILL = {
    "id": "brute_force",
    "name": "Brute Force / Rate Limiting",
    "category": "auth",
    "severity": "high",

    "detection": """
- Test login endpoint: send 20+ requests with wrong passwords
- Check if account gets locked after N failed attempts
- Check if there is rate limiting (HTTP 429 response)
- Check if CAPTCHA appears after failed attempts
- Check if response time differs between valid/invalid usernames (user enumeration)
- Test SSH for brute force protection: multiple rapid connections
- Test API endpoints for rate limiting
- Check for fail2ban or similar on SSH (get banned after attempts)
- Check if login response reveals username validity:
  "Invalid password" vs "User not found" = user enumeration
- Test password reset for rate limiting
""",

    "exploitation": """
- Brute force login with common passwords: rockyou.txt top 1000
- Credential stuffing: use leaked credential databases
- SSH brute force with hydra: hydra -l root -P passwords.txt target ssh
- API abuse: unlimited requests to paid/resource-heavy endpoints
- User enumeration: build list of valid usernames
- Account lockout DoS: lock out legitimate users by flooding wrong passwords
- Document: show number of attempts possible without lockout as proof
""",

    "remediation": """
- Implement account lockout: lock after 5 failed attempts for 15 minutes
- Add rate limiting on login endpoint:
  nginx: limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
         location /login { limit_req zone=login burst=3 nodelay; }
- Implement progressive delays: 1s, 2s, 4s, 8s between attempts
- Add CAPTCHA after 3 failed attempts (reCAPTCHA, hCaptcha)
- Use generic error messages: "Invalid username or password" (never reveal which)
- Install fail2ban for SSH:
  sudo apt install fail2ban
  /etc/fail2ban/jail.local:
    [sshd]
    enabled = true
    maxretry = 3
    bantime = 3600
- Implement API rate limiting:
  Per IP: 100 requests/minute
  Per user: 1000 requests/hour
  Return 429 Too Many Requests with Retry-After header
- Use WAF rules for brute force detection
- Enable MFA as defense-in-depth
- SSH fix: install fail2ban, configure nginx rate limiting
- SSH fix: add rate limit middleware to application
- Verify: test rapid login attempts, confirm lockout/rate limit triggers
""",

    "tools": ["nmap_scan", "port_check", "ssh_exec"],

    "payloads": [],

    "references": [
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        "CWE-799: Improper Control of Interaction Frequency",
    ],
}
