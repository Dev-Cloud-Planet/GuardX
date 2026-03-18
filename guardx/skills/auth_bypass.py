"""Authentication Bypass and Broken Authentication."""

SKILL = {
    "id": "auth_bypass",
    "name": "Authentication Bypass / Broken Auth",
    "category": "auth",
    "severity": "critical",

    "detection": """
- Check for default credentials on admin panels: admin/admin, admin/password, root/root
- Check for authentication bypass via URL manipulation:
  /admin -> 403, try /Admin, /ADMIN, /admin/, /admin/., /admin;
- Test HTTP verb tampering: GET blocked? Try HEAD, OPTIONS, TRACE
- Check for JWT vulnerabilities:
  Change algorithm to 'none': {"alg":"none"} with empty signature
  Change algorithm from RS256 to HS256 (key confusion)
  Check if token expires (exp claim), try expired tokens
  Brute force weak JWT secrets
- Check session management:
  Are sessions invalidated on logout?
  Are session IDs predictable?
  Is session fixation possible?
- Check for password reset flaws: token reuse, no expiration, predictable tokens
- Test rate limiting on login: can you brute force without lockout?
- Check for 2FA bypass: skip 2FA step, reuse codes, race condition
- Check for OAuth misconfigurations: open redirect in callback URL
""",

    "exploitation": """
- Login with default credentials
- Forge JWT with algorithm 'none' to become admin
- Use JWT key confusion (RS256->HS256) with public key as secret
- Brute force login with common password lists (if no rate limit)
- Hijack session: steal session cookie via XSS or network sniffing
- Password reset: intercept reset token, use for another user's account
- OAuth: redirect token to attacker-controlled URL
- Document: show successful authentication bypass, admin access gained
""",

    "remediation": """
- Change ALL default credentials immediately
- Implement account lockout after 5 failed attempts
- Enforce strong passwords: minimum 12 chars, complexity requirements
- Use bcrypt/argon2 for password hashing (never MD5/SHA1)
- JWT:
  Always validate algorithm server-side (reject 'none')
  Use RS256 with proper key management
  Set short expiration (15 min for access tokens)
  Implement token refresh mechanism
- Session management:
  Regenerate session ID after login
  Invalidate session on logout (server-side)
  Set session timeout (30 min idle)
  Use secure, HttpOnly, SameSite cookies
- Password reset:
  Single-use tokens that expire in 1 hour
  Don't reveal if email exists
- Implement rate limiting: max 10 login attempts per minute
- Enable MFA for admin accounts
- SSH fix: install fail2ban, configure lockout, update default creds
- Verify: test default creds, check rate limiting, verify JWT validation
""",

    "tools": ["http_headers_check", "nmap_scan", "dir_bruteforce", "tech_fingerprint", "web_spider"],

    "payloads": [
        "admin:admin", "admin:password", "admin:123456", "root:root",
        "admin:admin123", "test:test", "user:user", "guest:guest",
    ],

    "references": [
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-287: Improper Authentication",
        "CWE-384: Session Fixation",
        "CWE-798: Hard-coded Credentials",
    ],
}
