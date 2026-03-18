"""
SSL/TLS Advanced Security Skill - Protocol weaknesses, cipher attacks, certificate validation bypasses
"""

SKILL = {
    "id": "ssl_deep",
    "name": "SSL/TLS Deep Analysis",
    "category": "infrastructure",
    "severity": "high",

    "detection": """
1. IDENTIFY SSL/TLS PROTOCOL VERSIONS:

   a) Use ssl_analyzer tool to detect enabled protocols:
      - SSLv3 (deprecated, vulnerable to POODLE)
      - TLSv1.0 (deprecated, vulnerable to BEAST, CRIME)
      - TLSv1.1 (deprecated, weak)
      - TLSv1.2 (modern, acceptable)
      - TLSv1.3 (latest, secure)

   b) Manual testing with openssl:
      ```bash
      openssl s_client -connect target.com:443 -ssl3
      openssl s_client -connect target.com:443 -tls1
      openssl s_client -connect target.com:443 -tls1_1
      openssl s_client -connect target.com:443 -tls1_2
      openssl s_client -connect target.com:443 -tls1_3
      ```

   c) If any of SSLv3, TLSv1.0, TLSv1.1 connect successfully → VULNERABILITY

2. DETECT WEAK CIPHER SUITES:

   a) Run ssl_analyzer to list all ciphers accepted:
      - Check for NULL ciphers (no encryption)
      - Check for EXPORT ciphers (40-bit encryption)
      - Check for RC4, DES, 3DES (broken algorithms)
      - Check for MD5, SHA1 (broken hashing)
      - Check for anon/aNULL (no authentication)

   b) Manual test with nmap:
      ```bash
      nmap --script ssl-enum-ciphers -p 443 target.com
      ```

   c) Weak ciphers to flag:
      - NONE: "NULL" cipher (no encryption)
      - EXPORT: Export-grade (40-56 bit) ciphers
      - DES: Single DES (56-bit) - trivially breakable
      - 3DES: Triple DES (outdated, slow)
      - RC4: Broken stream cipher (multiple attacks)
      - MD5: Broken hash (collision attacks)
      - PSK: Pre-shared key (requires shared secret)
      - anon/aNULL: Anonymous (no server authentication)

3. CERTIFICATE VALIDATION ISSUES:

   a) Certificate expiration:
      - Check certificate notAfter date
      - If expired → apps won't trust it, but attacker MITM possible
      - If expiring soon → needs immediate renewal

   b) Self-signed certificates:
      ```bash
      openssl x509 -in cert.pem -noout -issuer -subject
      # If issuer == subject → self-signed (untrusted unless explicitly added)
      ```

   c) Hostname mismatch:
      - Extract CN (Common Name) and SANs (Subject Alternative Names)
      - If accessing domain doesn't match cert → MITM possible
      - Example: cert for "www.example.com" but accessing "example.com"

   d) Missing certificate chain:
      - Server should send intermediate certs
      - If chain incomplete → client must have it or connection fails
      ```bash
      openssl s_client -connect target.com:443 -showcerts
      ```

4. CERTIFICATE CHAIN VALIDATION:

   a) Check certificate hierarchy:
      ```bash
      # Get full chain
      openssl s_client -connect target.com:443 -showcerts 2>/dev/null | \
      grep -A 30 "BEGIN CERTIFICATE" | head -100
      ```

   b) Verify each cert in chain:
      - Root CA should be trusted (in system trust store)
      - Intermediate certs should be valid and properly signed
      - End-entity cert should be properly signed by intermediate

   c) Look for:
      - Missing intermediate certs (client must fetch them)
      - Revoked certificates (check CRL/OCSP)
      - Certs with invalid paths (cross-signed in wrong order)

5. DETECT KNOWN VULNERABILITIES:

   a) BEAST (Browser Exploit Against SSL/TLS):
      - Vulnerability: TLSv1.0 with block cipher + compression
      - Affected: TLSv1.0 + CBC mode ciphers
      - If TLSv1.0 enabled → vulnerable
      - Fix: Disable TLSv1.0 or use stream ciphers

   b) CRIME (Compression Ratio Info-leak Made Easy):
      - Vulnerability: TLS compression exposes plaintext length
      - Affected: TLSv1.0+ with compression enabled
      - Attack: Attacker can infer sensitive data (CSRF tokens, session cookies)
      - Check: Look for compression_method in ServerHello
      - Fix: Disable TLS compression (most servers do this by default)

   c) POODLE (Padding Oracle On Downgraded Legacy Encryption):
      - Vulnerability: SSLv3 allows downgrade attack
      - Attack: Force connection down to SSLv3, exploit CBC oracle
      - If SSLv3 enabled → vulnerable
      - Fix: Disable SSLv3 completely

   d) Heartbleed (OpenSSL vulnerability):
      - Test: Send heartbeat request to vulnerable server
      - Vulnerable: OpenSSL 1.0.1 - 1.0.1f (and 1.0.2 beta)
      - Impact: Attacker can leak 64KB of memory per request
      - Check server version: `openssl s_client -connect target.com:443 | grep -i openssl`

   e) RC4 Fallback:
      - If modern ciphers fail, server falls back to RC4
      - RC4 has biases that can leak plaintext
      - Attack: Send TLS downgrade, force RC4

6. CERTIFICATE TRANSPARENCY (CT) CHECKS:

   a) Modern certificates should have CT logs:
      ```bash
      openssl x509 -in cert.pem -noout -text | grep -A 10 "CT Precertificate"
      ```

   b) If missing CT logs on public CA cert:
      - May indicate non-public or improper issuance
      - Risk: Unauthorized certificates not logged

7. STAPLED OCSP CHECKS:

   a) Check if OCSP stapling is enabled:
      ```bash
      echo | openssl s_client -connect target.com:443 -tlsextdebug 2>/dev/null | \
      grep "OCSP"
      ```

   b) If not stapled → client must fetch OCSP response (slower, leaks info)

8. USING ssl_analyzer TOOL:

   Simply run ssl_analyzer against target:
   ```python
   result = await ssl_analyzer.execute({
       'target': 'target.com',
       'port': 443
   })
   # Returns: Grade A+ to F, protocol versions, cipher details, all vulnerabilities
   ```
""",

    "exploitation": """
1. PROTOCOL DOWNGRADE ATTACK (BEAST):

   If TLSv1.0 + CBC cipher enabled:
   ```bash
   # Force server to use weak protocol
   openssl s_client -connect target.com:443 -tls1

   # Send HTTP request
   GET / HTTP/1.1
   Host: target.com
   ```

   Attack: Attacker intercepts traffic, uses BEAST oracle to decrypt cookies/tokens

2. PADDING ORACLE ATTACK:

   If SSLv3 + CBC cipher enabled:
   ```bash
   # Connect with SSLv3
   openssl s_client -connect target.com:443 -ssl3

   # Send malformed ciphertext
   # Server responds with "padding error" or "decryption error"
   # Attacker learns: does this ciphertext decrypt validly?
   # Repeat ~256 times to decrypt one byte of plaintext
   ```

3. CERTIFICATE HOSTNAME MISMATCH BYPASS:

   If cert is for "www.example.com" but server running on "example.com":
   ```bash
   # Attacker MITM with certificate for different domain
   # Many clients accept any cert from same IP
   openssl s_client -connect attacker-proxy:443 \
       -servername example.com  # Different from cert CN
   # If succeeds → hostname verification broken
   ```

4. SELF-SIGNED CERTIFICATE ACCEPTANCE:

   If client doesn't validate cert:
   ```bash
   # Attacker uses self-signed cert
   openssl genrsa -out attacker.key 2048
   openssl req -new -x509 -key attacker.key -out attacker.crt

   # Client connects without error → vulnerable
   # Attacker can MITM all traffic
   ```

5. CERTIFICATE EXPIRATION BYPASS:

   If client doesn't check expiration:
   ```bash
   # Attacker uses old expired certificate
   # Client still accepts it → vulnerable
   # Even if cert is old, attacker can MITM
   ```

6. MISSING INTERMEDIATE CERTIFICATE:

   If server doesn't send intermediate certs:
   ```bash
   # Client must fetch intermediate from CA
   # Attacker can intercept this fetch
   # Or client gives up, accepts unvalidated chain
   ```

7. HEARTBLEED EXPLOITATION:

   Against vulnerable OpenSSL version:
   ```bash
   # Send heartbeat request with large length but small payload
   echo -n "0018030401f40000" | xxd -r -p | \
   openssl s_client -connect target.com:443 \
   -servername target.com 2>/dev/null | xxd

   # Server leaks 64KB of memory (may contain secrets, keys, passwords)
   ```

8. WEAK CIPHER EXPLOITATION:

   RC4 stream cipher attack:
   ```bash
   # Connect using RC4 cipher
   openssl s_client -connect target.com:443 -cipher RC4-SHA

   # Send HTTPS request
   GET / HTTP/1.1
   Host: target.com
   Cookie: session=abc123...

   # Attacker analyzes RC4 biases to recover key bits
   # Over time, recovers plaintext (cookies, auth tokens)
   ```

   NULL cipher (no encryption):
   ```bash
   openssl s_client -connect target.com:443 -cipher NULL
   # All data sent in plaintext over "encrypted" TLS
   ```

9. CERTIFICATE CHAIN VALIDATION BYPASS:

   If client doesn't validate full chain:
   ```bash
   # Attacker creates self-signed "intermediate" cert
   # Claims to be signed by real CA (forged signature)
   # If client doesn't verify signatures → accepts fake chain
   ```

10. STEALING DATA VIA WEAK CIPHER:

    Against server using single-DES or similar:
    ```bash
    # DES is 56-bit (can brute force ~1 hour)
    openssl s_client -connect target.com:443 -cipher DES-CBC3-SHA

    # Send sensitive request
    POST /api/transfer HTTP/1.1
    Host: target.com
    Content-Length: 50

    {"to":"attacker","amount":999999,"account":"12345"}

    # Attacker brute forces DES key, decrypts request
    ```
""",

    "remediation": """
1. DISABLE LEGACY PROTOCOLS:

   a) Nginx/Apache configuration:
      ```nginx
      # /etc/nginx/nginx.conf
      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_prefer_server_ciphers on;

      # Disable SSL/TLS 1.0, 1.1
      # (already disabled in TLSv1.2+ only config)
      ```

   b) Node.js/Express:
      ```javascript
      const https = require('https');
      const tls = require('tls');

      const options = {
          key: fs.readFileSync('server.key'),
          cert: fs.readFileSync('server.crt'),
          minVersion: tls.TLS1_2,  // Minimum is TLS 1.2
          maxVersion: tls.TLS1_3,  // Support up to TLS 1.3
      };

      https.createServer(options, app).listen(443);
      ```

   c) Python/Flask:
      ```python
      from ssl import SSLContext, TLSVersion

      ctx = SSLContext()
      ctx.minimum_version = TLSVersion.TLSv1_2
      ctx.maximum_version = TLSVersion.TLSv1_3

      app.run(ssl_context=ctx, host='0.0.0.0', port=443)
      ```

2. USE STRONG CIPHER SUITES:

   a) Modern recommended ciphers (prioritized):
      - TLS_AES_256_GCM_SHA384 (TLS 1.3)
      - TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
      - TLS_AES_128_GCM_SHA256 (TLS 1.3)
      - ECDHE-ECDSA-AES256-GCM-SHA384 (TLS 1.2)
      - ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2)
      - ECDHE-ECDSA-CHACHA20-POLY1305 (TLS 1.2)
      - ECDHE-RSA-CHACHA20-POLY1305 (TLS 1.2)

   b) Nginx cipher string:
      ```nginx
      ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
      ssl_prefer_server_ciphers on;
      ssl_session_cache shared:SSL:10m;
      ssl_session_timeout 10m;
      ```

   c) Disable weak ciphers explicitly:
      ```bash
      # Remove NULL, EXPORT, RC4, DES, MD5, anon ciphers
      # Use: !aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA
      ```

3. PROPER CERTIFICATE MANAGEMENT:

   a) Valid certificate from trusted CA:
      ```bash
      # Use Let's Encrypt (free, automated)
      certbot certonly --webroot -w /var/www/html -d example.com

      # Or commercial CA: Comodo, DigiCert, GlobalSign
      ```

   b) Certificate includes all SANs (Subject Alternative Names):
      ```bash
      # Certificate should list all domains:
      # example.com, www.example.com, api.example.com, etc
      ```

   c) Automatic renewal (Let's Encrypt):
      ```bash
      # Set cron job
      0 2 * * * certbot renew --quiet
      ```

4. HSTS (HTTP Strict Transport Security):

   ```nginx
   # /etc/nginx/nginx.conf
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

   # max-age=31536000 = 1 year
   # includeSubDomains = apply to all subdomains
   # preload = submit to HSTS preload list
   ```

5. CERTIFICATE PINNING (Optional, advanced):

   ```javascript
   // Node.js with certificate pinning
   const https = require('https');
   const crypto = require('crypto');

   const pins = {
       'example.com': 'sha256/AAAAAAAAAAAAAAAAAAA='  // Public key hash
   };

   https.get('https://example.com', {
       checkServerIdentity: (servername, cert) => {
           const pubkey = crypto.createPublicKey({
               key: cert.pubkey,
               format: 'der',
               type: 'spki'
           });
           const hash = crypto.createHash('sha256')
               .update(pubkey.export({ format: 'der', type: 'spki' }))
               .digest('base64');

           if (pins[servername] !== 'sha256/' + hash) {
               throw new Error('Certificate pinning failed');
           }
       }
   });
   ```

6. OCSP STAPLING:

   Nginx:
   ```nginx
   ssl_stapling on;
   ssl_stapling_verify on;
   ssl_trusted_certificate /path/to/chain.crt;
   resolver 8.8.8.8 1.1.1.1 valid=300s;
   resolver_timeout 5s;
   ```

7. TEST CONFIGURATION:

   Use online tests:
   - SSL Labs: https://www.ssllabs.com/ssltest/
   - Test command:
      ```bash
      openssl s_client -connect target.com:443 -tls1_2
      # Should work

      openssl s_client -connect target.com:443 -tls1
      # Should fail

      openssl s_client -connect target.com:443 -ssl3
      # Should fail
      ```

8. VERIFICATION CHECKLIST:

   ✓ Only TLS 1.2 and TLS 1.3 enabled
   ✓ No NULL, EXPORT, DES, RC4 ciphers
   ✓ ECDHE used for forward secrecy
   ✓ GCM or ChaCha20-Poly1305 for AEAD
   ✓ Certificate valid and not expired
   ✓ Certificate includes all SANs
   ✓ HSTS header set to min 1 year
   ✓ OCSP stapling enabled
   ✓ No compression enabled
   ✓ SSL Labs rating A or A+
""",

    "tools": ["ssl_analyzer"],

    "payloads": [
        "tls1.0", "tls1.1", "tls1.2", "tls1.3", "ssl3",
        "RC4-SHA", "RC4-MD5",
        "DES-CBC3-SHA", "DES-CBC-SHA",
        "NULL-SHA", "NULL-MD5", "eNULL-DES-CBC3-SHA",
        "EXPORT-RC4-MD5", "EXPORT-DES-CBC-SHA",
        "aNULL-AES256-SHA", "aNULL-AES128-SHA",
        "PSK-AES256-CBC-SHA", "PSK-AES128-CBC-SHA",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],

    "references": [
        "NIST: TLS 1.2 and 1.3 Recommendations - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf",
        "OWASP: SSL/TLS Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "BEAST Attack: https://en.wikipedia.org/wiki/BEAST_(cryptography)",
        "CRIME Attack: https://en.wikipedia.org/wiki/CRIME",
        "POODLE Attack: https://poodle.io/",
        "Heartbleed: https://heartbleed.com/",
        "Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/",
        "CWE-295: Improper Certificate Validation",
        "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    ],
}
